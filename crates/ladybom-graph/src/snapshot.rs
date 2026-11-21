use super::*;
use bytes::Bytes;
use parquet::{
    data_type::{ByteArray, ByteArrayType},
    file::{
        reader::{FileReader, SerializedFileReader},
        writer::SerializedFileWriter,
    },
    record::RowAccessor,
    schema::parser::parse_message_type,
};
use std::{
    ffi::CString,
    fs::{self, File},
    os::fd::AsRawFd,
    path::Path,
    sync::Arc,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    logical_sha256: String,
    components: usize,
    dependencies: usize,
    files: BTreeMap<String, FileRecord>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    sha256: String,
    bytes: usize,
}
const NODE_COLUMNS: &[&str] = &["purl", "component"];
const EDGE_COLUMNS: &[&str] = &[
    "from_purl",
    "to_purl",
    "to_graph",
    "kind",
    "condition",
    "evidence",
];
fn parquet_error(e: impl std::fmt::Display) -> ladybom::error::Error {
    invalid(format!("Invalid Parquet: {e}"))
}

pub(super) fn write_table(path: &Path, columns: &[&str], rows: &[Vec<String>]) -> Result<()> {
    let fields = columns
        .iter()
        .map(|name| format!("REQUIRED BINARY {name} (UTF8);"))
        .collect::<Vec<_>>()
        .join(" ");
    let schema = Arc::new(
        parse_message_type(&format!("message data {{ {fields} }}")).map_err(parquet_error)?,
    );
    let mut writer = SerializedFileWriter::new(File::create(path)?, schema, Default::default())
        .map_err(parquet_error)?;
    // Bounded row groups avoid one allocation spanning the whole snapshot.
    for chunk in rows.chunks(4096) {
        let mut group = writer.next_row_group().map_err(parquet_error)?;
        for i in 0..columns.len() {
            let mut column = group
                .next_column()
                .map_err(parquet_error)?
                .ok_or_else(|| invalid("Missing Parquet column".into()))?;
            let values: Vec<ByteArray> = chunk
                .iter()
                .map(|row| ByteArray::from(row[i].as_str()))
                .collect();
            column
                .typed::<ByteArrayType>()
                .write_batch(&values, None, None)
                .map_err(parquet_error)?;
            column.close().map_err(parquet_error)?;
        }
        group.close().map_err(parquet_error)?;
    }
    writer.close().map_err(parquet_error)?;
    Ok(())
}
fn read_table(bytes: Vec<u8>, columns: &[&str], limit: usize) -> Result<Vec<Vec<String>>> {
    let reader = SerializedFileReader::new(Bytes::from(bytes)).map_err(parquet_error)?;
    let meta = reader.metadata();
    ensure!(
        meta.file_metadata().num_rows() >= 0
            && meta.file_metadata().num_rows() as u64 <= limit as u64,
        "Too many Parquet rows"
    );
    let schema = meta.file_metadata().schema_descr();
    ensure!(
        schema.num_columns() == columns.len(),
        "Parquet schema mismatch"
    );
    for (i, name) in columns.iter().enumerate() {
        let col = schema.column(i);
        ensure!(
            col.name() == *name
                && col.physical_type() == parquet::basic::Type::BYTE_ARRAY
                && col.max_def_level() == 0
                && col.max_rep_level() == 0,
            "Colonne Parquet divergente"
        );
    }
    let mut decoded_bytes = 0u64;
    for group in meta.row_groups() {
        ensure!(group.total_byte_size() >= 0, "Negative Parquet size");
        decoded_bytes = decoded_bytes
            .checked_add(group.total_byte_size() as u64)
            .ok_or_else(|| invalid("Taille Parquet excessive".into()))?;
        for col in group.columns() {
            ensure!(
                col.compression() == parquet::basic::Compression::UNCOMPRESSED,
                "Parquet compression is not supported by this schema"
            );
        }
    }
    ensure!(
        decoded_bytes <= MAX_BYTES as u64,
        "Decoded Parquet exceeds 128 MiB"
    );
    let mut rows = Vec::new();
    let mut size = 0usize;
    for row in reader.get_row_iter(None).map_err(parquet_error)? {
        let row = row.map_err(parquet_error)?;
        let mut values = Vec::new();
        for i in 0..columns.len() {
            let value = row.get_string(i).map_err(parquet_error)?.clone();
            size = size.saturating_add(value.len());
            ensure!(size <= MAX_BYTES, "Parquet data too large");
            values.push(value);
        }
        rows.push(values);
        ensure!(rows.len() <= limit, "Parquet row limit exceeded");
    }
    Ok(rows)
}

pub fn write_snapshot(graph: &Graph, destination: &Path) -> Result<()> {
    let mut graph = graph.clone();
    graph.canonicalize()?;
    graph.validate()?;
    let absolute = files::absolute(destination)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("Missing parent".into()))?;
    let directory = files::open_directory(parent)?;
    let name = absolute
        .file_name()
        .ok_or_else(|| invalid("Missing name".into()))?;
    let staging = tempfile::Builder::new()
        .prefix(".ladybom-graph-")
        .tempdir_in(format!("/proc/self/fd/{}", directory.as_raw_fd()))?;
    let mut records = BTreeMap::new();
    let mut header = graph.clone();
    header.components.clear();
    header.dependencies.clear();
    fs::write(
        staging.path().join("inventory.json"),
        serde_json::to_vec(&header)?,
    )?;
    let mut paths = vec!["inventory.json".to_owned()];
    for (path, context) in &graph.contexts {
        fs::create_dir_all(staging.path().join(path))?;
        let context_file = format!("{path}/context.json");
        fs::write(
            staging.path().join(&context_file),
            serde_json::to_vec(context)?,
        )?;
        paths.push(context_file);
        let nodes: Vec<Vec<String>> = graph
            .components
            .iter()
            .filter(|n| n.key.graph == *path)
            .map(|n| {
                Ok(vec![
                    n.key.purl.clone(),
                    serde_json::to_string(&n.component)?,
                ])
            })
            .collect::<Result<_>>()?;
        let edges: Vec<Vec<String>> = graph
            .dependencies
            .iter()
            .filter(|e| e.from.graph == *path)
            .map(|e| {
                Ok(vec![
                    e.from.purl.clone(),
                    e.to.purl.clone(),
                    e.to.graph.clone(),
                    e.kind.clone(),
                    serde_json::to_string(&e.condition)?,
                    serde_json::to_string(&e.evidence)?,
                ])
            })
            .collect::<Result<_>>()?;
        for (name, cols, rows) in [
            ("components.parquet", NODE_COLUMNS, nodes),
            ("dependencies.parquet", EDGE_COLUMNS, edges),
        ] {
            let file = format!("{path}/{name}");
            write_table(&staging.path().join(&file), cols, &rows)?;
            paths.push(file);
        }
    }
    let mut total = 0usize;
    for path in paths {
        let bytes = fs::read(staging.path().join(&path))?;
        total = total.saturating_add(bytes.len());
        ensure!(total <= MAX_BYTES, "Snapshot exceeds 128 MiB");
        File::open(staging.path().join(&path))?.sync_all()?;
        records.insert(
            path,
            FileRecord {
                sha256: files::hash(&bytes),
                bytes: bytes.len(),
            },
        );
    }
    let manifest = Manifest {
        schema_version: 1,
        logical_sha256: files::hash(&serde_json::to_vec(&graph)?),
        components: graph.components.len(),
        dependencies: graph.dependencies.len(),
        files: records,
    };
    fs::write(
        staging.path().join("manifest.json"),
        serde_json::to_vec(&manifest)?,
    )?;
    File::open(staging.path().join("manifest.json"))?.sync_all()?;
    // Publish atomically through held parent descriptors. Never replace even an empty directory.
    let source = CString::new(
        staging
            .path()
            .file_name()
            .ok_or_else(|| invalid("Missing temporary name".into()))?
            .as_encoded_bytes(),
    )?;
    let target = CString::new(name.as_encoded_bytes())?;
    // SAFETY: valid C strings and directory fd remain alive during renameat2.
    let rc = unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}
fn read_at(root: &File, path: &str, limit: usize) -> Result<Vec<u8>> {
    ladybom::sources::relative_path(path)?;
    let mut directory = root.try_clone()?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        let file = files::open_child(&directory, part.as_ref(), parts.peek().is_some())?;
        if parts.peek().is_none() {
            return files::read_file(file, limit);
        }
        directory = file;
    }
    Err(invalid("Empty path".into()))
}
pub fn read_snapshot(path: &Path) -> Result<Graph> {
    let directory = files::open_directory(path)?;
    let manifest: Manifest =
        serde_json::from_slice(&read_at(&directory, "manifest.json", 4 * 1024 * 1024)?)?;
    ensure!(
        manifest.schema_version == 1
            && manifest.components <= MAX_COMPONENTS
            && manifest.dependencies <= MAX_EDGES
            && manifest.files.len() <= MAX_CONTEXTS * 3 + 1,
        "Snapshot manifest out of bounds"
    );
    let mut all = BTreeMap::new();
    let mut total = 0usize;
    for (path, record) in &manifest.files {
        total = total.saturating_add(record.bytes);
        ensure!(total <= MAX_BYTES, "Snapshot exceeds 128 MiB");
        let bytes = read_at(&directory, path, record.bytes)?;
        ensure!(
            bytes.len() == record.bytes && files::hash(&bytes) == record.sha256,
            "Digest mismatch : {path}"
        );
        all.insert(path.clone(), bytes);
    }
    let mut graph: Graph = serde_json::from_slice(
        &all.remove("inventory.json")
            .ok_or_else(|| invalid("Missing inventory".into()))?,
    )?;
    ensure!(
        graph.components.is_empty()
            && graph.dependencies.is_empty()
            && graph.contexts.len() <= MAX_CONTEXTS,
        "Invalid snapshot header"
    );
    for (path, context) in &graph.contexts {
        ensure!(*path == context.path()?, "Invalid context");
        let bytes = all
            .remove(&format!("{path}/context.json"))
            .ok_or_else(|| invalid("Missing context".into()))?;
        let actual: Context = serde_json::from_slice(&bytes)?;
        ensure!(
            serde_json::to_value(&actual)? == serde_json::to_value(context)?,
            "Context metadata mismatch"
        );
        let nodes = all
            .remove(&format!("{path}/components.parquet"))
            .ok_or_else(|| invalid("Missing components".into()))?;
        for row in read_table(
            nodes,
            NODE_COLUMNS,
            MAX_COMPONENTS.saturating_sub(graph.components.len()),
        )? {
            graph.components.push(Node {
                key: NodeRef {
                    graph: path.clone(),
                    purl: row[0].clone(),
                },
                component: serde_json::from_str(&row[1])?,
            });
        }
        let edges = all
            .remove(&format!("{path}/dependencies.parquet"))
            .ok_or_else(|| invalid("Missing relationships".into()))?;
        for row in read_table(
            edges,
            EDGE_COLUMNS,
            MAX_EDGES.saturating_sub(graph.dependencies.len()),
        )? {
            graph.dependencies.push(Edge {
                from: NodeRef {
                    graph: path.clone(),
                    purl: row[0].clone(),
                },
                to: NodeRef {
                    graph: row[2].clone(),
                    purl: row[1].clone(),
                },
                kind: row[3].clone(),
                condition: serde_json::from_str(&row[4])?,
                evidence: serde_json::from_str(&row[5])?,
            });
        }
    }
    // Original dependency ordering is canonicalized at projection/publication boundary.
    graph.canonicalize()?;
    ensure!(
        all.is_empty()
            && graph.components.len() == manifest.components
            && graph.dependencies.len() == manifest.dependencies,
        "Cardinality or file mismatch"
    );
    graph.validate()?;
    ensure!(
        files::hash(&serde_json::to_vec(&graph)?) == manifest.logical_sha256,
        "Logical identity mismatch"
    );
    Ok(graph)
}
