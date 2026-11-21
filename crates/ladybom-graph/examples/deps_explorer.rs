//! Reproducible static workspace inventory and a disposable Ladybug Explorer import.
//! This example never invokes a project's package manager or build scripts.
use ladybom::{deps, files, sources};
use ladybom_graph as graph;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn json_file(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
    serde_json::to_writer(&mut file, value)?;
    file.flush()?;
    Ok(())
}
fn include_if_present(root: &Path, selected: &mut BTreeSet<String>, path: String) -> Result<()> {
    if fs::symlink_metadata(root.join(&path)).is_ok() {
        selected.insert(path);
    }
    Ok(())
}
fn explicit_members(value: Option<&Value>) -> Result<Vec<String>> {
    value
        .into_iter()
        .flat_map(|v| v.as_array().into_iter().flatten())
        .map(|v| {
            let path = v.as_str().ok_or("workspace path must be text")?;
            if path.contains(['*', '?', '[']) {
                return Err("this experiment requires explicit workspace member paths".into());
            }
            Ok(path.to_owned())
        })
        .collect()
}
fn csv(path: &Path, header: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> Result<()> {
    let mut file = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
    writeln!(file, "{}", header.join(","))?;
    for row in rows {
        for (i, value) in row.iter().enumerate() {
            if i > 0 {
                write!(file, ",")?;
            }
            write!(file, "\"{}\"", value.replace('"', "\"\""))?;
        }
        writeln!(file)?;
    }
    file.flush()?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: deps_explorer ABSOLUTE_PROJECT NEW_OUTPUT_DIRECTORY".into());
    }
    let root = PathBuf::from(&args[0]);
    let out = PathBuf::from(&args[1]);
    files::open_directory(&root)?;
    let mut selected = BTreeSet::new();
    let mut members = BTreeSet::new();
    if root.join("Cargo.toml").exists() {
        let manifest = deps::parse_toml(&String::from_utf8(files::read_limited(
            &root.join("Cargo.toml"),
            8 * 1024 * 1024,
        )?)?)?;
        let manifest = serde_json::to_value(manifest)?;
        members.extend(explicit_members(manifest["workspace"].get("members"))?);
        selected.insert("Cargo.toml".into());
        include_if_present(&root, &mut selected, "Cargo.lock".into())?;
    }
    if root.join("package.json").exists() {
        let manifest: Value = serde_json::from_slice(&files::read_limited(
            &root.join("package.json"),
            8 * 1024 * 1024,
        )?)?;
        let workspaces = manifest.get("workspaces");
        members.extend(explicit_members(
            workspaces.and_then(|w| w.get("packages")).or(workspaces),
        )?);
        selected.insert("package.json".into());
        for name in ["package-lock.json", "npm-shrinkwrap.json"] {
            include_if_present(&root, &mut selected, name.into())?;
        }
    }
    for member in &members {
        for name in [
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "uv.lock",
            "package-lock.json",
            "npm-shrinkwrap.json",
        ] {
            include_if_present(&root, &mut selected, format!("{member}/{name}"))?;
        }
    }
    for name in [
        "rust-toolchain.toml",
        "rust-toolchain",
        ".nvmrc",
        ".node-version",
        ".python-version",
        "pyproject.toml",
        "uv.lock",
    ] {
        include_if_present(&root, &mut selected, name.into())?;
    }
    let inputs = sources::snapshot(
        &root,
        &sources::Sources {
            include: selected.into_iter().collect(),
            exclude: Vec::new(),
        },
        None,
    )?;
    let report = deps::scan_snapshot(&root, &inputs)?;
    fs::create_dir(&out)?;
    json_file(
        &out.join("scope.json"),
        &json!({"source":root,"selection":"root and explicit maintained workspace members; manifests and lockfiles only","inputs":inputs}),
    )?;
    json_file(&out.join("scan.json"), &report)?;
    let locked_components = report.projects.iter().try_fold(0, |count, project| {
        report
            .components_for(project)
            .map(|components| count + components.len())
    })?;
    println!(
        "{}",
        json!({"projects":report.projects.len(),"locked_components_in_inventory":locked_components,"scan_bytes":fs::metadata(out.join("scan.json"))?.len(),"scan_complete":report.complete})
    );
    let graph = graph::project(report)?;
    graph::write_snapshot(&graph, &out.join("snapshot"))?;
    let import = out.join("explorer");
    fs::create_dir(&import)?;
    let nodes = graph
        .components
        .iter()
        .map(|n| {
            Ok(vec![
                n.key.engine_key()?,
                n.component.name.clone(),
                n.component.version.clone(),
                n.key.purl.clone(),
                n.key.graph.clone(),
                format!("{}@{}", n.component.name, n.component.version),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    csv(
        &import.join("components.csv"),
        &["id", "name", "version", "purl", "context", "label"],
        nodes,
    )?;
    let edges = graph
        .dependencies
        .iter()
        .map(|e| {
            Ok(vec![
                e.from.engine_key()?,
                e.to.engine_key()?,
                e.kind.clone(),
                e.condition.to_string(),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    csv(
        &import.join("dependencies.csv"),
        &["from_id", "to_id", "kind", "condition"],
        edges,
    )?;
    let projects = graph.inventory.projects.iter().map(|p| {
        vec![
            files::hash(p.manifest.as_bytes()),
            p.manifest.clone(),
            p.ecosystem.clone(),
            p.locked.to_string(),
            p.root.clone(),
        ]
    });
    csv(
        &import.join("projects.csv"),
        &["id", "manifest", "ecosystem", "locked", "label"],
        projects,
    )?;
    let roots = graph
        .roots
        .iter()
        .map(|r| {
            Ok(vec![
                files::hash(r.manifest.as_bytes()),
                r.to.engine_key()?,
                r.kind.clone(),
                r.condition.to_string(),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    csv(
        &import.join("roots.csv"),
        &["from_id", "to_id", "kind", "condition"],
        roots,
    )?;
    let script = "CALL threads=2;\nCREATE NODE TABLE Package(id STRING, name STRING, version STRING, purl STRING, context STRING, label STRING, PRIMARY KEY(id));\nCREATE NODE TABLE Project(id STRING, manifest STRING, ecosystem STRING, locked STRING, label STRING, PRIMARY KEY(id));\nCREATE REL TABLE Depends(FROM Package TO Package, kind STRING, condition STRING);\nCREATE REL TABLE Requires(FROM Project TO Package, kind STRING, condition STRING);\nCOPY Package FROM 'components.csv' (HEADER=true);\nCOPY Project FROM 'projects.csv' (HEADER=true);\nCOPY Depends FROM 'dependencies.csv' (HEADER=true);\nCOPY Requires FROM 'roots.csv' (HEADER=true);\nMATCH (n:Package) RETURN count(n) AS packages;\nMATCH (n:Project) RETURN count(n) AS projects;\nMATCH ()-[e:Depends]->() RETURN count(e) AS dependencies;\nMATCH ()-[e:Requires]->() RETURN count(e) AS roots;\nCHECKPOINT;\n";
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(import.join("load.cypher"))?;
    file.write_all(script.as_bytes())?;
    json_file(
        &out.join("summary.json"),
        &json!({"source":root,"complete":graph.complete(),"projects":graph.inventory.projects.len(),"contexts":graph.contexts.len(),"components":graph.components.len(),"dependencies":graph.dependencies.len(),"roots":graph.roots.len(),"limitation_count":graph.limitations.len(),"limitations":graph.limitations}),
    )?;
    println!(
        "{}",
        json!({"contexts":graph.contexts.len(),"components":graph.components.len(),"dependencies":graph.dependencies.len(),"roots":graph.roots.len(),"complete":graph.complete()})
    );
    Ok(())
}
