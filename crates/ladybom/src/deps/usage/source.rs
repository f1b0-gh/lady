use super::{graph, invalid};
use crate::{
    config::Sources,
    error::{ensure, Error, Result},
    files,
    sources::{self, FileRecord, Snapshot},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::Path,
};

pub(super) struct SourcesRead {
    pub snapshot: Snapshot,
    pub data: BTreeMap<String, Vec<u8>>,
    root: File,
    total: usize,
    entries: usize,
    scanned: BTreeSet<(String, String)>,
    boundaries: BTreeSet<String>,
}
impl SourcesRead {
    pub fn collect(root: &Path, graph: &graph::Graph, selected: &[String]) -> Result<Self> {
        let mut result = Self {
            snapshot: Snapshot::new(),
            data: BTreeMap::new(),
            root: files::open_directory(root)?,
            total: 0,
            entries: 0,
            scanned: BTreeSet::new(),
            boundaries: graph
                .inventory
                .projects
                .iter()
                .map(|project| parent(&project.manifest).to_owned())
                .collect(),
        };
        // Inventory inputs are verified even when their projects are not selected.
        for path in graph.inventory.inputs.keys() {
            result.include(path, false)?;
        }
        let boundaries = result.boundaries.clone();
        for manifest in selected {
            crate::config::relative_path(manifest)?;
            ensure!(
                graph.inventory.inputs.contains_key(manifest),
                "Manifest absent des empreintes de l’inventaire : {manifest}"
            );
            if let Some(project) = graph
                .inventory
                .projects
                .iter()
                .find(|p| p.manifest == *manifest)
            {
                if project.ecosystem == "rust" {
                    let text = result
                        .text(manifest)
                        .ok_or_else(|| invalid(format!("Manifest non UTF-8 : {manifest}")))?;
                    if super::super::parse_toml(text)?.get("package").is_none() {
                        continue;
                    }
                }
                result.scan(parent(manifest), &project.ecosystem, &boundaries)?;
            }
        }
        Ok(result)
    }
    fn open(&self, name: &str) -> Result<Option<File>> {
        if !name.is_empty() {
            crate::config::relative_path(name)?;
        }
        let mut file = self.root.try_clone()?;
        for component in Path::new(name).components() {
            file = match files::open_entry(&file, component.as_os_str()) {
                Ok(file) => file,
                Err(error) if missing(&error) => return Ok(None),
                Err(error) => return Err(error),
            };
        }
        Ok(Some(file))
    }
    fn include(&mut self, name: &str, honor_exclusions: bool) -> Result<()> {
        if self.data.contains_key(name) || (honor_exclusions && excluded(name)) {
            return Ok(());
        }
        self.record_entry()?;
        if let Some(file) = self.open(name)? {
            self.read(file, name)?;
        }
        Ok(())
    }
    fn record_entry(&mut self) -> Result<()> {
        self.entries += 1;
        ensure!(self.entries <= 20_000, "Maximum 20000 entrées d’usage");
        Ok(())
    }
    fn read(&mut self, file: File, name: &str) -> Result<()> {
        if self.data.contains_key(name) {
            return Ok(());
        }
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file(),
            "Fichier source régulier requis : {name}"
        );
        ensure!(
            self.snapshot.len() < 20_000,
            "Maximum 20000 fichiers d’usage"
        );
        let bytes = files::read_file(file, (64 * 1024 * 1024 - self.total).min(8 * 1024 * 1024))?;
        self.total += bytes.len();
        ensure!(
            self.total <= 64 * 1024 * 1024,
            "Budget d’usage de 64 Mio dépassé"
        );
        self.snapshot.insert(
            name.into(),
            FileRecord {
                sha256: files::hash(&bytes),
                executable: metadata.permissions().mode() & 0o111 != 0,
            },
        );
        self.data.insert(name.into(), bytes);
        Ok(())
    }
    fn scan(&mut self, base: &str, ecosystem: &str, boundaries: &BTreeSet<String>) -> Result<()> {
        if self.scanned.contains(&(base.into(), ecosystem.into())) {
            return Ok(());
        }
        if let Some(directory) = self.open(base)? {
            ensure!(
                directory.metadata()?.is_dir(),
                "Répertoire source requis : {base}"
            );
            if excluded_directory(base) {
                return Ok(());
            }
            self.visit(directory, base, ecosystem, boundaries, 0)?;
            self.scanned.insert((base.into(), ecosystem.into()));
        }
        Ok(())
    }
    fn visit(
        &mut self,
        directory: File,
        base: &str,
        ecosystem: &str,
        boundaries: &BTreeSet<String>,
        depth: usize,
    ) -> Result<()> {
        ensure!(depth <= 64, "Sources d’usage trop imbriquées");
        for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
            let entry = entry?;
            self.record_entry()?;
            let child = entry.file_name();
            let child_name = child
                .to_str()
                .ok_or_else(|| invalid("Nom source non UTF-8".into()))?;
            let path = if base.is_empty() {
                child_name.into()
            } else {
                format!("{base}/{child_name}")
            };
            crate::config::relative_path(&path)?;
            if boundaries.contains(&path) {
                continue;
            }
            let kind = entry.file_type()?;
            if kind.is_dir() {
                if excluded_directory(&path) {
                    continue;
                }
                self.visit(
                    files::open_child(&directory, &child, true)?,
                    &path,
                    ecosystem,
                    boundaries,
                    depth + 1,
                )?;
            } else if excluded(&path) {
                continue;
            } else if relevant(&path, ecosystem) {
                self.read(files::open_child(&directory, &child, false)?, &path)?;
            } else if !kind.is_file() {
                // A link could conceal a source directory: refuse, never follow it.
                files::open_entry(&directory, &child)?;
            }
        }
        Ok(())
    }
    pub fn rust_target(&mut self, path: &str) -> Result<()> {
        self.include(path, true)?;
        if !excluded(path) {
            let base = parent(path);
            if !self
                .scanned
                .iter()
                .any(|(root, ecosystem)| ecosystem == "rust" && self.owns(root, base))
            {
                self.scan(base, "rust", &self.boundaries.clone())?;
            }
        }
        Ok(())
    }
    /// A collected file belongs to this scope only until the next project root.
    /// Explicit targets start their own local scope, even inside another project.
    pub fn owns(&self, base: &str, path: &str) -> bool {
        (path == base || within(path, base))
            && !self.boundaries.iter().any(|boundary| {
                boundary != base
                    && within(boundary, base)
                    && (path == boundary || within(path, boundary))
            })
    }
    pub fn text(&self, name: &str) -> Option<&str> {
        self.data
            .get(name)
            .and_then(|v| std::str::from_utf8(v).ok())
    }
}
fn missing(error: &Error) -> bool {
    match error {
        Error::PathIo { source, .. } | Error::Io(source) => {
            source.kind() == std::io::ErrorKind::NotFound
        }
        Error::Context { source, .. } => missing(source),
        _ => false,
    }
}
fn excluded(name: &str) -> bool {
    excluded_source(name, false)
}
fn excluded_directory(name: &str) -> bool {
    excluded_source(name, true)
}
fn excluded_source(name: &str, directory: bool) -> bool {
    let spec = Sources {
        include: vec![],
        exclude: vec![],
    };
    (if directory {
        sources::excluded_directory(name, &spec)
    } else {
        sources::excluded(name, &spec)
    }) || name
        .split('/')
        .any(|p| matches!(p, "vendor" | "archive" | "archives"))
}
pub(super) fn relevant(path: &str, ecosystem: &str) -> bool {
    let extensions: &[&str] = match ecosystem {
        "rust" => &[".rs"],
        "npm" => &[
            ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".json", ".jsonc",
            ".yaml", ".yml", ".vue", ".svelte", ".astro", ".node", ".gyp",
        ],
        "python" => &[
            ".py", ".pyi", ".pyx", ".ipynb", ".so", ".pyd", ".toml", ".ini", ".cfg",
        ],
        _ => &[],
    };
    extensions.iter().any(|extension| path.ends_with(extension))
        || (ecosystem == "rust" && path.contains(".cargo/config"))
}
/// Normalize explicit source paths lexically; never follow them on the host.
pub(super) fn resolve(base: &str, path: &str) -> Result<String> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.contains('\\')
            && !path.chars().any(char::is_control),
        "Chemin source relatif requis : {path}"
    );
    let mut parts: Vec<&str> = base
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    for part in path.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                ensure!(parts.pop().is_some(), "Chemin source hors racine : {path}");
            }
            _ => parts.push(part),
        }
    }
    let result = parts.join("/");
    crate::config::relative_path(&result)?;
    Ok(result)
}
pub(super) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}
pub(super) fn within(path: &str, root: &str) -> bool {
    root.is_empty() || path.strip_prefix(root).is_some_and(|p| p.starts_with('/'))
}
