//! Bounded, descriptor-relative source inventories. No worker or runtime execution.
use crate::{
    config::{relative_path, Sources},
    error::{ensure, Error, Result},
    files, sources,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::Path,
};
pub const FILE_LIMIT: usize = 16 * 1024 * 1024;
pub const TOTAL_LIMIT: usize = 256 * 1024 * 1024;
pub const JSON_LIMIT: usize = 24 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub sha256: String,
    pub executable: bool,
    pub size: usize,
}
pub type Inventory = BTreeMap<String, Entry>;
pub fn validate_path(path: &str) -> Result<()> {
    relative_path(path)?;
    ensure!(
        path.len() <= 4096 && path.split('/').count() <= 65,
        "Chemin export trop long"
    );
    ensure!(
        !sources::excluded(
            path,
            &Sources {
                include: vec![],
                exclude: vec![]
            }
        ),
        "Chemin export exclu : {path}"
    );
    Ok(())
}
pub fn validate(inventory: &Inventory) -> Result<()> {
    ensure!(inventory.len() <= 5000, "Trop de fichiers exportés");
    let mut total = 0usize;
    for (path, entry) in inventory {
        validate_path(path)?;
        ensure!(
            entry.sha256.len() == 64
                && entry
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Empreinte invalide"
        );
        ensure!(entry.size <= FILE_LIMIT, "Fichier export trop volumineux");
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| invalid("Volume invalide".into()))?;
        ensure!(total <= TOTAL_LIMIT, "Budget export dépassé");
        let mut parent = Path::new(path).parent();
        while let Some(p) = parent {
            if let Some(s) = p.to_str() {
                ensure!(!inventory.contains_key(s), "Collision fichier/dossier");
            }
            parent = p.parent();
        }
    }
    Ok(())
}
pub fn local_bytes(root: &Path, path: &str) -> Result<(Entry, Vec<u8>)> {
    validate_path(path)?;
    let mut file = files::open_directory(root)?;
    for component in Path::new(path).components() {
        file = files::open_entry(&file, component.as_os_str())?;
    }
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "Fichier régulier requis");
    let bytes = files::read_file(file.try_clone()?, FILE_LIMIT)?;
    let after = file.metadata()?;
    ensure!(
        meta.mode() == after.mode()
            && meta.ctime() == after.ctime()
            && meta.ctime_nsec() == after.ctime_nsec(),
        "Fichier modifié pendant lecture"
    );
    Ok((
        Entry {
            sha256: files::hash(&bytes),
            executable: meta.permissions().mode() & 0o111 != 0,
            size: bytes.len(),
        },
        bytes,
    ))
}
pub fn inventory(root: &Path) -> Result<Inventory> {
    inventory_filtered(root, &[])
}
pub fn inventory_filtered(root: &Path, exclude: &[String]) -> Result<Inventory> {
    for path in exclude {
        relative_path(path)?;
    }
    let dir = files::open_directory(root)?;
    let mut include = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("Nom non UTF-8".into()))?;
        let spec = Sources {
            include: vec![],
            exclude: exclude.to_vec(),
        };
        let is_directory = entry.file_type()?.is_dir();
        let excluded = if is_directory {
            sources::excluded_directory(&name, &spec)
        } else {
            sources::excluded(&name, &spec)
        };
        if !excluded {
            if is_directory {
                files::open_child(&dir, &entry.file_name(), true)?;
            }
            include.push(name);
        }
        ensure!(include.len() <= 20000, "Trop d’entrées");
    }
    let baseline = sources::snapshot(
        root,
        &Sources {
            include,
            exclude: exclude.to_vec(),
        },
        None,
    )?;
    let mut result = Inventory::new();
    for (path, record) in baseline {
        let (entry, _) = local_bytes(root, &path)?;
        ensure!(
            entry.sha256 == record.sha256 && entry.executable == record.executable,
            "Projet modifié pendant inventaire"
        );
        result.insert(path, entry);
    }
    validate(&result)?;
    Ok(result)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

/// Read-only metadata observations; these do not verify bytes or authorize export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Preview {
    pub schema_version: u32,
    pub entries: BTreeMap<String, PreviewEntry>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreviewEntry {
    pub disposition: Disposition,
    pub kind: EntryKind,
    pub size: Option<u64>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Included,
    ExcludedByPolicy,
    UnsupportedType,
    FileSizeLimit,
    TotalSizeLimit,
    FileCountLimit,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    Special,
}
impl Preview {
    pub fn validate(&self, exclude: &[String]) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.entries.len() <= 20000,
            "Invalid preview schema or entry limit"
        );
        let spec = Sources {
            include: vec![],
            exclude: exclude.to_vec(),
        };
        let mut included = 0usize;
        let mut total = 0u64;
        let mut smallest_included = None::<u64>;
        for (path, entry) in &self.entries {
            relative_path(path)?;
            ensure!(
                path.len() <= 4096 && path.split('/').count() <= 65,
                "Preview path limit exceeded"
            );
            let excluded = if entry.kind == EntryKind::Directory {
                sources::excluded_directory(path, &spec)
            } else {
                sources::excluded(path, &spec)
            };
            ensure!(
                (entry.disposition == Disposition::ExcludedByPolicy) == excluded,
                "Preview exclusion contradicts host policy"
            );
            ensure!(
                entry.size.is_some() == (entry.kind == EntryKind::File && !excluded),
                "Invalid preview size"
            );
            if !excluded {
                match entry.disposition {
                    Disposition::Included => {
                        ensure!(
                            entry.kind == EntryKind::File && entry.size <= Some(FILE_LIMIT as u64),
                            "Invalid included preview entry"
                        );
                        included += 1;
                        let size = entry.size.unwrap_or(0);
                        smallest_included =
                            Some(smallest_included.map_or(size, |smallest| smallest.min(size)));
                        total = total
                            .checked_add(entry.size.unwrap_or(0))
                            .ok_or_else(|| invalid("Preview byte overflow".into()))?;
                    }
                    Disposition::UnsupportedType => ensure!(
                        matches!(entry.kind, EntryKind::Symlink | EntryKind::Special),
                        "Invalid unsupported preview entry"
                    ),
                    Disposition::FileSizeLimit => ensure!(
                        entry.size > Some(FILE_LIMIT as u64),
                        "Invalid oversized preview entry"
                    ),
                    Disposition::TotalSizeLimit | Disposition::FileCountLimit => ensure!(
                        entry.kind == EntryKind::File && entry.size <= Some(FILE_LIMIT as u64),
                        "Invalid quota refusal preview entry"
                    ),
                    Disposition::ExcludedByPolicy => (),
                }
            }
            let mut parent = Path::new(path).parent();
            while let Some(p) = parent {
                ensure!(
                    !p.to_str().is_some_and(|p| self.entries.contains_key(p)),
                    "Preview contains descendants of a pruned entry"
                );
                parent = p.parent();
            }
        }
        ensure!(
            included <= 5000 && total <= TOTAL_LIMIT as u64,
            "Preview export budget exceeded"
        );
        // Refusals refer to the complete admitted set, not BTreeMap order.
        // Byte totals only grow during traversal. If admission eventually fills
        // the count quota, a byte refusal must be possible before its last file:
        // omit the smallest admitted file to maximize that earlier byte total.
        let before_count_capacity = if included == 5000 {
            total.saturating_sub(smallest_included.unwrap_or(0))
        } else {
            total
        };
        for entry in self.entries.values() {
            match entry.disposition {
                Disposition::FileCountLimit => ensure!(
                    included == 5000,
                    "File-count refusal lacks an admitted capacity-sized set"
                ),
                Disposition::TotalSizeLimit => ensure!(
                    before_count_capacity.saturating_add(entry.size.unwrap_or(0))
                        > TOTAL_LIMIT as u64,
                    "Byte-budget refusal lacks a preceding admitted byte overflow"
                ),
                _ => (),
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= JSON_LIMIT,
            "Preview JSON limit exceeded"
        );
        Ok(())
    }
}
pub fn preview_filtered(root: &Path, exclude: &[String]) -> Result<Preview> {
    for path in exclude {
        relative_path(path)?;
    }
    let spec = Sources {
        include: vec![],
        exclude: exclude.to_vec(),
    };
    let mut preview = Preview {
        schema_version: 1,
        entries: BTreeMap::new(),
    };
    let mut visited = 0usize;
    let mut total = 0u64;
    let mut included = 0usize;
    preview_walk(
        &files::open_directory_path(root)?,
        "",
        &spec,
        &mut preview,
        &mut visited,
        &mut total,
        &mut included,
    )?;
    preview.validate(exclude)?;
    Ok(preview)
}
fn preview_walk(
    dir: &fs::File,
    prefix: &str,
    spec: &Sources,
    preview: &mut Preview,
    visited: &mut usize,
    total: &mut u64,
    included: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
        let entry = entry?;
        *visited += 1;
        ensure!(*visited <= 20000, "Preview traversal entry limit exceeded");
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("Preview requires UTF-8 names".into()))?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        relative_path(&path)?;
        ensure!(
            path.len() <= 4096 && path.split('/').count() <= 65,
            "Preview path limit exceeded"
        );
        let kind = entry.file_type()?;
        let kind = if kind.is_dir() {
            EntryKind::Directory
        } else if kind.is_file() {
            EntryKind::File
        } else if kind.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::Special
        };
        // Pin directories without content access, and never follow links.
        let child = if kind == EntryKind::Directory {
            Some(files::open_directory_child_path(dir, &entry.file_name())?)
        } else {
            None
        };
        let excluded = if kind == EntryKind::Directory {
            sources::excluded_directory(&path, spec)
        } else {
            sources::excluded(&path, spec)
        };
        let (disposition, size) = if excluded {
            (Disposition::ExcludedByPolicy, None)
        } else if let Some(child) = child {
            preview_walk(&child, &path, spec, preview, visited, total, included)?;
            continue;
        } else if kind == EntryKind::File {
            let size = entry.metadata()?.len();
            let disposition = if size > FILE_LIMIT as u64 {
                Disposition::FileSizeLimit
            } else if *included >= 5000 {
                Disposition::FileCountLimit
            } else if total.saturating_add(size) > TOTAL_LIMIT as u64 {
                Disposition::TotalSizeLimit
            } else {
                *included += 1;
                *total += size;
                Disposition::Included
            };
            (disposition, Some(size))
        } else {
            (Disposition::UnsupportedType, None)
        };
        preview.entries.insert(
            path,
            PreviewEntry {
                disposition,
                kind,
                size,
            },
        );
    }
    Ok(())
}
