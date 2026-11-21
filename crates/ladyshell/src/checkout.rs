//! Three-way checkout updates, with durable backups and a resumable journal.
use crate::{
    error::{ensure, Error, Result},
    files, snapshot,
    sources::{FileRecord, Snapshot},
    state,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{self, File},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    path: String,
    before: Option<FileRecord>,
    after: Option<FileRecord>,
    before_mode: Option<u32>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    sandbox_id: String,
    project: PathBuf,
    export: PathBuf,
    backup: PathBuf,
    remote: Snapshot,
    changes: Vec<Change>,
}
fn records(root: &Path, exclude: &[String]) -> Result<Snapshot> {
    Ok(snapshot::inventory_filtered(root, exclude)?
        .into_iter()
        .map(|(p, e)| {
            (
                p,
                FileRecord {
                    sha256: e.sha256,
                    executable: e.executable,
                },
            )
        })
        .collect())
}
fn current(root: &Path, path: &str) -> Result<Option<FileRecord>> {
    match snapshot::local_bytes(root, path) {
        Ok((e, _)) => Ok(Some(FileRecord {
            sha256: e.sha256,
            executable: e.executable,
        })),
        Err(e) if missing(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
fn missing(e: &Error) -> bool {
    match e {
        Error::Io(e) | Error::PathIo { source: e, .. } => e.kind() == std::io::ErrorKind::NotFound,
        Error::Context { source, .. } => missing(source),
        _ => false,
    }
}
fn report(changes: &[Change], conflicts: &[String], export: &Path, applied: bool) -> Value {
    let changes:Vec<_>=changes.iter().map(|c|json!({"path":c.path,"action":if c.before.is_none(){"add"}else if c.after.is_none(){"delete"}else{"modify"}})).collect();
    json!({"export":export,"changes":changes,"conflicts":conflicts,"applied":applied})
}
/// Caller holds the state lock for the complete operation.
pub fn run(state: &Value, directory: &Path, apply: bool) -> Result<Value> {
    crate::continuous::host::execution_directory(directory)?;
    crate::continuous::host::ensure_ready(state)?;
    let project = PathBuf::from(state::text(&state["desired_inputs"], "project")?);
    ensure!(project.is_absolute(), "Chemin projet absolu requis");
    files::open_directory(&project)?;
    ensure!(
        !files::absolute(directory)?.starts_with(&project),
        "L’état doit résider hors du projet"
    );
    let pending = directory.join("checkout-pending.json");
    if let Some(value) = state::read(&pending)? {
        let journal: Journal = serde_json::from_value(value)?;
        ensure!(
            journal.schema_version == 1
                && journal.project == project
                && journal.sandbox_id == state::text(state, "sandbox_id")?,
            "Journal checkout incompatible"
        );
        if apply {
            return finish(state, directory, journal);
        }
        let mut result = report(&journal.changes, &[], &journal.export, false);
        result["pending"] = json!(true);
        return Ok(result);
    }
    let export = PathBuf::from(state::text(state, "last_sync")?);
    ensure!(export.is_absolute(), "Chemin export absolu requis");
    let receipt = crate::json::parse(&files::read_limited(
        &export.join("manifest.json"),
        2 * 1024 * 1024,
    )?)?;
    crate::continuous::host::verify_export(state, &receipt)?;
    ensure!(
        receipt["schema_version"] == 2 && receipt["sandbox_id"] == state["sandbox_id"],
        "Export incompatible"
    );
    let exclude = crate::sync::exclusions(state)?;
    let spec = crate::config::Sources {
        include: vec![],
        exclude: exclude.clone(),
    };
    let mut base: Snapshot = serde_json::from_value(
        state
            .get("checkout_base")
            .unwrap_or(&state["host_sources"])
            .clone(),
    )?;
    base.retain(|p, _| !crate::sources::excluded(p, &spec));
    let remote: Snapshot = serde_json::from_value(receipt["files"].clone())?;
    ensure!(
        remote.keys().all(|p| !crate::sources::excluded(p, &spec)),
        "Export contenant un chemin exclu"
    );
    ensure!(
        records(&export.join("project"), &exclude)? == remote,
        "Export altéré"
    );
    let local = records(&project, &exclude)?;
    let keys: BTreeSet<_> = base
        .keys()
        .chain(local.keys())
        .chain(remote.keys())
        .collect();
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();
    for path in keys {
        snapshot::validate_path(path)?;
        let b = base.get(path);
        let l = local.get(path);
        let r = remote.get(path);
        if l == r || r == b {
            continue;
        }
        if l != b {
            conflicts.push(path.clone());
            continue;
        }
        changes.push(Change {
            path: path.clone(),
            before: l.cloned(),
            after: r.cloned(),
            before_mode: if l.is_some() {
                Some(mode(&project, path)?)
            } else {
                None
            },
        });
    }
    // File/directory transitions are explicit conflicts, never recursive deletions.
    for c in &changes {
        if c.after.is_some() {
            let mut parent = Path::new(&c.path).parent();
            while let Some(p) = parent {
                if p.to_str().is_some_and(|p| local.contains_key(p)) {
                    conflicts.push(c.path.clone());
                    break;
                }
                parent = p.parent();
            }
            if local.keys().any(|p| p.starts_with(&format!("{}/", c.path)))
                || project.join(&c.path).is_dir()
            {
                conflicts.push(c.path.clone());
            }
        }
    }
    conflicts.sort();
    conflicts.dedup();
    let result = report(&changes, &conflicts, &export, false);
    if !apply {
        return Ok(result);
    }
    ensure!(
        conflicts.is_empty(),
        "Conflits checkout : {} ; export conservé dans {}",
        conflicts.join(", "),
        export.display()
    );
    if changes.is_empty() {
        let mut next = state.clone();
        next["checkout_base"] = serde_json::to_value(&remote)?;
        next["last_checkout_export"] = json!(export);
        crate::environment_lock::atomic_json(&directory.join("state.json"), &next)?;
        return Ok(report(&changes, &[], &export, true));
    }
    let backup = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .prefix("checkout-backup-")
        .tempdir_in(directory)?
        .keep();
    fs::create_dir(backup.join("project"))?;
    for c in &changes {
        if let Some(before) = &c.before {
            let (entry, bytes) = snapshot::local_bytes(&project, &c.path)?;
            ensure!(
                entry.sha256 == before.sha256 && entry.executable == before.executable,
                "Checkout modifié pendant préparation : {}",
                c.path
            );
            crate::image::write_source(
                &backup.join("project"),
                &c.path,
                &bytes,
                before.executable,
            )?;
        }
    }
    sync_tree(&backup)?;
    let journal = Journal {
        schema_version: 1,
        sandbox_id: state::text(state, "sandbox_id")?.into(),
        project,
        export,
        backup,
        remote,
        changes,
    };
    crate::environment_lock::atomic_json(&pending, &serde_json::to_value(&journal)?)?;
    finish(state, directory, journal)
}
fn finish(state: &Value, directory: &Path, journal: Journal) -> Result<Value> {
    // Validate every precondition before the first write, including on restart.
    for c in &journal.changes {
        snapshot::validate_path(&c.path)?;
        let actual = current(&journal.project, &c.path)?;
        ensure!(
            actual == c.before || actual == c.after,
            "Checkout modifié depuis le journal : {} ; sauvegarde {}",
            c.path,
            journal.backup.display()
        );
        if actual != c.after {
            verify_mode(&journal.project, c)?;
        }
        if let Some(after) = &c.after {
            ensure!(
                current(&journal.export.join("project"), &c.path)?.as_ref() == Some(after),
                "Export altéré : {}",
                c.path
            );
        }
    }
    for c in &journal.changes {
        if current(&journal.project, &c.path)? == c.after {
            continue;
        }
        ensure!(
            current(&journal.project, &c.path)? == c.before,
            "Écriture concurrente détectée : {}",
            c.path
        );
        verify_mode(&journal.project, c)?;
        let parent = parent(&journal.project, &c.path, c.after.is_some())?;
        let leaf = Path::new(&c.path)
            .file_name()
            .ok_or_else(|| invalid("Nom absent".into()))?;
        let fdpath = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
        if let Some(after) = &c.after {
            let (entry, bytes) = snapshot::local_bytes(&journal.export.join("project"), &c.path)?;
            ensure!(
                entry.sha256 == after.sha256 && entry.executable == after.executable,
                "Export modifié pendant lecture"
            );
            let mut staged = tempfile::NamedTempFile::new_in(&fdpath)?;
            staged.write_all(&bytes)?;
            staged
                .as_file()
                .set_permissions(fs::Permissions::from_mode(target_mode(c, after)))?;
            staged.as_file().sync_all()?;
            ensure!(
                current(&journal.project, &c.path)? == c.before,
                "Écriture concurrente détectée : {}",
                c.path
            );
            verify_mode(&journal.project, c)?;
            if c.before.is_none() {
                staged
                    .persist_noclobber(fdpath.join(leaf))
                    .map_err(|e| Error::Io(e.error))?;
            } else {
                staged
                    .persist(fdpath.join(leaf))
                    .map_err(|e| Error::Io(e.error))?;
            }
        } else {
            ensure!(
                current(&journal.project, &c.path)? == c.before,
                "Écriture concurrente détectée : {}",
                c.path
            );
            verify_mode(&journal.project, c)?;
            fs::remove_file(fdpath.join(leaf))?;
        }
        parent.sync_all()?;
    }
    let mut next = state.clone();
    next["checkout_base"] = serde_json::to_value(&journal.remote)?;
    next["last_checkout_export"] = json!(journal.export);
    crate::environment_lock::atomic_json(&directory.join("state.json"), &next)?;
    let mut result = report(&journal.changes, &[], &journal.export, true);
    result["backup"] = json!(journal.backup);
    crate::environment_lock::atomic_json(
        &journal.backup.join("receipt.json"),
        &serde_json::to_value(&journal)?,
    )?;
    fs::remove_file(directory.join("checkout-pending.json"))?;
    files::open_directory(directory)?.sync_all()?;
    Ok(result)
}
fn parent(root: &Path, path: &str, create: bool) -> Result<File> {
    let mut dir = files::open_directory(root)?;
    let parent = Path::new(path)
        .parent()
        .ok_or_else(|| invalid("Parent absent".into()))?;
    for component in parent.components() {
        let name = component.as_os_str();
        if create {
            let name = CString::new(name.as_bytes())?;
            // SAFETY: descriptor and NUL-terminated name remain live for mkdirat.
            if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) } < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error.into());
                }
            }
            dir.sync_all()?;
        }
        dir = files::open_child(&dir, name, true)?;
    }
    Ok(dir)
}
fn sync_tree(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            files::open_regular(&entry.path())?.sync_all()?;
        }
    }
    files::open_directory(root)?.sync_all()?;
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

fn mode(root: &Path, path: &str) -> Result<u32> {
    let mut file = files::open_directory(root)?;
    for part in Path::new(path).components() {
        file = files::open_entry(&file, part.as_os_str())?;
    }
    Ok(file.metadata()?.permissions().mode() & 0o777)
}
fn target_mode(change: &Change, after: &FileRecord) -> u32 {
    match change.before_mode {
        Some(mode)
            if change
                .before
                .as_ref()
                .is_some_and(|b| b.executable == after.executable) =>
        {
            mode
        }
        Some(mode) => {
            (mode & 0o666)
                | if after.executable {
                    (mode & 0o444) >> 2
                } else {
                    0
                }
        }
        None => {
            if after.executable {
                0o700
            } else {
                0o600
            }
        }
    }
}

fn verify_mode(root: &Path, change: &Change) -> Result<()> {
    if let Some(expected) = change.before_mode {
        ensure!(
            mode(root, &change.path)? == expected,
            "Permissions modifiées depuis le journal : {}",
            change.path
        );
    }
    Ok(())
}
