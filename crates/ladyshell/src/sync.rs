//! Incremental verified full exports, published separately from the host checkout.
use crate::{
    error::{ensure, Error, Result},
    files,
    openshell::Backend,
    snapshot::{self, FilePayload, Inventory},
    sources::{FileRecord, Snapshot},
    state::text,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub trait Transport {
    fn inventory(&mut self) -> Result<Vec<u8>>;
    fn file(&mut self, path: &str) -> Result<Vec<u8>>;
}
struct Remote<'a> {
    backend: &'a Backend,
    state: &'a Value,
    started: Instant,
}
impl Remote<'_> {
    fn call(&self, operation: &str, path: Option<&str>) -> Result<Vec<u8>> {
        let remaining = Duration::from_secs(300)
            .checked_sub(self.started.elapsed())
            .ok_or_else(|| invalid("Overall sync time limit exceeded".into()))?;
        let mut command = self.backend.command();
        command.args([
            "sandbox",
            "exec",
            "--no-login-shell",
            "--no-tty",
            text(self.state, "sandbox_name")?,
            "--",
            self.state["snapshot_binary"]
                .as_str()
                .unwrap_or("/usr/local/bin/ladyshell"),
            operation,
        ]);
        for excluded in exclusions(self.state)? {
            command.arg("--exclude").arg(excluded);
        }
        if let Some(path) = path {
            command.arg("--").arg(path);
        }
        crate::process::capture(command, remaining.min(Duration::from_secs(60)), snapshot::JSON_LIMIT).map_err(|e|e.context("Rust snapshot worker unavailable or rejected; explicitly migrate the sandbox runtime"))
    }
}
impl Transport for Remote<'_> {
    fn inventory(&mut self) -> Result<Vec<u8>> {
        self.call("snapshot-list", None)
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.call("snapshot-file", Some(path))
    }
}
pub fn parse_inventory(bytes: &[u8]) -> Result<Inventory> {
    ensure!(bytes.len() <= 2 * 1024 * 1024, "Inventory is too large");
    let value: Inventory = serde_json::from_value(crate::json::parse(bytes)?)?;
    snapshot::validate(&value)?;
    Ok(value)
}
fn records(inventory: &Inventory) -> Snapshot {
    inventory
        .iter()
        .map(|(path, e)| {
            (
                path.clone(),
                FileRecord {
                    sha256: e.sha256.clone(),
                    executable: e.executable,
                },
            )
        })
        .collect()
}
/// Read-only worker inventory for source-bound checks; caller holds the session lease.
pub(crate) fn observe_inventory(state: &Value, backend: &Backend) -> Result<Inventory> {
    backend.verify_execution(state)?;
    let mut remote = Remote {
        backend,
        state,
        started: Instant::now(),
    };
    parse_inventory(&remote.inventory()?)
}
pub fn sync(state: &Value, directory: &Path, backend: &Backend, persist: bool) -> Result<Value> {
    backend.verify_execution(state)?;
    let mut remote = Remote {
        backend,
        state,
        started: Instant::now(),
    };
    sync_with(state, directory, &mut remote, persist)
}
pub fn sync_with(
    state: &Value,
    directory: &Path,
    remote: &mut impl Transport,
    persist: bool,
) -> Result<Value> {
    let started = Instant::now();
    let directory = files::absolute(directory)?;
    crate::state::create_directory(&directory)?;
    let destination = text(&state["sync"], "destination")?;
    crate::config::relative_path(destination)?;
    let exports = directory.join(destination);
    crate::state::create_directory(&exports)?;
    let (mut previous, source) = previous(state)?;
    let spec = crate::config::Sources {
        include: vec![],
        exclude: exclusions(state)?,
    };
    previous.retain(|p, _| !crate::sources::excluded(p, &spec));
    let before = parse_inventory(&remote.inventory()?)?;
    ensure!(
        before.keys().all(|p| !crate::sources::excluded(p, &spec)),
        "The worker exported a path excluded by the project"
    );
    let current = records(&before);
    let changes: Vec<_> = current
        .iter()
        .filter(|(p, e)| previous.get(*p) != Some(*e))
        .map(|(p, _)| p.clone())
        .collect();
    let deletions: Vec<_> = previous
        .keys()
        .filter(|p| !current.contains_key(*p))
        .cloned()
        .collect();
    // Crash leftovers have an explicit .incomplete prefix and are never considered exports.
    let stage = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .prefix(".incomplete-")
        .tempdir_in(&exports)?;
    let project = stage.path().join("project");
    fs::create_dir(&project)?;
    for (path, entry) in &before {
        ensure!(
            started.elapsed() < Duration::from_secs(300),
            "Overall sync time limit exceeded"
        );
        let data = if previous.get(path) == current.get(path) {
            let (actual, data) = snapshot::local_bytes(&source, path)?;
            ensure!(
                &actual == entry,
                "Previous local source was altered: {path}"
            );
            data
        } else {
            let bytes = remote.file(path)?;
            ensure!(
                bytes.len() <= snapshot::JSON_LIMIT,
                "File response is too large"
            );
            let payload: FilePayload = serde_json::from_value(crate::json::parse(&bytes)?)?;
            ensure!(
                payload.path == *path && payload.entry == *entry,
                "File metadata mismatch"
            );
            ensure!(
                payload.data.len() <= entry.size.div_ceil(3) * 4,
                "Base64 is too large"
            );
            let data = STANDARD
                .decode(payload.data)
                .map_err(|e| invalid(format!("Invalid Base64: {e}")))?;
            ensure!(
                data.len() == entry.size && files::hash(&data) == entry.sha256,
                "Transferred content mismatch: {path}"
            );
            data
        };
        let target = project.join(path);
        let parent = target
            .parent()
            .ok_or_else(|| invalid("Missing parent".into()))?;
        fs::create_dir_all(parent)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        out.write_all(&data)?;
        out.set_permissions(fs::Permissions::from_mode(if entry.executable {
            0o755
        } else {
            0o644
        }))?;
        out.sync_all()?;
    }
    ensure!(
        before == parse_inventory(&remote.inventory()?)?,
        "Sandbox project changed during sync; retry"
    );
    ensure!(
        started.elapsed() < Duration::from_secs(300),
        "Overall sync time limit exceeded"
    );
    let mut manifest = json!({"schema_version":2,"sandbox_id":text(state,"sandbox_id")?,"files":current,"changes":changes,"deletions":deletions});
    if state.get("continuous").is_some() {
        manifest["continuous"] = crate::continuous::host::export_binding(state)?;
    }
    crate::environment_lock::atomic_json(&stage.path().join("manifest.json"), &manifest)?;
    sync_directories(&project)?;
    files::open_directory(stage.path())?.sync_all()?;
    let suffix = stage
        .path()
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix(".incomplete-"))
        .ok_or_else(|| invalid("Invalid staging name".into()))?;
    let published = exports.join(format!("sync-{suffix}"));
    ensure!(!published.try_exists()?, "Export already exists");
    fs::rename(stage.path(), &published)?;
    files::open_directory(&exports)?.sync_all()?;
    let mut next = state.clone();
    next["last_sync"] = json!(published);
    if persist {
        crate::environment_lock::atomic_json(&directory.join("state.json"), &next)?;
    }
    Ok(next)
}
fn previous(state: &Value) -> Result<(Snapshot, PathBuf)> {
    if let Some(path) = state.get("last_sync").and_then(Value::as_str) {
        let root = PathBuf::from(path);
        ensure!(
            root.is_absolute(),
            "An absolute path to the previous export is required"
        );
        let manifest = crate::json::parse(&files::read_limited(
            &root.join("manifest.json"),
            2 * 1024 * 1024,
        )?)?;
        ensure!(
            manifest["schema_version"] == 2 && manifest["sandbox_id"] == state["sandbox_id"],
            "Incompatible previous manifest"
        );
        let records: Snapshot = serde_json::from_value(manifest["files"].clone())?;
        crate::continuous::host::verify_export(state, &manifest)?;
        validate_records(&records)?;
        Ok((records, root.join("project")))
    } else {
        let records: Snapshot = serde_json::from_value(state["host_sources"].clone())?;
        validate_records(&records)?;
        let root = PathBuf::from(text(state, "project_snapshot")?);
        ensure!(
            root.is_absolute(),
            "An absolute source snapshot path is required"
        );
        Ok((records, root))
    }
}
fn validate_records(records: &Snapshot) -> Result<()> {
    let inventory = records
        .iter()
        .map(|(p, r)| {
            (
                p.clone(),
                snapshot::Entry {
                    sha256: r.sha256.clone(),
                    executable: r.executable,
                    size: 0,
                },
            )
        })
        .collect();
    snapshot::validate(&inventory)
}
fn sync_directories(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_directories(&entry.path())?;
        }
    }
    files::open_directory(root)?.sync_all()?;
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

pub fn exclusions(state: &Value) -> Result<Vec<String>> {
    let value = &state["desired_inputs"]["evaluated"]["config"]["sources"]["exclude"];
    let exclude: Vec<String> = if value.is_null() {
        vec![]
    } else {
        serde_json::from_value(value.clone())?
    };
    ensure!(exclude.len() <= 1000, "Too many exclusions");
    for path in &exclude {
        crate::config::relative_path(path)?;
    }
    Ok(exclude)
}

/// Untrusted, bounded worker metadata. Never used as export or publication authority.
pub(crate) fn observe_preview(
    state: &Value,
    backend: &Backend,
) -> Result<ladybom::inventory::Preview> {
    backend.verify_execution(state)?;
    let remote = Remote {
        backend,
        state,
        started: Instant::now(),
    };
    let bytes = remote.call("snapshot-preview", None).map_err(|e| e.context("Live inspection requires the optional snapshot-preview worker capability; explicitly update the sandbox runtime. No fallback was attempted"))?;
    parse_preview(&bytes, &exclusions(state)?)
}
pub fn parse_preview(bytes: &[u8], exclude: &[String]) -> Result<ladybom::inventory::Preview> {
    ensure!(
        bytes.len() <= snapshot::JSON_LIMIT,
        "Preview JSON limit exceeded"
    );
    let preview: ladybom::inventory::Preview = serde_json::from_value(crate::json::parse(bytes)?)?;
    preview.validate(exclude)?;
    Ok(preview)
}
