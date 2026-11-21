//! Bounded source handoff. Host admission and writer quiescence are prerequisites.
//! The wire format is an eight-byte header length, strict JSON, then file bytes
//! in inventory order. Paths and lengths come only from the validated inventory.
use super::{
    invalid,
    model::{self, Acknowledgement, RefreshOffer},
};
use crate::{
    error::{ensure, Result},
    files, image, json, plan,
    snapshot::{self, Inventory},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

pub const BUNDLE_LIMIT: usize = snapshot::TOTAL_LIMIT + snapshot::JSON_LIMIT + 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    offer: RefreshOffer,
    runtime: String,
    inventory: Inventory,
    context: Value,
}
impl Request {
    fn validate(&self) -> Result<()> {
        self.offer.validate()?;
        snapshot::validate(&self.inventory)?;
        ensure!(
            self.schema_version == 1 && model::token(&self.runtime),
            "Invalid worker version or runtime"
        );
        ensure!(
            plan::digest(&self.inventory)? == self.offer.tree,
            "Worker inventory differs from selected tree"
        );
        ensure!(
            plan::digest(&self.context)? == self.offer.context,
            "Worker context differs from selected context"
        );
        ensure!(
            serde_json::to_vec(&self.context)?.len() <= 256 * 1024,
            "Continuation context exceeds 256 KiB"
        );
        Ok(())
    }
    fn ack(&self) -> Acknowledgement {
        Acknowledgement::for_offer(&self.offer, &self.runtime)
    }
}

pub fn bundle(
    offer: &RefreshOffer,
    runtime: &str,
    context: &Value,
    source: &Path,
) -> Result<Vec<u8>> {
    let request = Request {
        schema_version: 1,
        offer: offer.clone(),
        runtime: runtime.into(),
        inventory: snapshot::inventory(source)?,
        context: context.clone(),
    };
    request.validate()?;
    let header = serde_json::to_vec(&request)?;
    ensure!(
        header.len() <= snapshot::JSON_LIMIT,
        "Worker header exceeds limit"
    );
    let mut result = (header.len() as u64).to_be_bytes().to_vec();
    result.extend_from_slice(&header);
    for (path, expected) in &request.inventory {
        ensure!(
            files::open_regular(&source.join(path))?.metadata()?.nlink() == 1,
            "Hard-linked candidate file refused: {path}"
        );
        let (entry, bytes) = snapshot::local_bytes(source, path)?;
        ensure!(
            &entry == expected,
            "Candidate changed while packaging: {path}"
        );
        result.extend_from_slice(&bytes);
    }
    ensure!(
        snapshot::inventory(source)? == request.inventory,
        "Candidate changed while packaging"
    );
    Ok(result)
}

fn decode(bytes: &[u8]) -> Result<(Request, &[u8])> {
    ensure!(
        bytes.len() >= 8 && bytes.len() <= BUNDLE_LIMIT,
        "Invalid worker bundle length"
    );
    let mut prefix = [0; 8];
    prefix.copy_from_slice(&bytes[..8]);
    let length = usize::try_from(u64::from_be_bytes(prefix))
        .map_err(|_| invalid("Invalid header length"))?;
    ensure!(
        length <= snapshot::JSON_LIMIT && length <= bytes.len() - 8,
        "Truncated worker header"
    );
    let request: Request = serde_json::from_value(json::parse(&bytes[8..8 + length])?)?;
    request.validate()?;
    let payload = &bytes[8 + length..];
    let mut remaining = payload;
    for entry in request.inventory.values() {
        ensure!(remaining.len() >= entry.size, "Truncated worker file");
        ensure!(
            files::hash(&remaining[..entry.size]) == entry.sha256,
            "Corrupt worker file"
        );
        remaining = &remaining[entry.size..];
    }
    ensure!(remaining.is_empty(), "Trailing worker bytes");
    Ok((request, payload))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStep {
    Staged,
    BackupCopied,
    SourceFileRemoved,
    ProjectRemoved,
    Installed,
    ContextWritten,
    MarkerWritten,
}

// Docker OverlayFS cannot rename an image-layer directory. Retain all bounded
// regular files (including generated files excluded from source exports), then
// remove that directory under the host's execution fence. Links/special files
// require a fresh incarnation; never follow or silently discard them.
fn backup_inventory(root: &Path) -> Result<Inventory> {
    fn walk(
        root: &Path,
        relative: &str,
        result: &mut Inventory,
        entries: &mut usize,
        total: &mut usize,
    ) -> Result<()> {
        let directory = root.join(relative);
        files::open_directory(&directory)?;
        for item in fs::read_dir(&directory)? {
            let item = item?;
            *entries += 1;
            ensure!(
                *entries <= 20000,
                "Retained project has too many entries; select a fresh sandbox"
            );
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| invalid("Non-UTF8 project entry"))?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            crate::config::relative_path(&path)?;
            ensure!(
                path.len() <= 4096 && path.split('/').count() <= 65,
                "Retained project path exceeds bound"
            );
            if item.file_type()?.is_dir() {
                walk(root, &path, result, entries, total)?;
            } else {
                ensure!(
                    item.file_type()?.is_file(),
                    "Generated links or special files require a fresh sandbox"
                );
                let file = files::open_regular(&item.path())?;
                let meta = file.metadata()?;
                ensure!(
                    meta.nlink() == 1,
                    "Linked generated file requires a fresh sandbox"
                );
                let bytes = files::read_file(file, snapshot::FILE_LIMIT)?;
                *total = total
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid("Retained project size overflow"))?;
                ensure!(
                    *total <= snapshot::TOTAL_LIMIT && result.len() < 5000,
                    "Retained project exceeds backup bound; select a fresh sandbox"
                );
                result.insert(
                    path,
                    snapshot::Entry {
                        sha256: files::hash(&bytes),
                        size: bytes.len(),
                        executable: meta.mode() & 0o111 != 0,
                    },
                );
            }
        }
        Ok(())
    }
    let mut result = Inventory::new();
    walk(root, "", &mut result, &mut 0, &mut 0)?;
    Ok(result)
}

/// Advisory capability observation; apply independently repeats all validation.
/// A negative result selects a fresh sandbox without modifying this workspace.
pub fn profile(root: &Path) -> Value {
    serde_json::json!({"schema_version":1,"warm_source_swap":backup_inventory(root).is_ok()})
}

fn backup(root: &Path, previous: &Path, attempt: &Path) -> Result<()> {
    let inventory = backup_inventory(root)?;
    let temporary = tempfile::Builder::new()
        .prefix("backup-")
        .tempdir_in(attempt)?;
    for (path, entry) in &inventory {
        let bytes = files::read_limited(&root.join(path), snapshot::FILE_LIMIT)?;
        ensure!(
            bytes.len() == entry.size && files::hash(&bytes) == entry.sha256,
            "Source changed during backup"
        );
        image::write_source(temporary.path(), path, &bytes, entry.executable)?;
    }
    ensure!(
        backup_inventory(root)? == inventory && backup_inventory(temporary.path())? == inventory,
        "Source changed during backup"
    );
    sync_tree(temporary.path())?;
    fs::rename(temporary.path(), previous)?;
    files::open_directory(attempt)?.sync_all()?;
    Ok(())
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_value(json::parse(&files::read_limited(
        path,
        snapshot::JSON_LIMIT,
    )?)?)?)
}
fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    files::open_directory(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        files::open_directory(parent)?.sync_all()?;
    }
    Ok(())
}
fn tree(path: &Path) -> Result<String> {
    plan::digest(&snapshot::inventory(path)?)
}
pub(crate) fn sync_tree(path: &Path) -> Result<()> {
    files::open_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        } else {
            files::open_regular(&entry.path())?.sync_all()?;
        }
    }
    files::open_directory(path)?.sync_all()?;
    Ok(())
}
fn validate_epoch(control: &Path, request: &Request) -> Result<()> {
    let marker = control.join("current.json");
    if exists(&marker)? {
        let current: Acknowledgement = read(&marker)?;
        let offer = &request.offer;
        ensure!(
            current.schema_version == 1
                && current.task == offer.task
                && current.sandbox_id == offer.sandbox_id
                && current.owner == offer.owner
                && current.environment == offer.environment
                && current.epoch == offer.expected_epoch,
            "Worker epoch or incarnation differs from handoff"
        );
    } else {
        ensure!(
            request.offer.expected_epoch == request.offer.incarnation_epoch,
            "Worker epoch marker is missing"
        );
    }
    Ok(())
}

pub fn apply(root: &Path, control: &Path, bytes: &[u8]) -> Result<Acknowledgement> {
    apply_with(root, control, bytes, |_| Ok(()))
}

/// Observer is called only after durable transitions; errors leave recoverable evidence.
pub fn apply_with(
    root: &Path,
    control: &Path,
    bytes: &[u8],
    mut observe: impl FnMut(WorkerStep) -> Result<()>,
) -> Result<Acknowledgement> {
    let (request, payload) = decode(bytes)?;
    let parent = root
        .parent()
        .ok_or_else(|| invalid("Project parent is missing"))?;
    files::open_directory(parent)?;
    directory(control)?;
    let attempt = control.join(&request.offer.attempt);
    if !exists(&attempt)? {
        let mut retained = 0;
        for entry in fs::read_dir(control)? {
            if entry?.file_type()?.is_dir() {
                retained += 1;
            }
            ensure!(
                retained < 32,
                "Retained source limit reached; select a fresh sandbox incarnation"
            );
        }
    }
    directory(&attempt)?;
    let intent = attempt.join("intent.json");
    if exists(&intent)? {
        ensure!(
            read::<Request>(&intent)? == request,
            "Attempt was already used for a different request"
        );
    } else {
        validate_epoch(control, &request)?;
        ensure!(
            tree(root)? == request.offer.previous_tree,
            "Sandbox changed since checkpoint"
        );
        files::publish_json(&intent, &request, false)?;
    }
    let ack = request.ack();
    let marker = control.join("current.json");
    let context = serde_json::json!({"binding":ack,"context":request.context});
    if exists(&marker)? && read::<Acknowledgement>(&marker)? == ack {
        ensure!(
            tree(root)? == request.offer.tree,
            "Completed refresh has subsequent edits; replay refused"
        );
        ensure!(
            read::<Value>(&control.join("context.json"))? == context,
            "Continuation context changed after acknowledgement"
        );
        return Ok(ack);
    }
    validate_epoch(control, &request)?;
    if request.offer.previous_tree == request.offer.tree {
        ensure!(
            tree(root)? == request.offer.tree,
            "No-op refresh has subsequent edits"
        );
        // Do not remove installed, excluded files such as node_modules or .venv.
        files::publish_json(&control.join("context.json"), &context, true)?;
        observe(WorkerStep::ContextWritten)?;
        files::publish_json(&marker, &ack, true)?;
        observe(WorkerStep::MarkerWritten)?;
        return Ok(ack);
    }
    let stage = attempt.join("stage");
    let previous = attempt.join("previous");
    if !exists(&previous)? {
        ensure!(
            tree(root)? == request.offer.previous_tree,
            "Sandbox changed since checkpoint"
        );
        if !exists(&stage)? {
            let temporary = tempfile::Builder::new()
                .prefix("staging-")
                .tempdir_in(&attempt)?;
            let mut remaining = payload;
            for (path, entry) in &request.inventory {
                image::write_source(
                    temporary.path(),
                    path,
                    &remaining[..entry.size],
                    entry.executable,
                )?;
                remaining = &remaining[entry.size..];
            }
            ensure!(
                snapshot::inventory(temporary.path())? == request.inventory,
                "Staged tree differs from selected tree"
            );
            sync_tree(temporary.path())?;
            fs::rename(temporary.path(), &stage)?;
            files::open_directory(&attempt)?.sync_all()?;
        }
        ensure!(
            tree(&stage)? == request.offer.tree,
            "Retained stage differs from request"
        );
        observe(WorkerStep::Staged)?;
        ensure!(
            tree(root)? == request.offer.previous_tree,
            "Sandbox changed before replacement"
        );
        backup(root, &previous, &attempt)?;
        observe(WorkerStep::BackupCopied)?;
    }
    ensure!(
        tree(&previous)? == request.offer.previous_tree,
        "Retained previous tree differs from checkpoint"
    );
    if exists(&stage)? {
        ensure!(
            tree(&stage)? == request.offer.tree,
            "Stage is missing or changed"
        );
        if exists(root)? {
            let retained = backup_inventory(&previous)?;
            let remaining = backup_inventory(root)?;
            ensure!(remaining.iter().all(|(path,entry)|retained.get(path)==Some(entry)),
                "Source changed during interrupted removal; retained backup and edits require inspection");
            for path in remaining.keys() {
                fs::remove_file(root.join(path))?;
                observe(WorkerStep::SourceFileRemoved)?;
            }
            ensure!(
                backup_inventory(root)?.is_empty(),
                "Source acquired new files during removal"
            );
            fs::remove_dir_all(root)?;
            files::open_directory(parent)?.sync_all()?;
            observe(WorkerStep::ProjectRemoved)?;
        }
        fs::rename(&stage, root)?;
        files::open_directory(parent)?.sync_all()?;
        files::open_directory(&attempt)?.sync_all()?;
    }
    ensure!(
        tree(root)? == request.offer.tree,
        "Installed source differs from request"
    );
    observe(WorkerStep::Installed)?;
    files::publish_json(&control.join("context.json"), &context, true)?;
    observe(WorkerStep::ContextWritten)?;
    files::publish_json(&marker, &ack, true)?;
    observe(WorkerStep::MarkerWritten)?;
    Ok(ack)
}

pub fn inspect(
    root: &Path,
    control: &Path,
    offer: &RefreshOffer,
) -> Result<Option<Acknowledgement>> {
    offer.validate()?;
    files::open_directory(control)?;
    let intent = control.join(&offer.attempt).join("intent.json");
    if !exists(&intent)? {
        return Ok(None);
    }
    let request: Request = read(&intent)?;
    request.validate()?;
    ensure!(
        &request.offer == offer,
        "Retained attempt differs from request"
    );
    let marker = control.join("current.json");
    if !exists(&marker)? {
        return Ok(None);
    }
    let ack: Acknowledgement = read(&marker)?;
    if ack != request.ack() {
        return Ok(None);
    }
    ensure!(
        tree(root)? == offer.tree,
        "Acknowledged source has subsequent edits"
    );
    Ok(Some(ack))
}
