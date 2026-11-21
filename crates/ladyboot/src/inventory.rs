//! Verify delivered files, including kernel/initramfs/modules and generated units.
//! The manifest is captured during assembly; Nix references are not an inventory.
use nickel_util::{
    error::{Error, Result},
    files, json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Component, Path},
    time::{Duration, Instant},
};

const MANIFEST: &str = "usr/share/ladyboot/inventory.json";
const MAX_FILES: usize = 200_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    self_excluded: String,
    resolved_plan: Value,
    files: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: String,
    mode: u32,
    kind: String,
    bytes: Option<u64>,
    sha256: Option<String>,
    target: Option<String>,
}
fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}

pub fn verify(root: &Path) -> Result<Value> {
    let _directory = files::open_directory(root)?;
    let bytes = files::read_limited(&root.join(MANIFEST), 64 * 1024 * 1024)?;
    let manifest: Manifest = serde_json::from_value(json::parse(&bytes)?)?;
    if manifest.schema_version != 1
        || manifest.self_excluded != MANIFEST
        || manifest.files.len() > MAX_FILES
    {
        return Err(invalid("Unsupported or oversized inventory"));
    }
    let mut expected = BTreeMap::new();
    let mut unit_links = Vec::new();
    for entry in &manifest.files {
        let path = Path::new(&entry.path);
        if entry.kind == "symlink"
            && (entry.path.starts_with("etc/systemd/system/")
                || entry.path.starts_with("usr/lib/systemd/system/"))
            && (entry.path.contains(".wants/") || entry.path.contains(".requires/"))
        {
            unit_links.push(json!({"path":entry.path,"target":entry.target}));
        }
        if path.as_os_str().is_empty()
            || entry.path.len() > 4096
            || path.is_absolute()
            || !path.components().all(|c| matches!(c, Component::Normal(_)))
            || entry
                .path
                .split('/')
                .any(|p| p.is_empty() || p == "." || p == "..")
            || entry.path == MANIFEST
            || expected.insert(entry.path.clone(), entry).is_some()
        {
            return Err(invalid("Unsafe or duplicate inventory path"));
        }
    }
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0usize;
    let mut total = 0u64;
    let deadline = Instant::now() + Duration::from_secs(300);
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            if Instant::now() > deadline {
                return Err(invalid("Inventory verification time limit"));
            }
            let path = entry?.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| invalid("Inventory escaped root"))?
                .to_str()
                .ok_or_else(|| invalid("Non-UTF8 inventory path"))?
                .to_owned();
            if relative == MANIFEST {
                continue;
            }
            count += 1;
            if count > MAX_FILES {
                return Err(invalid("Inventory file count limit"));
            }
            let record = expected
                .remove(&relative)
                .ok_or_else(|| invalid(format!("Unrecorded delivered path: {relative}")))?;
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.permissions().mode() & 0o7777 != record.mode {
                return Err(invalid(format!("Inventory mode mismatch: {relative}")));
            }
            let valid = if metadata.is_symlink() {
                record.kind == "symlink"
                    && record.target.as_deref() == fs::read_link(&path)?.to_str()
                    && record.bytes.is_none()
                    && record.sha256.is_none()
            } else if metadata.is_dir() {
                pending.push(path);
                record.kind == "directory"
                    && record.target.is_none()
                    && record.bytes.is_none()
                    && record.sha256.is_none()
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| invalid("Inventory byte overflow"))?;
                if total > MAX_BYTES {
                    return Err(invalid("Inventory byte limit"));
                }
                let mut stream = files::open_regular(&path)?;
                let mut digest = Sha256::new();
                let mut buffer = [0u8; 65536];
                let mut read = 0u64;
                loop {
                    let size = stream.read(&mut buffer)?;
                    if size == 0 {
                        break;
                    }
                    read += size as u64;
                    if read > metadata.len() || Instant::now() > deadline {
                        return Err(invalid("Inventory changed or verification time limit"));
                    }
                    digest.update(&buffer[..size]);
                }
                record.kind == "file"
                    && record.bytes == Some(read)
                    && record.target.is_none()
                    && record.sha256.as_deref() == Some(format!("{:x}", digest.finalize()).as_str())
            } else {
                false
            };
            if !valid {
                return Err(invalid(format!("Inventory content mismatch: {relative}")));
            }
        }
    }
    if !expected.is_empty() {
        return Err(invalid("Missing delivered files"));
    }
    Ok(
        json!({"verified":true,"inventory_sha256":files::hash(&bytes),"files":count,
        "regular_file_bytes":total,"resolved_plan":manifest.resolved_plan,"enabled_unit_links":unit_links,
        "self_excluded":MANIFEST,"boot_install_update_rollback_qualified":false}),
    )
}
