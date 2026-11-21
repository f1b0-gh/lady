use super::{invalid, FileEntry, InspectedRoot};
use crate::{error::Result, files, json};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_FILES: usize = 200_000;
const MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024;
const MAX_MANIFEST: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    self_excluded: String,
    resolved_plan: serde_json::Value,
    files: Vec<FileEntry>,
}

pub(super) fn relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 4096
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || path.split('/').count() > 64
        || !Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(invalid("Invalid artifact-relative path"));
    }
    Ok(())
}

pub(super) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn validate_entry(entry: &FileEntry) -> Result<()> {
    relative(&entry.path)?;
    if entry.mode > 0o7777 {
        return Err(invalid("Invalid file mode"));
    }
    let valid = match entry.kind.as_str() {
        "file" => {
            entry.bytes.is_some_and(|size| size <= MAX_BYTES)
                && entry.sha256.as_deref().is_some_and(is_digest)
                && entry.target.is_none()
        }
        "directory" => entry.bytes.is_none() && entry.sha256.is_none() && entry.target.is_none(),
        "symlink" => {
            entry.bytes.is_none()
                && entry.sha256.is_none()
                && entry
                    .target
                    .as_deref()
                    .is_some_and(|v| !v.is_empty() && v.len() <= 4096 && !v.contains('\0'))
        }
        _ => false,
    };
    if !valid {
        return Err(invalid("Inconsistent artifact file entry"));
    }
    Ok(())
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

pub(super) fn hash_file(mut file: File, budget: u64, deadline: Instant) -> Result<(String, u64)> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() > budget {
        return Err(invalid(
            "Artifact file exceeds byte budget or is not regular",
        ));
    }
    let mut digest = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        if Instant::now() > deadline {
            return Err(invalid("Artifact inspection time limit"));
        }
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > budget {
            return Err(invalid("Artifact byte budget exceeded"));
        }
        digest.update(&buffer[..n]);
    }
    if bytes != before.len() || !unchanged(&before, &file.metadata()?) {
        return Err(invalid("Artifact changed while hashing"));
    }
    Ok((format!("{:x}", digest.finalize()), bytes))
}

/// Verify a declared rootfs inventory without following any delivered symlink.
/// The manifest argument is a normalized path relative to the realized root.
pub fn inspect_rootfs(root: &Path, manifest_path: &Path) -> Result<InspectedRoot> {
    let manifest_path = manifest_path
        .to_str()
        .ok_or_else(|| invalid("Non-UTF8 manifest path"))?;
    relative(manifest_path)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let directory = files::open_directory(root)?;
    let manifest_file = root.join(manifest_path);
    let bytes = files::read_limited(&manifest_file, MAX_MANIFEST)?;
    let manifest: Manifest =
        serde_json::from_value(json::parse_with_limits(&bytes, MAX_MANIFEST, MAX_FILES)?)?;
    if manifest.schema_version != 1
        || manifest.self_excluded != manifest_path
        || !manifest.resolved_plan.is_object()
        || manifest.files.len() > MAX_FILES
    {
        return Err(invalid("Unsupported or oversized assembly inventory"));
    }
    let mut expected = BTreeMap::new();
    let mut declared_bytes = 0u64;
    for entry in &manifest.files {
        validate_entry(entry)?;
        declared_bytes = declared_bytes
            .checked_add(entry.bytes.unwrap_or(0))
            .ok_or_else(|| invalid("Artifact byte budget overflow"))?;
        if declared_bytes > MAX_BYTES
            || entry.path == manifest_path
            || expected.insert(entry.path.clone(), entry).is_some()
        {
            return Err(invalid("Duplicate, excluded or oversized inventory entry"));
        }
    }
    let mut pending = vec![(directory, String::new(), 0usize)];
    let mut count = 0usize;
    let mut total = 0u64;
    while let Some((directory, prefix, depth)) = pending.pop() {
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let before = directory.metadata()?;
        for item in fs::read_dir(&pinned)? {
            if Instant::now() > deadline {
                return Err(invalid("Artifact inspection time limit"));
            }
            let item = item?;
            let name = item.file_name();
            let text = name
                .to_str()
                .ok_or_else(|| invalid("Non-UTF8 delivered path"))?;
            let path = if prefix.is_empty() {
                text.to_owned()
            } else {
                format!("{prefix}/{text}")
            };
            if path == manifest_path {
                continue;
            }
            count += 1;
            if count > MAX_FILES || depth >= 64 {
                return Err(invalid("Artifact traversal budget exceeded"));
            }
            let entry = expected
                .remove(&path)
                .ok_or_else(|| invalid(format!("Unrecorded path: {path}")))?;
            let anchored = pinned.join(&name);
            let metadata = fs::symlink_metadata(&anchored)?;
            if metadata.permissions().mode() & 0o7777 != entry.mode {
                return Err(invalid(format!("Artifact mode mismatch: {path}")));
            }
            let valid = if metadata.is_symlink() {
                entry.kind == "symlink"
                    && fs::read_link(&anchored)?.to_str() == entry.target.as_deref()
                    && unchanged(&metadata, &fs::symlink_metadata(&anchored)?)
            } else if metadata.is_dir() {
                let child = files::open_child(&directory, &name, true)?;
                if !unchanged(&metadata, &child.metadata()?) {
                    return Err(invalid("Directory changed while opening"));
                }
                pending.push((child, path.clone(), depth + 1));
                entry.kind == "directory"
            } else if metadata.is_file() {
                let child = files::open_child(&directory, &name, false)?;
                if !unchanged(&metadata, &child.metadata()?) {
                    return Err(invalid("File changed while opening"));
                }
                let (digest, length) = hash_file(child, MAX_BYTES - total, deadline)?;
                total += length;
                entry.kind == "file"
                    && entry.bytes == Some(length)
                    && entry.sha256.as_deref() == Some(&digest)
                    && unchanged(&metadata, &fs::symlink_metadata(&anchored)?)
            } else {
                return Err(invalid(format!("Unsupported delivered file type: {path}")));
            };
            if !valid {
                return Err(invalid(format!("Artifact content mismatch: {path}")));
            }
        }
        if !unchanged(&before, &directory.metadata()?) {
            return Err(invalid("Directory changed while reading"));
        }
    }
    if !expected.is_empty() || files::read_limited(&manifest_file, MAX_MANIFEST)? != bytes {
        return Err(invalid("Missing delivered paths or changed manifest"));
    }
    let mut records = manifest.files;
    records.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(InspectedRoot {
        manifest_path: manifest_path.into(),
        manifest_sha256: files::hash(&bytes),
        content_bytes: total,
        files: records,
    })
}
