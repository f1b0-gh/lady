//! One forward image-archive scan. Only pre-manifest names and small-file
//! digests are retained; layer payloads are streamed and never cached.
use crate::{
    config::relative_path,
    error::{ensure, Error, Result},
    files,
    state::text,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
};

const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INDEX_NAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MEMBERS: usize = 100000;

enum Metadata {
    Digest(sha2::digest::Output<Sha256>),
    Invalid,
    Duplicate,
}

fn metadata(entry: &mut tar::Entry<'_, impl Read>) -> Result<Metadata> {
    if !entry.header().entry_type().is_file() || entry.size() > MAX_METADATA_BYTES {
        return Ok(Metadata::Invalid);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = entry.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(Metadata::Digest(digest.finalize()))
}

pub fn archive_image_id(path: &Path) -> Result<String> {
    let mut file = BufReader::new(files::open_regular(path)?);
    if file.fill_buf()?.starts_with(&[0x1f, 0x8b]) {
        image_id_from_reader(flate2::read::MultiGzDecoder::new(file))
    } else {
        image_id_from_reader(file)
    }
}

struct BoundedReader<R> {
    inner: R,
    remaining: u64,
}
impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut probe = [0];
            return if self.inner.read(&mut probe)? == 0 {
                Ok(0)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Image archive byte limit exceeded",
                ))
            };
        }
        let limit = (bytes.len() as u64).min(self.remaining) as usize;
        let count = self.inner.read(&mut bytes[..limit])?;
        self.remaining -= count as u64;
        Ok(count)
    }
}
fn image_id_from_reader(reader: impl Read) -> Result<String> {
    image_id_from_reader_with_limit(reader, MAX_ARCHIVE_BYTES)
}
fn image_id_from_reader_with_limit(reader: impl Read, limit: u64) -> Result<String> {
    let mut archive = tar::Archive::new(BoundedReader {
        inner: reader,
        remaining: limit,
    });
    // Consume padding through real EOF, so neither a byte cap nor an early
    // end marker can hide a later duplicate metadata member.
    archive.set_ignore_zeros(true);
    let mut before_manifest: BTreeMap<PathBuf, Metadata> = BTreeMap::new();
    let mut index_name_bytes = 0;
    let mut config_name: Option<PathBuf> = None;
    let mut selected = None;
    for (index, entry) in archive.entries()?.raw(true).enumerate() {
        ensure!(index < MAX_MEMBERS, "Image archive has too many members");
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        // Decoded iteration allocates GNU/PAX payloads before yielding entries.
        // Docker metadata here uses ordinary headers; reject extensions before
        // any payload read instead of silently interpreting an unbounded record.
        ensure!(
            !kind.is_gnu_longname()
                && !kind.is_gnu_longlink()
                && !kind.is_pax_local_extensions()
                && !kind.is_pax_global_extensions()
                && !kind.is_gnu_sparse(),
            "Image tar extensions and sparse records are unsupported"
        );
        let path = entry.path()?.into_owned();
        if path == Path::new("manifest.json") {
            ensure!(
                config_name.is_none(),
                "Duplicate image member: manifest.json"
            );
            ensure!(
                entry.header().entry_type().is_file() && entry.size() <= MAX_METADATA_BYTES,
                "Invalid image metadata"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            let manifest: Value = serde_json::from_slice(&bytes)?;
            let rows = manifest
                .as_array()
                .ok_or_else(|| invalid("Invalid image manifest".into()))?;
            ensure!(rows.len() == 1, "Exactly one image is required");
            let row = rows
                .first()
                .ok_or_else(|| invalid("Empty image manifest".into()))?;
            let name = text(row, "Config")?;
            relative_path(name)?;
            let name = PathBuf::from(name);
            selected = if name == path {
                Some(Metadata::Digest(Sha256::digest(&bytes)))
            } else {
                before_manifest.remove(&name)
            };
            config_name = Some(name);
            // Once the selected name is known, no unrelated digest/name is needed.
            before_manifest.clear();
        } else if let Some(name) = &config_name {
            if &path == name {
                ensure!(selected.is_none(), "Duplicate image member");
                selected = Some(metadata(&mut entry)?);
            }
        } else if let Some(previous) = before_manifest.get_mut(&path) {
            *previous = Metadata::Duplicate;
        } else {
            let name_bytes = path.as_os_str().as_encoded_bytes().len();
            ensure!(
                name_bytes <= MAX_INDEX_NAME_BYTES - index_name_bytes,
                "Image metadata index path budget exceeded"
            );
            index_name_bytes += name_bytes;
            before_manifest.insert(path, metadata(&mut entry)?);
        }
    }
    ensure!(config_name.is_some(), "Missing image member: manifest.json");
    match selected {
        Some(Metadata::Digest(digest)) => Ok(format!("sha256:{digest:x}")),
        Some(Metadata::Invalid) => Err(invalid("Invalid image metadata".into())),
        Some(Metadata::Duplicate) => Err(invalid("Duplicate image member".into())),
        None => Err(invalid("Missing image configuration member".into())),
    }
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
