use super::{invalid, Request};
use crate::{
    error::{ensure, Result},
    storage::Limits,
};
use std::io::{Read, Write};

pub(super) const AREAS: [&str; 3] = ["control", "artifacts", "incoming"];
pub(super) const MANIFEST: &str = "broker-export.json";

pub(super) fn path(name: &str) -> Result<Vec<&str>> {
    let parts: Vec<_> = name.split('/').collect();
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && parts.len() <= 32
            && parts.iter().all(|part| !part.is_empty()
                && *part != "."
                && *part != ".."
                && part.len() <= 100
                && part.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')),
        "Export path outside bounded canonical namespace"
    );
    Ok(parts)
}
pub(super) fn header(name: &str, directory: bool, size: u64) -> Result<tar::Header> {
    path(name)?;
    ensure!(!directory || size == 0, "Directory has payload");
    let mut header = tar::Header::new_ustar();
    header.set_path(name)?;
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_size(size);
    header.set_mode(if directory { 0o700 } else { 0o600 });
    header.set_uid(10001);
    header.set_gid(10001);
    header.set_mtime(0);
    header.set_cksum();
    Ok(header)
}

pub(super) struct Budget<'a> {
    limits: &'a Limits,
    pub entries: u64,
    bytes: u64,
}
impl<'a> Budget<'a> {
    pub fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            entries: 0,
            bytes: 0,
        }
    }
    pub fn entry(&mut self) -> Result<()> {
        self.entries += 1;
        ensure!(
            self.entries <= self.limits.inodes,
            "Export exceeds inode budget"
        );
        Ok(())
    }
    pub fn content(&mut self, size: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(size)
            .ok_or_else(|| invalid("Export byte overflow"))?;
        ensure!(
            self.bytes <= self.limits.bytes,
            "Export exceeds logical byte budget"
        );
        Ok(())
    }
}

fn block(input: &mut impl Read) -> Result<[u8; 512]> {
    let mut bytes = [0; 512];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn padding(input: &mut impl Read, size: u64) -> Result<()> {
    let padding = (512 - size % 512) % 512;
    let mut bytes = [0; 512];
    input.read_exact(&mut bytes[..padding as usize])?;
    ensure!(bytes.iter().all(|b| *b == 0), "Nonzero export padding");
    Ok(())
}
fn content(input: &mut impl Read, size: u64, mut output: impl Write) -> Result<()> {
    let copied = std::io::copy(&mut input.take(size), &mut output)?;
    ensure!(copied == size, "Truncated export content");
    padding(input, size)
}

pub(super) fn verify(request: &Request, input: &mut impl Read) -> Result<u64> {
    let manifest = serde_json::to_vec(request)?;
    ensure!(
        block(input)? == *header(MANIFEST, false, manifest.len() as u64)?.as_bytes(),
        "Invalid export correlation header"
    );
    let mut actual = Vec::new();
    content(input, manifest.len() as u64, &mut actual)?;
    ensure!(actual == manifest, "Export request mismatch");
    let limits = [
        &request.profile.control,
        &request.profile.artifacts,
        &request.profile.incoming,
    ];
    let mut budgets = limits.map(Budget::new);
    let mut current: Option<usize> = None;
    let mut previous: Vec<String> = Vec::new();
    let mut directories: Vec<Vec<String>> = Vec::new();
    let mut sealed_marker = false;
    loop {
        let bytes = block(input)?;
        if bytes == [0; 512] {
            ensure!(
                current == Some(2) && sealed_marker,
                "Missing export scopes or seal"
            );
            ensure!(block(input)? == [0; 512], "Incomplete export end marker");
            let mut trailing = [0];
            ensure!(input.read(&mut trailing)? == 0, "Trailing export data");
            return Ok(budgets.iter().map(|b| b.entries).sum());
        }
        let stored = tar::Header::from_byte_slice(&bytes);
        let name_bytes = stored.path_bytes();
        let name =
            std::str::from_utf8(&name_bytes).map_err(|_| invalid("Non-UTF-8 export path"))?;
        let parts = path(name)?
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let kind = stored.entry_type();
        ensure!(
            kind == tar::EntryType::Regular || kind == tar::EntryType::Directory,
            "Unsupported export entry type"
        );
        let directory = kind == tar::EntryType::Directory;
        let size = stored.size()?;
        ensure!(
            bytes == *header(name, directory, size)?.as_bytes(),
            "Noncanonical export header"
        );
        if parts.len() == 1 {
            let next = current.map_or(0, |i| i + 1);
            ensure!(
                next < 3 && name == AREAS[next] && directory,
                "Export scope order mismatch"
            );
            current = Some(next);
            previous.clear();
            directories.clear();
        }
        let index = current.ok_or_else(|| invalid("Export entry precedes its root"))?;
        ensure!(
            parts[0] == AREAS[index] && parts > previous,
            "Duplicate or unordered export path"
        );
        let parent = &parts[..parts.len() - 1];
        while directories.last().is_some_and(|d| d.as_slice() != parent) {
            directories.pop();
        }
        ensure!(
            parts.len() == 1 || directories.last().is_some_and(|d| d.as_slice() == parent),
            "Missing directory parent or file used as directory"
        );
        ensure!(
            name != "control/.lifecycle/open",
            "Exported broker is accepting mutations"
        );
        if name == "control/.lifecycle" {
            ensure!(directory, "Invalid sealed lifecycle directory");
            sealed_marker = true;
        }
        budgets[index].entry()?;
        budgets[index].content(size)?;
        content(input, size, std::io::sink())?;
        if directory {
            directories.push(parts.clone());
        }
        previous = parts;
    }
}
