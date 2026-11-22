//! Bounded snapshots of sealed broker storage. Receipts carry no deletion authority.
use super::{invalid, Profile};
use crate::error::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
mod archive;
mod snapshot;
use snapshot::snapshot;
#[cfg(test)]
mod tests;

/// Correlate this request with the original host lifecycle journal and runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub format: u8,
    pub token: String,
    pub profile: Profile,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == 1
                && self.token.len() == 64
                && self
                    .token
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Invalid export request"
        );
        self.profile.validate()
    }
    /// Maximum wire bytes including headers and padding. Host disk admission and
    /// transport deadlines must be enforced independently before capture starts.
    pub fn max_bytes(&self) -> Result<u64> {
        self.validate()?;
        Ok(4096
            + [
                &self.profile.control,
                &self.profile.artifacts,
                &self.profile.incoming,
            ]
            .iter()
            .map(|limits| limits.bytes + limits.inodes * 1024)
            .sum::<u64>())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub request: Request,
    pub sha256: String,
    pub bytes: u64,
    pub entries: u64,
}

/// Stream a fixed-root snapshot inside the qualified sandbox. The host must
/// fence uploaders and retained receivers; the broker seal fences broker writers.
/// Failure can leave partial stdout, which must never authorize reclamation.
pub fn worker(request: &Request, output: impl std::io::Write) -> Result<()> {
    request.validate()?;
    let observations = super::probe()?;
    let roots = [
        crate::files::open_directory(std::path::Path::new("/var/lib/ladyshell/broker/control"))?,
        crate::files::open_directory(std::path::Path::new("/var/lib/ladyshell/broker/artifacts"))?,
        crate::files::open_directory(std::path::Path::new("/var/lib/ladyshell/broker/incoming"))?,
    ];
    use std::os::unix::fs::MetadataExt;
    let limits = [
        &request.profile.control,
        &request.profile.artifacts,
        &request.profile.incoming,
    ];
    for ((root, observed), limits) in roots.iter().zip(&observations).zip(limits) {
        ensure!(
            root.metadata()?.dev() == observed.device
                && observed.bytes == limits.bytes
                && observed.inodes == limits.inodes,
            "Export mount or cap mismatch"
        );
    }
    ensure!(
        observations[0].device != observations[1].device
            && observations[0].device != observations[2].device
            && observations[1].device != observations[2].device,
        "Export storage scopes overlap"
    );
    snapshot(request, &roots, output)
}

/// Verify every header, byte, empty directory and the complete end marker.
/// No files are extracted. A valid receipt is correlation, not runtime identity,
/// durability of a host copy, deletion authority or LO task scope closure.
pub fn verify(request: &Request, input: impl Read) -> Result<Receipt> {
    request.validate()?;
    let mut input = Hashed {
        input,
        hash: Sha256::new(),
        bytes: 0,
        limit: request.max_bytes()?,
    };
    let entries = archive::verify(request, &mut input)?;
    Ok(Receipt {
        request: request.clone(),
        sha256: format!("{:x}", input.hash.finalize()),
        bytes: input.bytes,
        entries,
    })
}
/// Capture into a fresh host file, require successful transport, verify the
/// complete archive and synchronize its bytes. The caller authenticates the
/// runtime and command, retains its lifecycle lease, then publishes this file
/// and receipt outside the deletion scope. Partial output remains on failure.
pub fn capture(
    request: &Request,
    command: std::process::Command,
    output: &mut std::fs::File,
    timeout: std::time::Duration,
) -> Result<Receipt> {
    use std::io::Seek;
    let limit = request.max_bytes()?;
    crate::process::capture_to_file(
        command,
        &serde_json::to_vec(request)?,
        output,
        limit,
        timeout,
    )?;
    output.rewind()?;
    let receipt = verify(request, &mut *output)?;
    output.sync_all()?;
    Ok(receipt)
}

struct Hashed<R> {
    input: R,
    hash: Sha256,
    bytes: u64,
    limit: u64,
}
impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = self.input.read(buffer)?;
        self.bytes += n as u64;
        if self.bytes > self.limit {
            return Err(std::io::Error::other("Export exceeds wire budget"));
        }
        self.hash.update(&buffer[..n]);
        Ok(n)
    }
}
