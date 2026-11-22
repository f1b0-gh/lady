use super::{invalid, Receipt};
use crate::error::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// Fresh measurements from the trusted sandbox probe. Callers must authenticate
/// the runtime and probe separately; deserializing these values proves nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub target: String,
    pub device: u64,
    pub bytes: u64,
    pub available_bytes: u64,
    pub inodes: u64,
    pub available_inodes: u64,
}
impl Filesystem {
    /// A sampled 80% warning for bytes or inodes, not enforcement or a guarantee
    /// that capacity remains available until the next observation.
    pub fn warning(&self) -> bool {
        let high = |total: u64, available: u64| {
            u128::from(total.saturating_sub(available)) * 5 >= u128::from(total) * 4
        };
        high(self.bytes, self.available_bytes) || high(self.inodes, self.available_inodes)
    }
}

/// Correlate fresh trusted Docker Mounts and in-sandbox filesystem measurements
/// with all three original volume receipts. Revalidate the receipts against the
/// same pinned daemon separately. This function cannot authenticate observations
/// or establish native process limits, durability, or task scope closure.
pub fn verify_mounts(
    receipts: &[Receipt],
    mounts: &Value,
    filesystems: &[Filesystem],
) -> Result<()> {
    ensure!(
        receipts.len() == 3 && filesystems.len() == 3,
        "Missing bounded storage scopes"
    );
    let mounts = mounts
        .as_array()
        .ok_or_else(|| invalid("Missing runtime mounts"))?;
    let mut targets = BTreeSet::new();
    let mut devices = BTreeSet::new();
    for receipt in receipts {
        let intent = receipt.intent();
        intent.validate()?;
        ensure!(
            intent.owner == receipts[0].intent.owner
                && intent.workspace == receipts[0].intent.workspace
                && targets.insert(intent.target()),
            "Mixed or duplicate storage identities"
        );
        let matched = mounts
            .iter()
            .filter(|m| m["Destination"] == intent.target())
            .collect::<Vec<_>>();
        ensure!(
            matched.len() == 1
                && matched[0]["Type"] == "volume"
                && matched[0]["Name"] == intent.name()
                && matched[0]["RW"] == true,
            "Original bounded volume is not mounted read-write at its fixed target"
        );
        let nested = format!("{}/", intent.target());
        for mount in mounts {
            let target = mount["Destination"]
                .as_str()
                .ok_or_else(|| invalid("Invalid mount target"))?;
            ensure!(
                !target.starts_with(&nested),
                "Nested mount bypasses bounded storage"
            );
        }
        let matched = filesystems
            .iter()
            .filter(|f| f.target == intent.target())
            .collect::<Vec<_>>();
        ensure!(
            matched.len() == 1,
            "Missing or duplicate filesystem observation"
        );
        let fs = matched[0];
        ensure!(
            fs.bytes == intent.limits.bytes
                && fs.inodes == intent.limits.inodes
                && fs.available_bytes <= fs.bytes
                && fs.available_inodes <= fs.inodes
                && devices.insert(fs.device),
            "Mounted filesystem caps or isolation mismatch"
        );
    }
    Ok(())
}

/// Observe the three fixed broker mounts from inside the qualified sandbox.
/// These measurements carry no authority until correlated with host receipts.
pub fn probe() -> Result<Vec<Filesystem>> {
    for path in ["/tmp", "/sandbox/workspace/project"] {
        no_write(std::path::Path::new(path))?;
    }
    ["control", "artifacts", "incoming"]
        .iter()
        .map(|area| {
            probe_path(std::path::Path::new(&format!(
                "/var/lib/ladyshell/broker/{area}"
            )))
        })
        .collect()
}
fn no_write(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // An anonymous inode leaves no path behind even if a changed policy permits
    // this probe. Only an explicit access denial proves the intended boundary.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_TMPFILE | libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
    {
        Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid("Unbounded broker write scope is accessible")),
    }
}
fn probe_path(path: &std::path::Path) -> Result<Filesystem> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let directory = crate::files::open_directory(path)?;
    let metadata = directory.metadata()?;
    ensure!(
        metadata.uid() == 10001 && metadata.gid() == 10001 && metadata.mode() & 0o7777 == 0o700,
        "Broker storage must be private to UID/GID 10001"
    );
    // SAFETY: the owned descriptor remains open and stat points to writable storage.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        stat.f_type == libc::TMPFS_MAGIC
            && stat.f_bsize > 0
            && stat.f_blocks > 0
            && stat.f_files > 0
            && stat.f_files < u64::MAX,
        "Finite tmpfs broker storage required"
    );
    let block =
        u64::try_from(stat.f_bsize).map_err(|_| invalid("Invalid filesystem block size"))?;
    Ok(Filesystem {
        target: path
            .to_str()
            .ok_or_else(|| invalid("Invalid storage path"))?
            .into(),
        device: metadata.dev(),
        bytes: stat
            .f_blocks
            .checked_mul(block)
            .ok_or_else(|| invalid("Filesystem size overflow"))?,
        available_bytes: stat
            .f_bavail
            .checked_mul(block)
            .ok_or_else(|| invalid("Filesystem size overflow"))?,
        inodes: stat.f_files,
        available_inodes: stat.f_ffree,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn writable_directory_cannot_pass_the_landlock_denial_probe() -> Result<()> {
        let root = tempfile::tempdir()?;
        assert!(no_write(root.path()).is_err());
        Ok(())
    }
    #[test]
    fn probe_rejects_uncapped_host_directories() -> Result<()> {
        let root = tempfile::tempdir()?;
        assert!(
            probe_path(root.path()).is_err(),
            "ordinary host directory cannot certify tmpfs caps"
        );
        Ok(())
    }
}
