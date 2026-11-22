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
