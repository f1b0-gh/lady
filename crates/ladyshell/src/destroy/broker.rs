//! Recovery of deletion against original broker runtime and storage identities.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    state::{self, StateLock},
    storage::export,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{fs::File, io::Seek, path::Path};
mod native;
mod retained;
pub(super) use native::Native;
#[cfg(test)]
mod tests;

const JOURNAL: &str = "broker-destroy.json";

/// Trusted host effects; implementations must authenticate the original backend.
/// A positive presence check must reject a same-name replacement. Verification
/// includes original runtime, effective policy, storage receipts and mounted caps.
pub(super) trait Driver {
    fn verify(&mut self, current: &Value) -> Result<()>;
    fn present(&mut self, current: &Value) -> Result<bool>;
    fn seal(&mut self, current: &Value, token: &str) -> Result<()>;
    fn export(
        &mut self,
        current: &Value,
        request: &export::Request,
        output: &mut File,
    ) -> Result<()>;
    fn delete(&mut self, current: &Value) -> Result<()>;
    fn remove_storage(&mut self, current: &Value) -> Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Intent,
    Sealed,
    Captured,
    Exported,
    Deleting,
    SandboxDeleted,
    Complete,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u8,
    original: String,
    request: export::Request,
    phase: Phase,
    receipt: Option<export::Receipt>,
    attempts: u64,
    discarded_staging_bytes: u64,
}
impl Journal {
    fn save(&self, lock: &StateLock) -> Result<()> {
        lock.verify_directory()?;
        atomic_json(&lock.directory.join(JOURNAL), self)
    }
    fn transition(&mut self, lock: &StateLock, phase: Phase) -> Result<()> {
        self.phase = phase;
        self.save(lock)
    }
}
fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}

/// Any retained fence, including a corrupt or dangling entry, blocks managed work.
pub(crate) fn ensure_available(directory: &Path) -> Result<()> {
    for name in [JOURNAL, "broker-cancel.json"] {
        match std::fs::symlink_metadata(directory.join(name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(invalid("Broker deletion or cancellation is pending or complete; preserve this state and resume its lifecycle operation")),
        }
    }
    Ok(())
}

/// Caller holds the original environment StateLock and exclusive SessionLock.
/// Host state and exports survive all sandbox/volume removal operations.
pub(super) fn run(lock: &StateLock, current: &Value, driver: &mut impl Driver) -> Result<Value> {
    ensure!(
        current["image_profile"] == "openshell-worker-v1",
        "Not a fixed broker deployment"
    );
    lock.verify_directory()?;
    let original = crate::plan::digest(current)?;
    let request = export::Request {
        format: 1,
        token: crate::plan::digest(
            &json!({"operation":"destroy-broker","state":lock.directory,"original":original}),
        )?,
        profile: serde_json::from_value(
            current["desired_inputs"]["evaluated"]["config"]["storage"].clone(),
        )?,
    };
    request.validate()?;
    let mut journal = match state::read(&lock.directory.join(JOURNAL))? {
        Some(value) => {
            let journal: Journal = serde_json::from_value(value)?;
            ensure!(
                journal.format == 1 && journal.original == original && journal.request == request,
                "Broker deletion differs from its original state or storage profile"
            );
            let captured = !matches!(journal.phase, Phase::Intent | Phase::Sealed);
            ensure!(
                journal.receipt.is_some() == captured
                    && journal
                        .receipt
                        .as_ref()
                        .is_none_or(|r| r.request == request && journal.attempts > 0),
                "Invalid retained broker export phase"
            );
            journal
        }
        None => {
            driver.verify(current)?;
            let journal = Journal {
                format: 1,
                original,
                request,
                phase: Phase::Intent,
                receipt: None,
                attempts: 0,
                discarded_staging_bytes: 0,
            };
            journal.save(lock)?;
            journal
        }
    };
    // Before a deletion intent, disappearance is loss rather than successful cleanup.
    let present = driver.present(current)?;
    ensure!(
        present
            || matches!(
                journal.phase,
                Phase::Deleting | Phase::SandboxDeleted | Phase::Complete
            ),
        "Broker disappeared without a retained deletion intent; preserve all evidence"
    );
    if present {
        driver.verify(current)?;
    }
    if journal.phase == Phase::Intent {
        driver.seal(current, &journal.request.token)?;
        driver.verify(current)?;
        journal.transition(lock, Phase::Sealed)?;
    }
    let archive = StateLock::acquire(&lock.directory.join("broker-recovery"))?;
    if journal.phase == Phase::Sealed {
        driver.verify(current)?;
        // Repeat the idempotent seal before regenerating an unacknowledged copy.
        driver.seal(current, &journal.request.token)?;
        let mut output = retained::scratch(&archive, journal.request.max_bytes()?)?;
        journal.attempts = journal
            .attempts
            .checked_add(1)
            .ok_or_else(|| invalid("Export attempt overflow"))?;
        journal.discarded_staging_bytes = output.metadata()?.len();
        journal.save(lock)?;
        output.set_len(0)?;
        output.rewind()?;
        driver.export(current, &journal.request, &mut output)?;
        output.rewind()?;
        let receipt = export::verify(&journal.request, &mut output)?;
        output.sync_all()?;
        driver.verify(current)?;
        archive.verify_directory()?;
        journal.receipt = Some(receipt);
        journal.transition(lock, Phase::Captured)?;
    }
    let receipt = journal
        .receipt
        .as_ref()
        .ok_or_else(|| invalid("Broker export receipt missing"))?;
    if journal.phase == Phase::Captured {
        retained::publish(&archive, receipt)?;
        journal.transition(lock, Phase::Exported)?;
    }
    // Revalidate the durable copy on every retry, including after sandbox loss.
    let receipt = journal
        .receipt
        .as_ref()
        .ok_or_else(|| invalid("Broker export receipt missing"))?;
    retained::verify(&archive, "export.tar", receipt)?;
    if journal.phase == Phase::Exported {
        driver.verify(current)?;
        journal.transition(lock, Phase::Deleting)?;
    }
    if journal.phase == Phase::Deleting {
        let result = if driver.present(current)? {
            driver.verify(current)?;
            lock.verify_directory()?;
            driver.delete(current)
        } else {
            Ok(())
        };
        ensure!(
            !driver.present(current)?,
            "Broker deletion is not confirmed; retain original intent"
        );
        journal.transition(lock, Phase::SandboxDeleted)?;
        // A lost reply remains observable even when absence is already recorded.
        result?;
    }
    ensure!(
        !driver.present(current)?,
        "Broker resource reappeared during storage cleanup"
    );
    lock.verify_directory()?;
    driver.remove_storage(current)?;
    journal.transition(lock, Phase::Complete)?;
    Ok(
        json!({"schema_version":1,"sandbox_name":current["sandbox_name"],"sandbox_id":current["sandbox_id"],
        "owner":current["owner"],"context":current["context"],"deleted":true,"discard_work":false,
        "export":{"path":archive.directory.join("export.tar"),"receipt":journal.receipt}}),
    )
}
