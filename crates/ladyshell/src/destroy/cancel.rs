//! Cancellation preserves the distinction between unpublished resources and a bound generation.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    state::{self, StateLock},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
mod native;
#[cfg(test)]
mod tests;
const JOURNAL: &str = "broker-cancel.json";
fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Disposition {
    Bound { current: Value },
    Unpublished { sandbox: Option<Value> },
}
trait Driver {
    fn prepare(&mut self, lock: &StateLock, operation: &Value) -> Result<Disposition>;
    fn remove_unpublished(
        &mut self,
        lock: &StateLock,
        operation: &Value,
        sandbox: Option<&Value>,
    ) -> Result<()>;
    fn remove_storage(&mut self, lock: &StateLock, operation: &Value) -> Result<()>;
    fn destroy_bound(&mut self, lock: &StateLock, current: &Value) -> Result<Value>;
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: u8,
    operation: String,
    disposition: Option<Disposition>,
    complete: bool,
}
impl Journal {
    fn save(&self, lock: &StateLock) -> Result<()> {
        lock.verify_directory()?;
        atomic_json(&lock.directory.join(JOURNAL), self)
    }
}
fn run_with(lock: &StateLock, operation: &Value, driver: &mut impl Driver) -> Result<Value> {
    lock.verify_directory()?;
    let digest = crate::plan::digest(operation)?;
    let mut journal = match state::read(&lock.directory.join(JOURNAL))? {
        Some(value) => {
            let journal: Journal = serde_json::from_value(value)?;
            ensure!(
                journal.format == 1
                    && journal.operation == digest
                    && (!journal.complete || journal.disposition.is_some()),
                "Cancellation differs from original provisioning attempt"
            );
            journal
        }
        None => {
            let journal = Journal {
                format: 1,
                operation: digest,
                disposition: None,
                complete: false,
            };
            journal.save(lock)?;
            journal
        }
    };
    if journal.disposition.is_none() {
        journal.disposition = Some(driver.prepare(lock, operation)?);
        journal.save(lock)?;
    }
    let mut receipt = match journal
        .disposition
        .as_ref()
        .ok_or_else(|| invalid("Cancellation disposition missing"))?
    {
        Disposition::Bound { current } => driver.destroy_bound(lock, current)?,
        Disposition::Unpublished { sandbox } => {
            lock.verify_directory()?;
            driver.remove_unpublished(lock, operation, sandbox.as_ref())?;
            lock.verify_directory()?;
            driver.remove_storage(lock, operation)?;
            json!({"schema_version":1,"sandbox":sandbox,"owner":operation["owner"],"sandbox_name":operation["sandbox_name"],"storage_removed":true,"export":null})
        }
    };
    receipt["cancelled"] = json!(true);
    journal.complete = true;
    journal.save(lock)?;
    Ok(receipt)
}

/// Cancel only the pending broker provisioning attempt, retaining predecessor state,
/// original journals and any required generation export. Caller supplies policy admission.
pub fn cancel_broker(args: &crate::request::Existing) -> Result<Value> {
    cancel_selected(args, None)
}
/// Select the exact incomplete operation without contacting its backend.
pub fn select_cancellation(directory: &std::path::Path) -> Result<state::Selection> {
    let lock = StateLock::acquire_existing(directory)?;
    let operation = crate::apply::interrupted_broker(&lock.directory)?;
    state::Selection::capture(&lock, &operation)
}
/// Cancel only the selected original provisioning record and directory.
pub fn cancel_broker_pinned(
    args: &crate::request::Existing,
    selected: &state::Selection,
) -> Result<Value> {
    cancel_selected(args, Some(selected))
}
fn cancel_selected(
    args: &crate::request::Existing,
    selected: Option<&state::Selection>,
) -> Result<Value> {
    let lock = StateLock::acquire_existing(&args.state)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::continuous::host::lifecycle_directory(&lock.directory)?;
    let operation = crate::apply::interrupted_broker(&lock.directory)?;
    if let Some(selected) = selected {
        selected.verify(&lock, &operation)?;
    }
    run_with(&lock, &operation, &mut native::Native)
}
