//! Explicit deletion of the current owned sandbox; retain exports and host state.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    openshell::Backend,
    request::Destroy,
    state::{self, text},
};
use serde_json::{json, Value};
mod batch;
pub use batch::{all, all_at};

pub fn run(args: &Destroy) -> Result<Value> {
    run_selected(args, None)
}

pub(crate) fn run_expected(
    args: &Destroy,
    expected: &crate::associations::Association,
) -> Result<Value> {
    run_selected(args, Some(expected))
}

fn run_selected(
    args: &Destroy,
    expected: Option<&crate::associations::Association>,
) -> Result<Value> {
    let lock = if expected.is_some() {
        state::StateLock::acquire_existing(&args.state)?
    } else {
        state::StateLock::acquire(&args.state)?
    };
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    lock.verify_directory()?;
    let mut current = state::load(&lock.directory)?.ok_or_else(|| Error::InvalidInput {
        message: "State is missing".into(),
    })?;
    if let Some(expected) = expected {
        expected.verify(&current)?;
    }
    if let Some(operation) = state::read(&lock.directory.join("operation.json"))? {
        ensure!(
            operation["phase"] == "complete",
            "Apply was interrupted: resume before destroy"
        );
    }
    ensure!(
        !lock.directory.join("checkout-pending.json").try_exists()?,
        "Checkout application was interrupted: resume before destroy"
    );
    lock.verify_directory()?;
    let backend = Backend::new(&current["context"])?;
    let name = text(&current, "sandbox_name")?.to_owned();
    let path = lock.directory.join("destroy.json");
    let previous = state::read(&path)?;
    let observed = backend.sandbox(&name)?;
    lock.verify_directory()?;
    if observed.is_none() {
        let receipt = previous.ok_or_else(|| Error::InvalidInput {
            message: "Sandbox is missing without a deletion receipt; state retained".into(),
        })?;
        ensure!(
            receipt["sandbox_id"] == current["sandbox_id"]
                && receipt["context"] == current["context"]
                && receipt["owner"] == current["owner"],
            "Deletion receipt mismatch"
        );
        return complete(receipt, &path);
    }
    // Never delete a replacement which merely has the same name.
    let observed = observed.ok_or_else(|| Error::InvalidInput {
        message: "Sandbox is missing".into(),
    })?;
    let label = current["owner_label"]
        .as_str()
        .unwrap_or("ladyshell.owner")
        .to_owned();
    ensure!(
        observed["id"] == current["sandbox_id"]
            && observed["labels"].get(&label) == current.get("owner"),
        "Sandbox identity/ownership mismatch: deletion refused"
    );
    if !args.discard_work {
        // Fresh export even on retry: work may have changed after a failed delete.
        current = crate::sync::sync(&current, &lock.directory, &backend, true)?;
    }
    lock.verify_directory()?;
    let receipt = json!({"schema_version":1,"sandbox_name":name,
        "sandbox_id":current["sandbox_id"],"context":current["context"],
        "owner":current["owner"],"discard_work":args.discard_work,
        "export":if args.discard_work { Value::Null } else { current["last_sync"].clone() },
        "deleted":false});
    atomic_json(&path, &receipt)?;
    // Recheck identity after export, immediately before the name-based API call.
    let latest = backend.sandbox(&name)?;
    lock.verify_directory()?;
    ensure!(
        latest
            .as_ref()
            .is_some_and(|s| s["id"] == current["sandbox_id"]
                && s["labels"].get(&label) == current.get("owner")),
        "Sandbox changed before deletion"
    );
    backend.call(&["sandbox", "delete", &name])?;
    ensure!(
        backend.sandbox(&name)?.is_none(),
        "Deletion is not yet confirmed; run destroy again, state retained"
    );
    lock.verify_directory()?;
    complete(receipt, &path)
}
fn complete(mut receipt: Value, path: &std::path::Path) -> Result<Value> {
    receipt["deleted"] = json!(true);
    atomic_json(path, &receipt)?;
    Ok(receipt)
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
