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
pub(crate) mod broker;
mod cancel;
pub use batch::{all, all_at};
pub use cancel::{cancel_broker, cancel_broker_pinned, select_cancellation};

pub fn run(args: &Destroy) -> Result<Value> {
    run_selected(args, None, None)
}
/// Delete only the selected original generation under ordinary lifecycle locks.
/// Export progress alone does not change a generation. Policy admission remains
/// the caller's responsibility; this selection grants no authority.
pub fn run_pinned(args: &Destroy, selected: &state::Selection) -> Result<Value> {
    run_selected(args, None, Some(selected))
}

/// Seal, export and delete the original broker while retaining an uncertain
/// invocation's exact execution fence. Independently admit and retain the
/// selected generation, receiver binding and key before calling. The invocation
/// may be Execute, Stage or a storage probe; cleanup never replays it. A busy
/// broker seal fails closed. The original record/fence survive even successful
/// deletion, and grant no task termination or Promise retirement authority.
pub fn run_recovering(
    args: &Destroy,
    selected: &state::Selection,
    store: &crate::execution::Store,
    key: &crate::execution::Key,
) -> Result<Value> {
    with_recovery(args, selected, store, key, |lock, current| {
        let mut driver = broker::Native::new(current)?;
        broker::run(lock, current, &mut driver)
    })
}
pub(crate) fn with_recovery(
    args: &Destroy,
    selected: &state::Selection,
    store: &crate::execution::Store,
    key: &crate::execution::Key,
    cleanup: impl FnOnce(&state::StateLock, &Value) -> Result<Value>,
) -> Result<Value> {
    ensure!(
        !args.discard_work,
        "Fenced broker cleanup must retain its export"
    );
    let held = crate::execution::recovery(store, key)?;
    ensure!(
        crate::files::absolute(&args.state)? == held.lock.directory,
        "Cleanup state differs from original fenced environment"
    );
    selected.verify_generation(&held.lock, &held.current)?;
    ensure_ready_for_destroy(&held.lock)?;
    // No unconditional Ready observation here: after deletion, the retained
    // broker journal must verify the original deletion intent and absence.
    // Before seal/export, that same driver verifies the original live runtime.
    cleanup(&held.lock, &held.current)
}

fn ensure_ready_for_destroy(lock: &state::StateLock) -> Result<()> {
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
    lock.verify_directory()
}

pub(crate) fn run_expected(
    args: &Destroy,
    expected: &crate::associations::Association,
) -> Result<Value> {
    run_selected(args, Some(expected), None)
}

fn run_selected(
    args: &Destroy,
    expected: Option<&crate::associations::Association>,
    selected: Option<&state::Selection>,
) -> Result<Value> {
    let lock = if expected.is_some() || selected.is_some() {
        state::StateLock::acquire_existing(&args.state)?
    } else {
        state::StateLock::acquire(&args.state)?
    };
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::continuous::host::lifecycle_directory(&lock.directory)?;
    lock.verify_directory()?;
    let mut current = state::load(&lock.directory)?.ok_or_else(|| Error::InvalidInput {
        message: "State is missing".into(),
    })?;
    if let Some(expected) = expected {
        expected.verify(&current)?;
    }
    if let Some(selected) = selected {
        selected.verify_generation(&lock, &current)?;
    }
    ensure_ready_for_destroy(&lock)?;
    if current["image_profile"] == "openshell-wasi" {
        ensure!(
            !args.discard_work,
            "The broker lifecycle requires retaining records before deletion"
        );
        let mut driver = broker::Native::new(&current)?;
        return broker::run(&lock, &current, &mut driver);
    }
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
