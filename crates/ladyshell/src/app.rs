use crate::{
    environment_lock,
    error::{ensure, Error, Result},
    files,
    openshell::Backend,
    plan,
    request::{BrokerDesired, Desired},
    state,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
mod input;
pub fn lock_path(args: &Desired) -> PathBuf {
    input::Sources::from(args).lock_path()
}
pub fn desired(args: &Desired) -> Result<Value> {
    let runtime = std::env::current_exe()?;
    Ok(input::prepare(
        input::Sources::from(args),
        input::Artifacts::Native {
            codex: &args.codex,
            code_mode: &args.codex_code_mode_host,
            runtime: &runtime,
        },
        true,
    )?
    .0)
}
/// Build the exact broker inputs using explicitly selected worker and receiver
/// artifacts. This never selects the embedding application's executable.
pub fn desired_broker(args: &BrokerDesired) -> Result<Value> {
    Ok(input::prepare(
        input::Sources::from(args),
        input::Artifacts::Broker {
            worker: &args.worker,
            runtime: &args.runtime,
        },
        true,
    )?
    .0)
}
/// Explicit lock creation; a missing/mismatching lock never triggers this path
/// from planning or apply. No sandbox or image is created here.
pub fn lock_broker(args: &BrokerDesired) -> Result<environment_lock::EnvironmentLock> {
    let inputs = input::Sources::from(args);
    let path = inputs.lock_path();
    let (_, receipt) = input::prepare(
        inputs,
        input::Artifacts::Broker {
            worker: &args.worker,
            runtime: &args.runtime,
        },
        false,
    )?;
    environment_lock::write(&path, &receipt)?;
    Ok(receipt)
}
pub fn make_broker_plan(args: &BrokerDesired) -> Result<Value> {
    plan_inputs(desired_broker(args)?, &args.state)
}
pub fn make_plan(args: &Desired) -> Result<Value> {
    plan_inputs(desired(args)?, &args.state)
}
fn plan_inputs(desired: Value, directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current = state::load(&lock.directory)?;
    let backend = Backend::new(&desired["context"])?;
    let observed = backend.observe(current.as_ref())?;
    let result = plan::plan(&desired, current.as_ref(), &observed)?;
    environment_lock::atomic_json(&lock.directory.join("plan.json"), &result)?;
    environment_lock::atomic_json(
        &lock.directory.join("dependency-scan.json"),
        &desired["dependency_scan"],
    )?;
    Ok(result)
}
pub fn apply(args: &Desired) -> Result<Value> {
    apply_inputs(desired(args)?, &args.state)
}
/// Apply an explicitly locked fixed-broker plan under the ordinary state and session leases.
pub fn apply_broker(args: &BrokerDesired) -> Result<Value> {
    apply_inputs(desired_broker(args)?, &args.state)
}
fn apply_inputs(desired: Value, directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    if let Some(current) = state::load(&lock.directory)? {
        ensure!(
            crate::continuous::host::session(&current)?.is_none(),
            "Use cs refresh/replace for a continuous sandbox"
        );
    }
    let backend = Backend::new(&desired["context"])?;
    crate::apply::apply_with(
        &desired,
        &lock.directory,
        &mut crate::apply::NativeDriver { backend },
    )
}
pub fn status(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let backend = Backend::new(&current["context"])?;
    Ok(json!({"state":current,"observed":backend.observe(Some(&current))?}))
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

pub fn sync(args: &crate::request::SyncArgs) -> Result<Value> {
    let selected = crate::associations::resolve(args.state.as_deref())?;
    let lock = state::StateLock::acquire(&selected.directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, false)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    if let Some(expected) = selected.expected {
        expected.verify(&current)?;
    }
    crate::continuous::native::admit(&current)?;
    if lock.directory.join("checkout-pending.json").try_exists()? {
        ensure!(
            !args.export,
            "Checkout application interrupted: run sync again or inspect with --dry-run"
        );
        let result = crate::checkout::run(&current, &lock.directory, args.applies())?;
        return Ok(result);
    }
    sync_locked(&current, &lock.directory, args, None)
}

pub(crate) fn sync_after(
    directory: &Path,
    expected: &Value,
    apply: bool,
    publication: Option<&crate::publish::Prepared>,
) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    for field in [
        "sandbox_id",
        "owner",
        "desired_hash",
        "context",
        "policy_hash",
        "continuous",
    ] {
        ensure!(
            current[field] == expected[field],
            "Session state changed: {field}"
        );
    }
    ensure!(
        current["desired_inputs"]["project"] == expected["desired_inputs"]["project"],
        "Session checkout binding changed"
    );
    crate::run::ensure_no_pending(&lock.directory)?;
    sync_locked(
        &current,
        &lock.directory,
        &crate::request::SyncArgs {
            state: Some(lock.directory.clone()),
            dry_run: false,
            apply,
            export: !apply,
            json: false,
        },
        publication,
    )
}

fn sync_locked(
    current: &Value,
    directory: &Path,
    args: &crate::request::SyncArgs,
    publication: Option<&crate::publish::Prepared>,
) -> Result<Value> {
    let backend = Backend::new(&current["context"])?;
    let next = crate::sync::sync(current, directory, &backend, true)?;
    if args.state.is_some() {
        crate::associations::register(directory)?;
    }
    if !args.export {
        if let Some(prepared) = publication {
            prepared.before_apply()?;
            if let Some(checks) = prepared.policy().and_then(|p| p.checks.as_ref()) {
                crate::publication_checks::verify(
                    &next,
                    directory,
                    Path::new(state::text(&next, "last_sync")?),
                    checks,
                )?;
            }
        }
        let mut report = crate::checkout::run(&next, directory, args.applies())?;
        if let Some(prepared) = publication {
            report["publication"] = prepared.publish(&report, directory)?;
        }
        Ok(report)
    } else {
        let export = Path::new(state::text(&next, "last_sync")?);
        let manifest = crate::json::parse(&files::read_limited(
            &export.join("manifest.json"),
            2 * 1024 * 1024,
        )?)?;
        Ok(
            json!({"export":export,"changes":manifest["changes"],"deletions":manifest["deletions"],"applied":false}),
        )
    }
}
