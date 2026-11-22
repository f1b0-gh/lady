//! Trusted host entry points for verified, at-most-one OpenShell dispatch.
use super::{
    capture,
    fence::{self, Fence},
    invalid, *,
};
use crate::{
    continuous::{
        host::{self, Driver, Observation},
        native::Native,
    },
    error::{ensure, Result},
    files,
    openshell::Backend,
    plan, run,
    state::{self, SessionLock, StateLock},
    sync,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("Host clock precedes the Unix epoch"))?
        .as_secs())
}
fn load(lock: &StateLock) -> Result<Value> {
    lock.verify_directory()?;
    host::execution_directory(&lock.directory)?;
    state::load(&lock.directory)?.ok_or_else(|| invalid("Original environment state is missing"))
}
fn observe(current: &Value, driver: &mut impl Driver, phase: &str) -> Result<Observation> {
    let o = driver.observe(current)?;
    ensure!(
        o.sandbox_id == current["sandbox_id"]
            && o.owner == current["owner"]
            && o.phase == phase
            && crate::continuous::model::token(&o.runtime),
        "Original owned sandbox and required runtime phase could not be verified"
    );
    Ok(o)
}
fn load_inputs(lock: &StateLock) -> Result<Value> {
    let current = load(lock)?;
    ensure!(
        current["snapshot_binary"] == sync::IMAGE_SNAPSHOT_BINARY,
        "Retained inventory requires the image-owned Ladyshell snapshot helper"
    );
    ensure!(
        plan::digest(&current["desired_inputs"])? == current["desired_hash"],
        "Stored desired inputs differ from their identity"
    );
    Ok(current)
}
fn state_pin(
    lock: &StateLock,
    lease: &SessionLock,
    current: &Value,
    runtime: String,
    source_sha256: String,
) -> Result<EnvironmentPin> {
    fence::verify_named(lease.directory_file(), &lock.directory)?;
    let mut continuous = host::export_binding(current)?;
    if let Some(session) = host::session(current)? {
        session.admit(state::text(current, "sandbox_id")?, &runtime)?;
        continuous["incarnation_epoch"] = json!(session.incarnation_epoch);
    }
    let meta = lease.directory_file().metadata()?;
    Ok(EnvironmentPin {
        state: lock.directory.clone(),
        state_dev: meta.dev(),
        state_ino: meta.ino(),
        sandbox_name: state::text(current, "sandbox_name")?.into(),
        sandbox_id: state::text(current, "sandbox_id")?.into(),
        owner: state::text(current, "owner")?.into(),
        policy_hash: state::text(current, "policy_hash")?.into(),
        desired_hash: state::text(current, "desired_hash")?.into(),
        image_id: state::text(current, "image_id")?.into(),
        context: current["context"].clone(),
        runtime,
        continuous,
        source_sha256,
        exclusions: sync::exclusions(current)?,
    })
}
fn live_inputs(
    lock: &StateLock,
    current: &Value,
    driver: &mut impl Driver,
    expected_runtime: Option<&str>,
) -> Result<(String, String)> {
    let original = observe(current, driver, "Ready")?;
    ensure!(
        expected_runtime.is_none_or(|r| r == original.runtime),
        "Runtime generation changed before inventory"
    );
    if let Some(session) = host::session(current)? {
        session.admit(&original.sandbox_id, &original.runtime)?;
    }
    driver.verify(current)?;
    let source = plan::digest(&driver.inventory(current)?)?;
    ensure!(
        observe(current, driver, "Ready")?.runtime == original.runtime,
        "Runtime changed during source observation"
    );
    driver.verify(current)?;
    ensure!(
        load(lock)? == *current,
        "State changed during execution preflight"
    );
    Ok((original.runtime, source))
}

/// Install host-selected task definitions against a freshly observed environment.
pub fn install(state: &Path, receiver: &Path, tasks: Vec<TaskDefinition>) -> Result<Binding> {
    install_with(state, receiver, tasks, &mut Native)
}
fn install_with(
    state: &Path,
    receiver: &Path,
    tasks: Vec<TaskDefinition>,
    driver: &mut impl Driver,
) -> Result<Binding> {
    let lock = StateLock::acquire_existing(state)?;
    let lease = SessionLock::acquire(&lock.directory, true)?;
    let current = load_inputs(&lock)?;
    let path = files::absolute(receiver)?;
    super::model::normalized(&path)?;
    let project = Path::new(state::text(&current["desired_inputs"], "project")?).canonicalize()?;
    ensure!(
        !path.starts_with(project) && !path.starts_with(&lock.directory),
        "Receiver must be outside project and environment state"
    );
    let (runtime, source) = live_inputs(&lock, &current, driver, None)?;
    let environment = state_pin(&lock, &lease, &current, runtime, source)?;
    Store::create(
        &path,
        Catalog {
            schema_version: 1,
            environment,
            tasks,
        },
    )
}

/// Resubmission returns the original evidence without contacting the runtime.
pub fn submit(store: &Store, invocation: &Invocation, admission: &Admission) -> Result<Acceptance> {
    store.accept_with_clock(invocation, admission, now)
}
#[derive(Debug, Serialize)]
pub struct Status {
    pub record: Record,
    pub worker_observed: bool,
}
pub fn status(store: &Store, key: &Key) -> Result<Status> {
    let record = store.inspect(key)?;
    Ok(Status {
        record,
        worker_observed: store.worker_present(key)?,
    })
}
fn check_directory(dir: &File, e: &EnvironmentPin) -> Result<()> {
    let m = dir.metadata()?;
    ensure!(
        m.dev() == e.state_dev && m.ino() == e.state_ino,
        "Original environment directory identity changed"
    );
    fence::verify_named(dir, &e.state)
}
struct Prepared {
    lock: StateLock,
    lease: SessionLock,
    command: Command,
    input: Option<Vec<u8>>,
}
fn preflight(store: &Store, driver: &mut impl Driver, record: &Record) -> Result<Prepared> {
    let (lock, lease, current) = preflight_environment(&record.environment, driver)?;
    let task = store.definition(&record.invocation.task)?;
    let cmd = run::sandbox_command(
        &Backend::new(&current["context"])?,
        &current,
        &task.argv,
        task.timeout_seconds,
    )?;
    Ok(Prepared {
        lock,
        lease,
        command: cmd,
        input: task.stdin_bytes(&record.invocation.intent)?,
    })
}
fn preflight_environment(
    env: &EnvironmentPin,
    driver: &mut impl Driver,
) -> Result<(StateLock, SessionLock, Value)> {
    let lock = StateLock::acquire_existing(&env.state)?;
    let lease = SessionLock::acquire(&lock.directory, true)?;
    check_directory(lease.directory_file(), env)?;
    let current = load_inputs(&lock)?;
    ensure!(
        &state_pin(
            &lock,
            &lease,
            &current,
            env.runtime.clone(),
            env.source_sha256.clone()
        )? == env,
        "Retained environment state differs from installation"
    );
    let (_, source) = live_inputs(&lock, &current, driver, Some(&env.runtime))?;
    ensure!(
        source == env.source_sha256,
        "Retained working tree differs from installation"
    );
    Ok((lock, lease, current))
}

/// Correlated incoming storage receipt. This neither installs a component nor
/// authorizes execution, proves termination, or retires a task/Promise scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadedComponent {
    pub component: String,
    pub bytes: u64,
}

/// Transfer an independently admitted component to the original fixed broker.
/// Supply the independently retained installation pin, never a guest assertion.
/// The host must retain its exact operation before invoking this blocking I/O
/// primitive outside LO guards, for example in an already initiated lifecycle
/// process. Errors remain unresolved: do not automatically repeat an upload.
/// The broker preserves an existing partial or complete file without replacement.
pub fn upload(
    environment: &EnvironmentPin,
    component: &str,
    bytes: &[u8],
    timeout_seconds: u32,
) -> Result<UploadedComponent> {
    upload_with(
        environment,
        component,
        bytes,
        timeout_seconds,
        &mut Native,
        capture::run_with_input,
    )
}
fn upload_with(
    environment: &EnvironmentPin,
    component: &str,
    bytes: &[u8],
    timeout_seconds: u32,
    driver: &mut impl Driver,
    transfer: impl FnOnce(Command, Duration, usize, Option<&[u8]>) -> (ClientResult, CapturedOutputs),
) -> Result<UploadedComponent> {
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 2 * 1024 * 1024
            && files::hash(bytes) == component
            && (1..=86400).contains(&timeout_seconds),
        "Invalid bounded component upload"
    );
    let (lock, _lease, current) = preflight_environment(environment, driver)?;
    ensure!(
        current["image_profile"] == "openshell-wasi",
        "Component upload requires the fixed broker profile"
    );
    let command = run::sandbox_command(
        &Backend::new(&current["context"])?,
        &current,
        &[
            "/usr/local/bin/lo-executor-worker",
            "broker-upload",
            "/var/lib/ladyshell/broker/control",
            "/var/lib/ladyshell/broker/artifacts",
            "/var/lib/ladyshell/broker/incoming",
            component,
        ],
        timeout_seconds,
    )?;
    // Keep the original session lease through transport. Seal in the broker
    // separately fences its actual writes, including after host/client death.
    drop(lock);
    let (result, output) = transfer(
        command,
        Duration::from_secs(u64::from(timeout_seconds)),
        16384,
        Some(bytes),
    );
    ensure!(
        result == (ClientResult::Exit { code: 0 })
            && !output.stdout.truncated
            && !output.stderr.truncated
            && output.stdout.bytes.len() <= 16384
            && output.stderr.bytes.len() <= 16384,
        "Component upload transport is unresolved; preserve original intake"
    );
    let reply: std::result::Result<UploadedComponent, String> =
        serde_json::from_value(crate::json::parse(&output.stdout.bytes)?)?;
    let receipt =
        reply.map_err(|_| invalid("Component upload not confirmed; inspect original intake"))?;
    ensure!(
        receipt.component == component && receipt.bytes == bytes.len() as u64,
        "Component upload reply differs from original bytes"
    );
    Ok(receipt)
}
/// Run only an already accepted invocation under its independent worker lease.
pub fn worker(store: &Store, key: &Key) -> Result<Record> {
    worker_with(store, key, &mut Native, now, capture::run_with_input)
}
fn worker_with(
    store: &Store,
    key: &Key,
    driver: &mut impl Driver,
    mut clock: impl FnMut() -> Result<u64>,
    launch: impl FnOnce(Command, Duration, usize, Option<&[u8]>) -> (ClientResult, CapturedOutputs),
) -> Result<Record> {
    let worker = store.acquire_worker(key)?;
    let record = store.inspect(key)?;
    let fence = Fence::for_record(store, &record);
    let Prepared {
        lock,
        lease,
        command,
        input,
    } = match preflight(store, driver, &record) {
        Ok(prepared) => prepared,
        // Native errors can contain transport diagnostics. Keep a bounded, nonsecret refusal.
        Err(_) => {
            // A previous supervisor may have died after publishing this exact
            // fence but before publishing Dispatching. Never turn that into a
            // refusal or attempt a second dispatch.
            if files::open_directory(&record.environment.state)
                .and_then(|dir| {
                    check_directory(&dir, &record.environment)?;
                    fence.matches_or_absent(&dir)
                })
                .is_ok_and(|same| same)
            {
                return store.uncertain_before_spawn(
                    &worker,
                    Phase::Accepted,
                    "Interrupted retained fence installation",
                    clock()?,
                );
            }
            return store.refuse(&worker, "Native execution preflight failed", clock()?);
        }
    };
    let mut fence_started = false;
    // Owner and claim are verified under the journal lock before this callback.
    // Persist the state exclusion first so every durable dispatch has a fence.
    let dispatch = store.begin_with_clock(&worker, || {
        ensure!(
            clock()? < record.admission.admit_before,
            "Retained dispatch admission expired"
        );
        lock.verify_directory()?;
        check_directory(lease.directory_file(), &record.environment)?;
        fence_started = true;
        fence.install(&lease)?;
        clock()
    });
    let dispatch = match dispatch {
        Ok(r) => r,
        Err(_) if !fence_started => {
            return store.refuse(
                &worker,
                "Retained dispatch authority or deadline failed verification",
                clock()?,
            )
        }
        Err(e) => {
            // Failure of the journal itself may prevent publication. Explicit
            // recovery then examines its durable prefix after this lease drops.
            let phase = store.inspect(key)?.phase;
            return store
                .uncertain_before_spawn(
                    &worker,
                    phase,
                    "Dispatch interrupted during fence or journal persistence",
                    clock()?,
                )
                .map_err(|err| err.context(e.to_string()));
        }
    };
    drop(lock);
    let timeout = Duration::from_secs(u64::from(record.definition.timeout_seconds));
    let limit = record.definition.output_limit_bytes as usize;
    check_directory(lease.directory_file(), &record.environment)?;
    ensure!(
        fence.matches_or_absent(lease.directory_file())?,
        "Durable dispatch fence is missing"
    );
    let last = clock()?;
    ensure!(
        last >= dispatch
            .dispatched_at
            .ok_or_else(|| invalid("Missing dispatch timestamp"))?,
        "Host clock regressed after durable dispatch"
    );
    if last >= dispatch.admission.admit_before {
        return store.uncertain_before_spawn(
            &worker,
            Phase::Dispatching,
            "Admission deadline expired after durable dispatch",
            last,
        );
    }
    let (result, outputs) = launch(command, timeout, limit, input.as_deref());
    let receipt = store.complete(&worker, result, outputs, clock()?)?;
    if receipt.phase == Phase::Completed {
        fence.clear(&lease, &record.environment.state)?;
    }
    Ok(receipt)
}
/// Explicitly consume orphaned work. A verified completed receipt repairs a lost fence clear.
pub fn recover(store: &Store, key: &Key) -> Result<Record> {
    let record = store.inspect(key)?;
    match record.phase {
        Phase::Accepted | Phase::Dispatching => store.recover(key, now()?),
        Phase::Completed => {
            let lock = StateLock::acquire_existing(&record.environment.state)?;
            let fence = Fence::for_record(store, &record);
            let (lease, present) = SessionLock::for_reconciliation(&lock, &fence)?;
            check_directory(lease.directory_file(), &record.environment)?;
            let verified = store.inspect(key)?; // validates both original stream hashes
            if present {
                fence.clear(&lease, &record.environment.state)?;
            }
            Ok(verified)
        }
        _ => Ok(record),
    }
}
/// Record independent evidence of an operator-stopped original incarnation before releasing it.
pub fn reconcile(store: &Store, key: &Key, reason: &str) -> Result<Record> {
    reconcile_with(store, key, reason, &mut Native)
}
fn reconcile_with(
    store: &Store,
    key: &Key,
    reason: &str,
    driver: &mut impl Driver,
) -> Result<Record> {
    super::model::text(reason, 1024)?;
    let record = store.inspect(key)?;
    ensure!(
        record.phase == Phase::Uncertain,
        "Reconciliation requires a terminal uncertain invocation"
    );
    let env = &record.environment;
    let lock = StateLock::acquire_existing(&env.state)?;
    let fence = Fence::for_record(store, &record);
    let (lease, present) = SessionLock::for_reconciliation(&lock, &fence)?;
    check_directory(lease.directory_file(), env)?;
    let mut record = store.inspect(key)?;
    let current = load(&lock)?;
    let env = &record.environment;
    ensure!(
        current["sandbox_name"] == env.sandbox_name
            && current["sandbox_id"] == env.sandbox_id
            && current["owner"] == env.owner
            && current["image_id"] == env.image_id
            && current["context"] == env.context,
        "Stopped observation requires the original sandbox, owner, image and context"
    );
    let o = observe(&current, driver, "Stopped")?;
    ensure!(
        o.runtime == env.runtime,
        "Observed stopped runtime differs from original generation"
    );
    check_directory(lease.directory_file(), env)?;
    ensure!(
        load(&lock)? == current,
        "State changed during stopped observation"
    );
    // SAFETY: geteuid takes no arguments and returns this process's effective operator UID.
    let uid = unsafe { libc::geteuid() };
    let evidence = json!({"profile":"openshell-local-docker-v1","observation":o,"operator_uid":uid,
        "sandbox_name":env.sandbox_name,"image_id":env.image_id,"context":env.context});
    let recorded = record
        .reconciliations
        .iter()
        .any(|note| note.evidence == evidence);
    ensure!(
        present || record.dispatched_at.is_none() || recorded,
        "Dispatched invocation is missing its state fence"
    );
    if !recorded {
        record = store.record_reconciliation(key, reason, &evidence, now()?)?;
    }
    if present {
        fence.clear(&lease, &record.environment.state)?;
    }
    Ok(record)
}
#[cfg(test)]
mod tests;
