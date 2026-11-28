//! Explicit sandbox experiments with verified completion exports.
use crate::{
    error::{ensure, Error, Result},
    openshell::{Backend, SANDBOX_ENV},
    state::{self, SessionLock, StateLock},
};
use serde_json::Value;
use std::{ffi::OsString, os::unix::ffi::OsStrExt, path::Path, process::Stdio};

#[derive(Debug)]
pub struct Outcome {
    pub exit_code: i32,
    pub sync: Option<Value>,
}

pub(crate) fn ensure_no_pending(directory: &Path) -> Result<()> {
    ensure!(
        !directory.join("checkout-pending.json").try_exists()?,
        "Checkout recovery is pending; run explicit sync before another automatic export"
    );
    Ok(())
}

pub(crate) fn verify_provider(backend: &Backend, current: &Value) -> Result<()> {
    if current["image_profile"] == "openshell-worker-v1" {
        let config: crate::config::ResolvedConfig =
            serde_json::from_value(current["desired_inputs"]["evaluated"]["config"].clone())?;
        return config.validate_broker();
    }
    if crate::config::sandbox_mode(&current["desired_inputs"]["evaluated"]["config"])?
        == crate::config::SandboxMode::Offline
    {
        ensure!(
            current["sandbox_mode"] == "offline",
            "Offline runtime mode mismatch"
        );
        return backend.verify_no_providers(state::text(current, "sandbox_name")?);
    }
    backend.verify_provider(state::text(
        &current["desired_inputs"]["evaluated"]["config"]["sandbox"],
        "provider",
    )?)
}

pub fn execute(
    directory: &Path,
    arguments: &[OsString],
    sync_back: bool,
    timeout: u32,
    publication: Option<&crate::publish::Options>,
) -> Result<Outcome> {
    ensure!(
        arguments.first().is_some_and(|s| !s.is_empty())
            && arguments.iter().all(|s| !s.as_bytes().contains(&0)),
        "A program and NUL-free arguments are required"
    );
    ensure!(
        (1..=86400).contains(&timeout),
        "Timeout must be between 1 and 86400 seconds"
    );
    let lock = StateLock::acquire(directory)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let _lease = SessionLock::acquire(&lock.directory, false)?;
    let current = state::load(&lock.directory)?.ok_or_else(|| Error::InvalidInput {
        message: "State is missing; apply an environment first".into(),
    })?;
    crate::continuous::native::admit(&current)?;
    if sync_back {
        ensure_no_pending(&lock.directory)?;
    }
    let prepared = prepare_publication(&lock.directory, &current, sync_back, publication)?;
    let backend = Backend::new(&current["context"])?;
    backend.verify_execution(&current)?;
    verify_provider(&backend, &current)?;
    let mut command = sandbox_command(&backend, &current, arguments, timeout)?;
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let directory = lock.directory.clone();
    drop(lock);
    let code = crate::interactive::terminal_status(&mut command)?;
    finish(&directory, &current, code, sync_back, prepared.as_ref())
}

/// Build the exact noninteractive OpenShell invocation for a verified state.
pub(crate) fn sandbox_command<S: AsRef<std::ffi::OsStr>>(
    backend: &Backend,
    current: &Value,
    arguments: &[S],
    timeout: u32,
) -> Result<std::process::Command> {
    let mut command = backend.command();
    command.args([
        "sandbox",
        "exec",
        "--no-tty",
        "--no-login-shell",
        "--workdir",
        "/sandbox/workspace/project",
        "--timeout",
        &timeout.to_string(),
    ]);
    for variable in SANDBOX_ENV {
        command.args(["--env", variable]);
    }
    command
        .args([state::text(current, "sandbox_name")?, "--"])
        .args(arguments);
    Ok(command)
}

pub(crate) fn finish(
    directory: &Path,
    current: &Value,
    code: i32,
    sync_back: bool,
    publication: Option<&crate::publish::Prepared>,
) -> Result<Outcome> {
    let sync = if sync_back {
        Some(crate::app::sync_after(directory, current, code == 0, publication)
            .map_err(|e| e.context(format!("Sandbox command exited {code}; automatic sync did not complete. Work remains in the sandbox or retained export")))?)
    } else {
        None
    };
    Ok(Outcome {
        exit_code: code,
        sync,
    })
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

pub(crate) fn prepare_publication(
    directory: &Path,
    current: &Value,
    sync_back: bool,
    options: Option<&crate::publish::Options>,
) -> Result<Option<crate::publish::Prepared>> {
    let Some(options) = options else {
        return Ok(None);
    };
    ensure!(sync_back, "Publication requires automatic sync");
    crate::publication_recovery::ensure_available(directory)?;
    crate::stacks::ensure_current(directory)?;
    let project = Path::new(state::text(&current["desired_inputs"], "project")?);
    Ok(Some(crate::publish::Prepared::new(project, options)?))
}
