//! Operator-requested execution inside a verified OpenShell sandbox.
use super::invalid;
use crate::{
    error::{ensure, Result},
    files,
    openshell::{Backend, SANDBOX_ENV},
    process,
    state::{self, SessionLock, StateLock},
    sync,
};
pub use ladybom::deps::prune_validation::{verify_inventory, ValidationPlan};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize)]
pub struct CheckResult {
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout_sha256: Option<String>,
    pub diagnostic: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ValidationReceipt {
    pub schema_version: u32,
    pub plan_sha256: String,
    pub source_sha256: String,
    pub sandbox_id: String,
    pub policy_hash: String,
    pub desired_hash: String,
    pub passed: bool,
    pub checks: Vec<CheckResult>,
    pub limitations: Vec<String>,
}
/// Operator-requested execution; never called by scan, lock, plan or simulation.
pub fn run(directory: &Path, plan: &ValidationPlan) -> Result<ValidationReceipt> {
    plan.validate()?;
    let lock = StateLock::acquire(directory)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let _lease = SessionLock::acquire(&lock.directory, true)?;
    let current = state::load(&lock.directory)?.ok_or_else(|| {
        invalid("State is missing: prepare an isolated copy and apply its environment".into())
    })?;
    crate::continuous::native::admit(&current)?;
    let config = &current["desired_inputs"]["evaluated"]["config"];
    let checks: Vec<Vec<String>> = serde_json::from_value(config["checks"].clone())?;
    ensure!(
        !checks.is_empty() && checks.len() <= 32,
        "Between 1 and 32 declared checks are required"
    );
    for command in &checks {
        ensure!(
            !command.is_empty()
                && command.len() <= 128
                && command
                    .iter()
                    .all(|a| !a.is_empty() && a.len() <= 8192 && !a.contains('\0')),
            "Invalid declared check"
        );
    }
    let backend = Backend::new(&current["context"])?;
    let name = state::text(&current, "sandbox_name")?;
    let exclusions = sync::exclusions(&current)?;
    ensure!(
        exclusions.iter().collect::<BTreeSet<_>>() == plan.exclusions.iter().collect(),
        "Sandbox exclusions differ from the validation plan"
    );
    let verify = || -> Result<()> {
        backend.verify_execution(&current)?;
        crate::run::verify_provider(&backend, &current)?;
        verify_inventory(plan, &sync::observe_inventory(&current, &backend)?).map_err(Into::into)
    };
    verify()?;
    let mut receipt=ValidationReceipt{schema_version:1,plan_sha256:files::hash(&serde_json::to_vec(plan)?),source_sha256:files::hash(&serde_json::to_vec(&plan.expected)?),sandbox_id:state::text(&current,"sandbox_id")?.into(),policy_hash:state::text(&current,"policy_hash")?.into(),desired_hash:state::text(&current,"desired_hash")?.into(),passed:false,checks:Vec::new(),limitations:vec!["Result is limited to declared commands/configurations; no guarantee for untested targets, features or uses".into(),"Receipt is bound to the observed sources and sandbox; not an independent signature or proof of absence of use".into()]};
    drop(lock);
    let started = Instant::now();
    for args in checks {
        verify()?;
        let remaining = Duration::from_secs(600)
            .checked_sub(started.elapsed())
            .ok_or_else(|| invalid("Overall validation budget exceeded".into()))?;
        let mut command = backend.command();
        command.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/sandbox/workspace/project",
            "--timeout",
            "300",
        ]);
        for variable in SANDBOX_ENV {
            command.args(["--env", variable]);
        }
        command.args([name, "--"]).args(&args);
        let outcome =
            process::capture(command, remaining.min(Duration::from_secs(300)), 512 * 1024);
        // A command may alter tracked sources or sandbox admission even when it exits zero.
        verify()?;
        match outcome {
            Ok(output) => receipt.checks.push(CheckResult {
                command: args,
                exit_code: 0,
                stdout_sha256: Some(files::hash(&output)),
                diagnostic: None,
            }),
            Err(crate::error::Error::ProcessExit { status, stderr, .. }) => {
                use std::os::unix::process::ExitStatusExt;
                receipt.checks.push(CheckResult {
                    command: args,
                    exit_code: status
                        .code()
                        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
                    stdout_sha256: None,
                    diagnostic: Some(stderr.chars().take(8192).collect()),
                });
                return Ok(receipt);
            }
            Err(error) => return Err(error),
        }
    }
    receipt.passed = true;
    Ok(receipt)
}
