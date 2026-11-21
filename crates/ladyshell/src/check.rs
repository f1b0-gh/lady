//! Execute only the checks recorded by reconciliation, inside the verified sandbox.
use crate::{
    error::{ensure, Error, Result},
    interactive::terminal_status,
    openshell::{Backend, SANDBOX_ENV},
    state::{self, SessionLock, StateLock},
};
use std::{path::Path, process::Stdio};

pub fn run(directory: &Path) -> Result<i32> {
    let lock = StateLock::acquire(directory)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let _lease = SessionLock::acquire(&lock.directory, false)?;
    let current = state::load(&lock.directory)?.ok_or_else(|| {
        invalid("État absent : appliquer un environnement avant de lancer check".into())
    })?;
    crate::continuous::native::admit(&current)?;
    let config = &current["desired_inputs"]["evaluated"]["config"];
    let checks: Vec<Vec<String>> =
        serde_json::from_value(config["checks"].clone()).map_err(|_| {
            invalid("Checks résolus absents ou invalides : réconcilier avec plan/apply".into())
        })?;
    ensure!(!checks.is_empty(), "Aucun check déclaré pour cette mission");
    // Validate the entire sequence before executing even its first command.
    for command in &checks {
        ensure!(
            !command.is_empty()
                && command
                    .iter()
                    .all(|arg| !arg.is_empty() && !arg.contains('\0')),
            "Liste d’arguments non vides requise pour chaque check"
        );
    }
    let provider = state::text(&config["sandbox"], "provider")?;
    crate::config::identifier(provider)?;
    let backend = Backend::new(&current["context"])?;
    let name = state::text(&current, "sandbox_name")?;
    // A shared session lease prevents apply/destroy while allowing sync to capture.
    drop(lock);
    for args in checks {
        backend.verify_execution(&current)?;
        backend.verify_provider(provider)?;
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
        command
            .args([name, "--"])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = terminal_status(&mut command)?;
        if status != 0 {
            return Ok(status);
        }
    }
    Ok(0)
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
