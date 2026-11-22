use super::{invalid, Disposition, Driver};
use crate::{
    apply::broker,
    error::{ensure, Result},
    openshell::Backend,
    process,
    state::{self, text, StateLock},
    storage,
};
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};

pub(super) struct Native;
struct Scope {
    backend: Backend,
    directory: PathBuf,
    evidence: Option<Value>,
}
fn scope(lock: &StateLock, op: &Value) -> Result<Scope> {
    lock.verify_directory()?;
    let context = &op["desired_inputs"]["context"];
    let backend = Backend::new(context)?;
    let directory = lock
        .directory
        .join(format!("storage-{}", text(op, "owner")?));
    let original = state::read(&directory.join("backend.json"))?;
    let recorded = op["build"].get("storage");
    let evidence = match original {
        Some(identity) => {
            ensure!(
                identity["context"] == *context && identity["owner"] == op["owner"],
                "Original provisioning backend changed"
            );
            let evidence = json!({"format":1,"backend":identity,"directory":directory});
            if let Some(recorded) = recorded {
                ensure!(
                    recorded["backend"] == identity
                        && recorded["directory"] == directory.to_string_lossy().as_ref(),
                    "Retained build storage differs from original journal"
                );
            }
            broker::bound(&backend, &evidence)?;
            Some(evidence)
        }
        None => {
            ensure!(
                recorded.is_none()
                    && state::read(&directory.join("binding.json"))?.is_none()
                    && state::read(&directory.join("volumes/storage.json"))?.is_none(),
                "Provisioning backend evidence missing"
            );
            None
        }
    };
    Ok(Scope {
        backend,
        directory,
        evidence,
    })
}
fn owner(op: &Value, observed: &Value) -> Result<()> {
    ensure!(
        observed["labels"]["ladyshell.owner"] == op["owner"],
        "Pending sandbox belongs to another operation"
    );
    text(observed, "id")?;
    Ok(())
}
fn absent(scope: &Scope, op: &Value) -> Result<()> {
    ensure!(
        scope
            .backend
            .sandbox_identity(text(op, "sandbox_name")?)?
            .is_none(),
        "Pending sandbox deletion is not confirmed"
    );
    if let Some(evidence) = &scope.evidence {
        let docker = broker::bound(&scope.backend, evidence)?;
        let mut command = docker.command()?;
        command.args([
            "ps",
            "--all",
            "--filter",
            &format!(
                "label=openshell.ai/sandbox-name={}",
                text(op, "sandbox_name")?
            ),
            "--filter",
            &format!(
                "label=openshell.ai/sandbox-workspace={}",
                scope.backend.workspace
            ),
            "--filter",
            "label=openshell.ai/isolation-role=sandbox",
            "--format",
            "{{.ID}}",
        ]);
        ensure!(
            process::capture(command, Duration::from_secs(30), 4096)?
                .iter()
                .all(u8::is_ascii_whitespace),
            "Original pending runtime remains after API deletion"
        );
    }
    Ok(())
}
impl Driver for Native {
    fn prepare(&mut self, lock: &StateLock, op: &Value) -> Result<Disposition> {
        let scope = scope(lock, op)?;
        if let Some(current) = op.get("result").filter(|v| !v.is_null()) {
            broker::verify_state_for_cleanup(&scope.backend, current)?;
            return Ok(Disposition::Bound {
                current: current.clone(),
            });
        }
        if let Some(binding) = state::read(&scope.directory.join("binding.json"))? {
            let build = &op["build"];
            ensure!(
                build["storage"].is_object(),
                "Bound provisioning storage evidence missing"
            );
            // Initialization can finish only on the original incarnation. This
            // does not publish an environment or admit any task execution.
            if state::read(&scope.directory.join("protocol.json"))?.is_none() {
                broker::validate_for_cleanup(&scope.backend, text(op, "sandbox_name")?, build)?;
            }
            let mut current = build.clone();
            let fields = current
                .as_object_mut()
                .ok_or_else(|| invalid("Original broker build missing"))?;
            fields.extend(
                binding["current"]
                    .as_object()
                    .ok_or_else(|| invalid("Original runtime binding missing"))?
                    .clone(),
            );
            fields.insert("desired_inputs".into(), op["desired_inputs"].clone());
            fields.insert("schema_version".into(), json!(2));
            ensure!(
                current["owner"] == op["owner"] && current["sandbox_name"] == op["sandbox_name"],
                "Bound generation belongs to another operation"
            );
            broker::verify_state_for_cleanup(&scope.backend, &current)?;
            return Ok(Disposition::Bound { current });
        }
        ensure!(op["phase"] != "validating"
            && state::read(&scope.directory.join("protocol.json"))?.is_none()
            && state::read(&scope.directory.join("mounts.json"))?.is_none(),
            "Runtime binding missing after validation intent; preserve the generation and resume original provisioning");
        let sandbox = scope.backend.sandbox_identity(text(op, "sandbox_name")?)?;
        if let Some(observed) = &sandbox {
            ensure!(
                op["build"]["storage"].is_object() && scope.evidence.is_some(),
                "Sandbox exists without its original storage creation intent"
            );
            owner(op, observed)?;
        } else {
            absent(&scope, op)?;
        }
        Ok(Disposition::Unpublished { sandbox })
    }
    fn remove_unpublished(
        &mut self,
        lock: &StateLock,
        op: &Value,
        original: Option<&Value>,
    ) -> Result<()> {
        let scope = scope(lock, op)?;
        ensure!(
            state::read(&scope.directory.join("binding.json"))?.is_none()
                && state::read(&scope.directory.join("protocol.json"))?.is_none()
                && state::read(&scope.directory.join("mounts.json"))?.is_none()
                && op["phase"] != "validating"
                && op["result"].is_null(),
            "Unpublished cleanup cannot discard a bound generation"
        );
        let observed = scope.backend.sandbox_identity(text(op, "sandbox_name")?)?;
        let result = if let Some(observed) = observed {
            owner(op, &observed)?;
            ensure!(
                original.is_some_and(|s| s["id"] == observed["id"]
                    && s["labels"]["ladyshell.owner"] == observed["labels"]["ladyshell.owner"]),
                "Pending sandbox identity changed since cancellation intent"
            );
            lock.verify_directory()?;
            scope
                .backend
                .call(&["sandbox", "delete", text(op, "sandbox_name")?])
                .map(|_| ())
        } else {
            Ok(())
        };
        absent(&scope, op)?;
        result
    }
    fn remove_storage(&mut self, lock: &StateLock, op: &Value) -> Result<()> {
        let scope = scope(lock, op)?;
        absent(&scope, op)?;
        let directory = scope.directory.join("volumes");
        if state::read(&directory.join("storage.json"))?.is_some() {
            let evidence = scope
                .evidence
                .as_ref()
                .ok_or_else(|| invalid("Original storage backend missing"))?;
            let profile: storage::Profile = serde_json::from_value(
                op["desired_inputs"]["evaluated"]["config"]["storage"].clone(),
            )?;
            storage::remove_planned(
                &directory,
                &profile,
                text(op, "owner")?,
                &scope.backend.workspace,
                &mut broker::bound(&scope.backend, evidence)?,
            )?;
        }
        Ok(())
    }
    fn destroy_bound(&mut self, lock: &StateLock, current: &Value) -> Result<Value> {
        super::super::broker::run(
            lock,
            current,
            &mut super::super::broker::Native::new(current)?,
        )
    }
}
