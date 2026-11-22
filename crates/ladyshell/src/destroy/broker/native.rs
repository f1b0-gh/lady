use super::{invalid, Driver};
use crate::{
    apply::broker,
    error::{ensure, Result},
    openshell::Backend,
    process,
    state::{self, text},
    storage::{self, export},
};
use serde_json::{json, Value};
use std::{fs::File, path::Path, process::Command, time::Duration};

pub(in crate::destroy) struct Native {
    backend: Backend,
}
impl Native {
    pub(in crate::destroy) fn new(current: &Value) -> Result<Self> {
        Ok(Self {
            backend: Backend::new(&current["context"])?,
        })
    }
    fn command(&self, current: &Value, args: &[&str]) -> Result<Command> {
        let mut command = self.backend.command();
        command
            .args([
                "sandbox",
                "exec",
                "--no-tty",
                "--no-login-shell",
                text(current, "sandbox_name")?,
                "--",
            ])
            .args(args);
        Ok(command)
    }
}
impl Driver for Native {
    fn verify(&mut self, current: &Value) -> Result<()> {
        broker::verify_state_for_cleanup(&self.backend, current)
    }
    fn present(&mut self, current: &Value) -> Result<bool> {
        let docker = broker::bound(&self.backend, &current["storage"])?;
        if let Some(observed) = self.backend.sandbox(text(current, "sandbox_name")?)? {
            ensure!(
                observed["id"] == current["sandbox_id"]
                    && observed["labels"]["ladyshell.owner"] == current["owner"],
                "Broker identity/ownership mismatch: deletion refused"
            );
            return Ok(true);
        }
        // API absence alone does not authorize removing possibly attached storage.
        let mut command = docker.command()?;
        command.args([
            "ps",
            "--all",
            "--filter",
            &format!(
                "label=openshell.ai/sandbox-id={}",
                text(current, "sandbox_id")?
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
            "Original broker runtime remains after sandbox disappearance"
        );
        Ok(false)
    }
    fn seal(&mut self, current: &Value, token: &str) -> Result<()> {
        let input =
            serde_json::to_vec(&json!({"format":1,"operation":{"kind":"seal","token":token}}))?;
        let reply = process::capture_input(
            self.command(current, &broker::BROKER_ARGS)?,
            &input,
            Duration::from_secs(30),
            16384,
        )?;
        ensure!(
            crate::json::parse(&reply)? == json!({"Ok":{"token":token,"accepting":false}}),
            "Broker seal refused or correlation changed"
        );
        Ok(())
    }
    fn export(
        &mut self,
        current: &Value,
        request: &export::Request,
        output: &mut File,
    ) -> Result<()> {
        process::capture_to_file(
            self.command(current, &["/usr/local/bin/ladyshell", "broker-export"])?,
            &serde_json::to_vec(request)?,
            output,
            request.max_bytes()?,
            Duration::from_secs(120),
        )?;
        Ok(())
    }
    fn delete(&mut self, current: &Value) -> Result<()> {
        self.verify(current)?;
        self.backend
            .call(&["sandbox", "delete", text(current, "sandbox_name")?])?;
        Ok(())
    }
    fn remove_storage(&mut self, current: &Value) -> Result<()> {
        let evidence = &current["storage"];
        let mut docker = broker::bound(&self.backend, evidence)?;
        let directory = Path::new(text(evidence, "directory")?);
        let lock = state::StateLock::acquire_existing(directory)?;
        let original = state::read(&directory.join("backend.json"))?;
        ensure!(
            original.as_ref() == Some(&evidence["backend"]),
            "Original storage backend journal changed"
        );
        let receipts = broker::receipts(evidence)?;
        lock.verify_directory()?;
        storage::remove_original(&directory.join("volumes"), &receipts, &mut docker)
    }
}
