use super::{invalid, Driver, Intent, Receipt};
use crate::{
    error::{ensure, Error, Result},
    process::capture,
};
use serde_json::Value;
use std::{process::Command, time::Duration};

/// Host Docker endpoint selected by the operator. Qualify that it is the same
/// daemon used by the selected OpenShell deployment before attaching volumes.
/// This driver is never available to a guest or selected through task input.
pub struct Docker;

fn call(command: Command) -> Result<Vec<u8>> {
    capture(command, Duration::from_secs(30), 1024 * 1024)
}
impl Driver for Docker {
    fn observe(&mut self, name: &str) -> Result<Option<Value>> {
        crate::config::identifier(name)?;
        let mut command = Command::new("docker");
        command.args(["volume", "inspect", name]);
        let bytes = match call(command) {
            Err(Error::ProcessExit { stderr, .. })
                if stderr.to_ascii_lowercase().contains("no such volume") =>
            {
                return Ok(None)
            }
            result => result?,
        };
        let values = crate::json::parse(&bytes)?;
        let rows = values
            .as_array()
            .ok_or_else(|| invalid("Invalid volume observation"))?;
        ensure!(
            rows.len() == 1 && rows[0]["Name"] == name,
            "Volume observation identity mismatch"
        );
        Ok(Some(rows[0].clone()))
    }
    fn create(&mut self, intent: &Intent) -> Result<()> {
        intent.validate()?;
        let name = intent.name();
        ensure!(
            self.observe(&name)?.is_none(),
            "Storage volume already exists"
        );
        let mut command = Command::new("docker");
        command.args(["volume", "create", "--driver", "local"]);
        for (kind, values) in [("--label", intent.labels()), ("--opt", intent.options())] {
            for (key, value) in values
                .as_object()
                .ok_or_else(|| invalid("Invalid volume arguments"))?
            {
                let value = value
                    .as_str()
                    .ok_or_else(|| invalid("Invalid volume argument"))?;
                command.arg(kind).arg(format!("{key}={value}"));
            }
        }
        command.arg(&name);
        let reply = String::from_utf8(call(command)?)?;
        ensure!(
            reply.trim() == name,
            "Volume creation acknowledgement mismatch"
        );
        Ok(())
    }
    fn delete(&mut self, original: &Receipt) -> Result<()> {
        let name = original.intent().name();
        let current = self
            .observe(&name)?
            .ok_or_else(|| invalid("Original storage volume is missing"))?;
        original.verify(&current)?;
        let mut attached = Command::new("docker");
        attached.args([
            "ps",
            "--all",
            "--filter",
            &format!("volume={name}"),
            "--format",
            "{{.ID}}",
        ]);
        ensure!(
            call(attached)?.iter().all(u8::is_ascii_whitespace),
            "Refusing to delete attached storage"
        );
        // Revalidate after the attachment query. Docker's non-forced removal also
        // refuses a volume attached between that query and the remove call.
        original.verify(
            &self
                .observe(&name)?
                .ok_or_else(|| invalid("Original storage volume is missing"))?,
        )?;
        let mut command = Command::new("docker");
        command.args(["volume", "rm", &name]);
        call(command)?;
        Ok(())
    }
}
