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

/// Original local daemon selection retained before resource effects. Every call
/// uses its explicit endpoint and verifies the daemon identity again.
pub struct PinnedDocker(Client);
struct Client {
    identity: Option<Value>,
}
impl Client {
    fn command(&self) -> Result<Command> {
        match &self.identity {
            None => Ok(Command::new("docker")),
            Some(identity) => {
                let mut command = Command::new("docker");
                command.args(["--host", crate::state::text(identity, "endpoint")?]);
                let mut info = Command::new("docker");
                info.args([
                    "--host",
                    crate::state::text(identity, "endpoint")?,
                    "info",
                    "--format",
                    "{{.ID}}",
                ]);
                ensure!(
                    String::from_utf8(call(info)?)?.trim()
                        == crate::state::text(identity, "daemon")?,
                    "Original Docker daemon changed"
                );
                Ok(command)
            }
        }
    }
}
impl PinnedDocker {
    pub fn select() -> Result<Self> {
        let endpoint = match std::env::var("DOCKER_HOST") {
            Ok(value) => value,
            Err(std::env::VarError::NotPresent) => {
                let mut command = Command::new("docker");
                command.args([
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                ]);
                String::from_utf8(call(command)?)?.trim().into()
            }
            Err(_) => return Err(invalid("Invalid Docker endpoint")),
        };
        ensure!(
            endpoint.starts_with("unix:///"),
            "Broker requires a local Docker Unix socket"
        );
        let mut command = Command::new("docker");
        command.args(["--host", &endpoint, "info", "--format", "{{.ID}}"]);
        let daemon = String::from_utf8(call(command)?)?;
        Self::from_identity(&serde_json::json!({"endpoint":endpoint,"daemon":daemon.trim()}))
    }
    pub fn from_identity(identity: &Value) -> Result<Self> {
        ensure!(
            crate::state::text(identity, "endpoint")?.starts_with("unix:///"),
            "Broker requires a local Docker Unix socket"
        );
        crate::state::text(identity, "daemon")?;
        Ok(Self(Client {
            identity: Some(identity.clone()),
        }))
    }
    pub fn identity(&self) -> Result<&Value> {
        self.0
            .identity
            .as_ref()
            .ok_or_else(|| invalid("Missing original Docker identity"))
    }
    pub(crate) fn command(&self) -> Result<Command> {
        self.0.command()
    }
}
impl Driver for Docker {
    fn observe(&mut self, name: &str) -> Result<Option<Value>> {
        Client { identity: None }.observe(name)
    }
    fn create(&mut self, intent: &Intent) -> Result<()> {
        Client { identity: None }.create(intent)
    }
    fn delete(&mut self, original: &Receipt) -> Result<()> {
        Client { identity: None }.delete(original)
    }
}
impl Driver for PinnedDocker {
    fn observe(&mut self, name: &str) -> Result<Option<Value>> {
        self.0.observe(name)
    }
    fn create(&mut self, intent: &Intent) -> Result<()> {
        self.0.create(intent)
    }
    fn delete(&mut self, original: &Receipt) -> Result<()> {
        self.0.delete(original)
    }
}

fn call(command: Command) -> Result<Vec<u8>> {
    capture(command, Duration::from_secs(30), 1024 * 1024)
}
impl Driver for Client {
    fn observe(&mut self, name: &str) -> Result<Option<Value>> {
        crate::config::identifier(name)?;
        let mut command = self.command()?;
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
        let mut command = self.command()?;
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
        let mut attached = self.command()?;
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
        let mut command = self.command()?;
        command.args(["volume", "rm", &name]);
        call(command)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_daemon_requires_a_local_endpoint_and_nonempty_original_identity() {
        for value in [
            serde_json::json!({"endpoint":"tcp://remote:2375","daemon":"a"}),
            serde_json::json!({"endpoint":"unix:///var/run/docker.sock","daemon":""}),
        ] {
            assert!(PinnedDocker::from_identity(&value).is_err());
        }
    }
}
