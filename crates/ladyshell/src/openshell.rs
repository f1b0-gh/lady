use crate::{
    config::identifier,
    error::{ensure, Error, Result},
    policy,
    process::capture,
    state::text,
};
use serde_json::{json, Value};
use std::{process::Command, time::Duration};
pub(crate) const SANDBOX_ENV: [&str; 6] = [
    "HOME=/sandbox",
    "CARGO_HOME=/sandbox/workspace/cache/cargo",
    "XDG_CACHE_HOME=/sandbox/workspace/cache",
    "ZIG_GLOBAL_CACHE_DIR=/sandbox/workspace/cache/zig",
    // OpenShell exec does not inherit OCI Env. The trusted image supplies these
    // read-only links to the exact libraries selected by the mission.
    "PKG_CONFIG_PATH=/usr/local/lib/ladyshell/pkgconfig",
    "LD_LIBRARY_PATH=/usr/local/lib/ladyshell",
];
#[derive(Debug, Clone)]
pub struct Backend {
    pub gateway: String,
    pub workspace: String,
}
impl Backend {
    pub fn new(context: &Value) -> Result<Self> {
        let gateway = text(context, "gateway")?.to_owned();
        let workspace = text(context, "workspace")?.to_owned();
        identifier(&gateway)?;
        identifier(&workspace)?;
        Ok(Self { gateway, workspace })
    }
    pub fn command(&self) -> Command {
        let mut command = Command::new("openshell");
        command.args([
            "--gateway",
            &self.gateway,
            "--workspace",
            &self.workspace,
            "--color",
            "never",
        ]);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("OPENSHELL_") {
                command.env_remove(key);
            }
        }
        command
    }
    pub fn call(&self, args: &[&str]) -> Result<Vec<u8>> {
        let mut command = self.command();
        command.args(args);
        capture(command, Duration::from_secs(120), 8 * 1024 * 1024)
    }
    fn sandbox_document(&self, name: &str) -> Result<Option<Value>> {
        identifier(name)?;
        let bytes = match self.call(&["sandbox", "get", name, "--output", "json"]) {
            Err(Error::ProcessExit { stderr, .. })
                if stderr.to_ascii_lowercase().contains("sandbox not found") =>
            {
                return Ok(None)
            }
            other => other?,
        };
        Ok(Some(crate::json::parse(&bytes)?))
    }
    pub fn sandbox(&self, name: &str) -> Result<Option<Value>> {
        let Some(value) = self.sandbox_document(name)? else {
            return Ok(None);
        };
        let id = text(&value, "id")?;
        let phase = text(&value, "phase")?;
        let hash = text(&value["configuration_admission"], "policy_hash")?;
        Ok(Some(
            json!({"id":id,"phase":phase,"policy_hash":hash,"labels":value.get("labels").cloned().unwrap_or_else(||json!({}))}),
        ))
    }
    /// Runtime generation changes on stop/start even when the resource ID stays fixed.
    pub fn runtime_identity(&self, name: &str) -> Result<Option<Value>> {
        let Some(value) = self.sandbox_document(name)? else {
            return Ok(None);
        };
        let runtime = text(
            &value["annotations"],
            "internal.openshell.ai/runtime-generation",
        )?;
        Ok(Some(
            json!({"id":text(&value,"id")?,"phase":text(&value,"phase")?,
            "labels":value["labels"],"runtime_generation":runtime}),
        ))
    }
    /// Observe ownership for journaling and cleanup, even before policy admission.
    /// This identity-only result never authorizes execution; callers must verify
    /// readiness and the complete effective policy independently before exec.
    pub fn sandbox_identity(&self, name: &str) -> Result<Option<Value>> {
        let Some(value) = self.sandbox_document(name)? else {
            return Ok(None);
        };
        let id = text(&value, "id")?;
        let phase = text(&value, "phase")?;
        let labels = value.get("labels").cloned().unwrap_or_else(|| json!({}));
        ensure!(
            labels
                .as_object()
                .is_some_and(|labels| labels.values().all(Value::is_string)),
            "Invalid sandbox identity labels"
        );
        let mut observed = json!({"id":id,"phase":phase,"labels":labels});
        if let Some(conditions) = value.get("conditions") {
            observed["conditions"] = conditions.clone();
        }
        Ok(Some(observed))
    }
    pub fn observe(&self, state: Option<&Value>) -> Result<Value> {
        let Some(state) = state else {
            return Ok(json!({"sandbox":null,"image_exists":false}));
        };
        let mut docker = Command::new("docker");
        docker.args(["image", "ls", "--no-trunc", "--format", "{{.ID}}"]);
        let list = String::from_utf8(capture(docker, Duration::from_secs(30), 1024 * 1024)?)?;
        let image = text(state, "image_id")?;
        Ok(
            json!({"image_exists":list.lines().any(|id|id==image),"sandbox":self.sandbox(text(state,"sandbox_name")?)?}),
        )
    }
    pub fn verify_execution(&self, state: &Value) -> Result<Value> {
        let observed = self
            .sandbox(text(state, "sandbox_name")?)?
            .ok_or_else(|| invalid("Sandbox is missing".into()))?;
        ensure!(
            observed["id"] == state["sandbox_id"] && observed["phase"] == "Ready",
            "Sandbox mismatch or not ready"
        );
        ensure!(
            observed["policy_hash"] == state["policy_hash"],
            "Policy changed: reconciliation required"
        );
        let label = state["owner_label"].as_str().unwrap_or("ladyshell.owner");
        ensure!(
            observed["labels"].get(label) == state.get("owner"),
            "Sandbox ownership mismatch"
        );
        if state["image_profile"] == "openshell-worker-v1" {
            crate::apply::broker::verify_state(self, state)?;
        } else {
            ensure!(
                state.get("image_profile").is_none(),
                "Unknown execution image profile"
            );
            self.validate_policy(text(state, "sandbox_name")?, text(state, "codex_binary")?)?;
        }
        Ok(observed)
    }
    pub fn validate_policy(&self, name: &str, binary: &str) -> Result<Value> {
        let value: Value = serde_json::from_slice(
            &self.call(&["policy", "get", name, "--full", "--output", "json"])?,
        )?;
        policy::validate_effective(&value["policy"], binary)?;
        Ok(value["policy"].clone())
    }
    pub fn verify_provider(&self, name: &str) -> Result<()> {
        identifier(name)?;
        // Never log the provider response: only test availability, with no credential fallback.
        let output = self.call(&["provider", "get", name]).map_err(|_| {
            invalid(format!(
                "Provider {name} is unavailable: verify/refresh this provider on the host"
            ))
        })?;
        let text = String::from_utf8_lossy(&output).to_ascii_lowercase();
        ensure!(
            !text.contains("expired") && !text.contains("revoked"),
            "Provider expired or revoked: refresh on the host"
        );
        Ok(())
    }
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
