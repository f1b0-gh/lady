use crate::{
    config::identifier,
    error::{ensure, Error, Result},
    policy,
    process::capture,
    state::text,
};
use serde_json::{json, Value};
use std::{process::Command, time::Duration};
pub(crate) const NATIVE_PREPARATION_TIMEOUT: Duration = Duration::from_secs(900);
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
        self.call_with_timeout(args, Duration::from_secs(120))
    }
    pub(crate) fn call_with_timeout(&self, args: &[&str], timeout: Duration) -> Result<Vec<u8>> {
        let mut command = self.command();
        command.args(args);
        capture(command, timeout, 8 * 1024 * 1024)
    }
    pub(crate) fn create_native(
        &self,
        name: &str,
        build: &Value,
        owner: &str,
        provider: Option<&str>,
    ) -> Result<()> {
        capture(
            self.native_creation_command(name, build, owner, provider)?,
            NATIVE_PREPARATION_TIMEOUT,
            8 * 1024 * 1024,
        )?;
        Ok(())
    }
    fn native_creation_command(
        &self,
        name: &str,
        build: &Value,
        owner: &str,
        provider: Option<&str>,
    ) -> Result<Command> {
        let label = format!("ladyshell.owner={owner}");
        let mut args = vec![
            "sandbox",
            "create",
            "--name",
            name,
            "--from",
            text(build, "image_id")?,
            "--policy",
            text(build, "policy_path")?,
            "--no-auto-providers",
            "--label",
            &label,
            "--detach",
        ];
        if let Some(provider) = provider {
            args.extend(["--provider", provider]);
        }
        args.extend(["--", "/bin/sleep", "infinity"]);
        let mut command = self.command();
        command.args(args);
        Ok(command)
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
        sandbox_observation(&value, false).map(Some)
    }
    pub(crate) fn preparing_sandbox(&self, name: &str) -> Result<Option<Value>> {
        self.sandbox_document(name)?
            .as_ref()
            .map(|value| sandbox_observation(value, true))
            .transpose()
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
            if crate::config::sandbox_mode(&state["desired_inputs"]["evaluated"]["config"])?
                == crate::config::SandboxMode::Offline
            {
                ensure!(
                    state["sandbox_mode"] == "offline",
                    "Offline runtime mode mismatch"
                );
                ensure!(
                    state["desired_inputs"]["evaluated"]["config"]["sandbox"]
                        .get("provider")
                        .is_none(),
                    "Offline mode forbids providers"
                );
                self.validate_offline_policy(text(state, "sandbox_name")?)?;
            } else {
                ensure!(
                    state.get("sandbox_mode").is_none(),
                    "Unexpected runtime mode"
                );
                self.validate_policy(text(state, "sandbox_name")?, text(state, "codex_binary")?)?;
            }
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
    pub(crate) fn validate_offline_policy(&self, name: &str) -> Result<Value> {
        let value: Value = serde_json::from_slice(
            &self.call(&["policy", "get", name, "--full", "--output", "json"])?,
        )?;
        policy::validate_offline_effective(&value["policy"])?;
        self.verify_no_providers(name)?;
        Ok(value["policy"].clone())
    }
    pub(crate) fn verify_no_providers(&self, name: &str) -> Result<()> {
        let value: Value = serde_json::from_slice(
            &self.call(&["sandbox", "provider", "list", name, "--output", "json"])?,
        )?;
        validate_no_providers(&value)
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
fn sandbox_observation(value: &Value, preparing: bool) -> Result<Value> {
    let id = text(value, "id")?;
    let phase = text(value, "phase")?;
    let admission = &value["configuration_admission"];
    ensure!(
        admission["state"] != "rejected",
        "Sandbox configuration admission rejected"
    );
    if phase == "Ready" {
        ensure!(
            admission["state"] == "accepted",
            "Sandbox readiness requires accepted configuration admission"
        );
    }
    let hash = if preparing && phase != "Ready" {
        admission["policy_hash"].clone()
    } else {
        Value::String(text(admission, "policy_hash")?.to_owned())
    };
    Ok(
        json!({"id":id,"phase":phase,"policy_hash":hash,"labels":value.get("labels").cloned().unwrap_or_else(||json!({}))}),
    )
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

fn validate_no_providers(value: &Value) -> Result<()> {
    ensure!(
        *value == json!({"providers":[],"next_page_token":""}),
        "Offline sandbox must have no providers and complete provider discovery"
    );
    Ok(())
}

#[cfg(test)]
mod offline_tests {
    use super::*;
    #[test]
    fn readiness_requires_accepted_admission_and_nonempty_policy_hash() -> Result<()> {
        let good = json!({"id":"id","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"}});
        sandbox_observation(&good, true)?;
        for admission in [
            json!(null),
            json!({"state":"pending","policy_hash":"hash"}),
            json!({"state":"rejected","policy_hash":"hash"}),
            json!({"state":"accepted","policy_hash":""}),
        ] {
            let mut bad = good.clone();
            bad["configuration_admission"] = admission;
            assert!(sandbox_observation(&bad, true).is_err());
        }
        let pending =
            json!({"id":"id","phase":"Provisioning","configuration_admission":{"state":"pending"}});
        sandbox_observation(&pending, true)?;
        assert!(sandbox_observation(&pending, false).is_err());
        let rejected = json!({"id":"id","phase":"Provisioning","configuration_admission":{"state":"rejected"}});
        assert!(sandbox_observation(&rejected, true).is_err());
        Ok(())
    }
    #[test]
    fn offline_creation_never_attaches_a_provider() -> Result<()> {
        let backend = Backend::new(&json!({"gateway":"g","workspace":"w"}))?;
        let build = json!({"image_id":"image", "policy_path":"policy"});
        for provider in [None, Some("selected")] {
            let command = backend.native_creation_command("sandbox", &build, "owner", provider)?;
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert!(args.iter().any(|arg| arg == "--no-auto-providers"));
            assert_eq!(
                args.iter().any(|arg| arg == "--provider"),
                provider.is_some()
            );
        }
        assert_eq!(NATIVE_PREPARATION_TIMEOUT, Duration::from_secs(900));
        Ok(())
    }
    #[test]
    fn provider_discovery_must_be_empty_complete_and_well_formed() -> Result<()> {
        validate_no_providers(&json!({"providers":[],"next_page_token":""}))?;
        for bad in [
            json!({}),
            json!({"providers":[],"next_page_token":"next"}),
            json!({"providers":[{"name":"dummy"}],"next_page_token":""}),
            json!({"providers":null,"next_page_token":""}),
        ] {
            assert!(validate_no_providers(&bad).is_err());
        }
        Ok(())
    }
}
