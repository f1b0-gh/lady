pub(crate) mod broker;
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    image,
    openshell::Backend,
    plan,
    state::{self, text},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
pub trait Driver {
    fn preflight(&mut self, desired: &Value) -> Result<()> {
        if let Some(value) = desired["evaluated"]["config"].get("storage") {
            let profile: crate::storage::Profile = serde_json::from_value(value.clone())?;
            profile.validate()?;
            self.preflight_storage(&profile, &desired["context"])?;
        }
        Ok(())
    }
    /// Qualify the selected storage backend before any build or provisioning.
    /// Existing drivers refuse this optional capability until implemented.
    fn preflight_storage(
        &mut self,
        _profile: &crate::storage::Profile,
        _context: &Value,
    ) -> Result<()> {
        Err(invalid("Driver does not support bounded storage".into()))
    }
    /// Reconcile the original per-resource journal, retaining each identity
    /// before proceeding. A missing previously observed volume must be refused.
    fn prepare_storage(
        &mut self,
        _profile: &crate::storage::Profile,
        _directory: &Path,
        _owner: &str,
        _context: &Value,
    ) -> Result<Value> {
        Err(invalid("Driver does not support bounded storage".into()))
    }
    /// Freshly verify the original backend, volumes, mounted limits and runtime.
    /// Recorded creation options alone are insufficient evidence.
    fn verify_storage(&mut self, _name: &str, _evidence: &Value) -> Result<()> {
        Err(invalid("Driver does not verify mounted storage".into()))
    }
    fn observe(&mut self, state: Option<&Value>) -> Result<Value>;
    fn sandbox(&mut self, name: &str) -> Result<Option<Value>>;
    fn build(
        &mut self,
        desired: &Value,
        directory: &Path,
        migration: Option<&Value>,
    ) -> Result<Value>;
    fn capture(&mut self, state: &Value, directory: &Path) -> Result<Value>;
    fn create(&mut self, name: &str, build: &Value, owner: &str, provider: &str) -> Result<()>;
    fn validate(&mut self, name: &str, binary: &str) -> Result<Value>;
    /// Select a supported creation profile without inventing a native provider.
    fn create_profile(
        &mut self,
        name: &str,
        build: &Value,
        owner: &str,
        config: &Value,
    ) -> Result<()> {
        ensure!(
            build["image_profile"] != "openshell-wasi",
            "Driver does not support broker creation"
        );
        self.create(name, build, owner, text(&config["sandbox"], "provider")?)
    }
    /// Validate the exact retained profile on initial publication and recovery.
    fn validate_profile(&mut self, name: &str, build: &Value) -> Result<Value> {
        ensure!(
            build["image_profile"] != "openshell-wasi",
            "Driver does not support broker validation"
        );
        self.validate(name, text(build, "codex_binary")?)
    }
    fn restore(&mut self, state: &Value) -> Result<()>;
    fn published(&mut self, _directory: &Path) -> Result<()> {
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Planned,
    Built,
    Publishing,
    Complete,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    schema_version: u32,
    desired_hash: String,
    state_before: Option<Value>,
    observed_before: Value,
    phase: Phase,
    owner: String,
    sandbox_name: String,
    restore_only: bool,
    build: Option<Value>,
    result: Option<Value>,
}
pub fn apply_with(desired: &Value, directory: &Path, driver: &mut impl Driver) -> Result<Value> {
    crate::destroy::broker::ensure_available(directory)?;
    let state = state::load(directory)?;
    let path = directory.join("operation.json");
    let mut operation = state::read(&path)?
        .map(serde_json::from_value::<Operation>)
        .transpose()?;
    let desired_hash = plan::digest(desired)?;
    let storage = desired["evaluated"]["config"]
        .get("storage")
        .map(|value| serde_json::from_value::<crate::storage::Profile>(value.clone()))
        .transpose()?;
    driver.preflight(desired)?;
    if let Some(op) = operation.as_ref().filter(|op| op.phase != Phase::Complete) {
        ensure!(
            op.schema_version == 2 && op.desired_hash == desired_hash,
            "Operation interrupted with different inputs: resume using its original inputs"
        );
        if op.phase == Phase::Publishing && state == op.result {
            let result = op
                .result
                .clone()
                .ok_or_else(|| invalid("Missing publication result".into()))?;
            let observed = driver
                .sandbox(text(&result, "sandbox_name")?)?
                .ok_or_else(|| invalid("Published sandbox is missing".into()))?;
            ensure!(
                observed["id"] == result["sandbox_id"]
                    && observed["policy_hash"] == result["policy_hash"]
                    && observed["phase"] == "Ready",
                "Publication interrupted and resource mismatch"
            );
            driver.validate_profile(text(&result, "sandbox_name")?, &result)?;
            verify_storage(&result, driver)?;
            driver.published(directory)?;
            let mut completed = op.clone();
            completed.phase = Phase::Complete;
            atomic_json(&path, &completed)?;
            return Ok(result);
        }
        ensure!(
            op.state_before == state,
            "State changed during the interrupted operation"
        );
        if let Some(state) = &state {
            ensure!(
                serde_json::to_value(driver.sandbox(text(state, "sandbox_name")?)?)?
                    == op.observed_before["sandbox"],
                "Sandbox preconditions changed during recovery"
            );
        }
    } else {
        let saved = state::read(&directory.join("plan.json"))?
            .ok_or_else(|| invalid("Run plan before apply".into()))?;
        let observed = driver.observe(state.as_ref())?;
        plan::verify(&saved, desired, state.as_ref(), &observed)?;
        if saved["actions"].as_array().is_some_and(|a| a.is_empty()) {
            if let Some(state) = &state {
                verify_storage(state, driver)?;
            }
            driver.published(directory)?;
            return state.ok_or_else(|| invalid("State is missing for an empty plan".into()));
        }
        let entropy = tempfile::Builder::new()
            .prefix("owner-")
            .tempdir_in(directory)?;
        // OpenShell labels are limited to 63 characters; retain 128 identity bits.
        let owner: String = crate::files::hash(entropy.path().as_os_str().as_encoded_bytes())
            .chars()
            .take(32)
            .collect();
        let sandbox_name = format!(
            "er-{}",
            owner
                .get(..12)
                .ok_or_else(|| invalid("Invalid creation identity".into()))?
        );
        let op = Operation {
            schema_version: 2,
            desired_hash: desired_hash.clone(),
            state_before: state.clone(),
            observed_before: observed,
            phase: Phase::Planned,
            owner,
            sandbox_name,
            restore_only: saved["actions"] == json!(["restore_image"]),
            build: None,
            result: None,
        };
        atomic_json(&path, &op)?;
        operation = Some(op);
    }
    let mut op = operation.ok_or_else(|| invalid("Missing journal".into()))?;
    if op.restore_only {
        let state = state.ok_or_else(|| invalid("Missing restoration state".into()))?;
        driver.restore(&state)?;
        verify_storage(&state, driver)?;
        driver.published(directory)?;
        op.phase = Phase::Complete;
        op.result = Some(state.clone());
        atomic_json(&path, &op)?;
        return Ok(state);
    }
    if op.phase == Phase::Planned {
        let mut migration = None;
        if let Some(state) = &state {
            let captured = if driver.sandbox(text(state, "sandbox_name")?)?.is_some() {
                Some(driver.capture(state, directory)?)
            } else if state["last_sync"].is_string() {
                Some(state.clone())
            } else {
                None
            };
            if let Some(captured) = captured {
                let export = Path::new(text(&captured, "last_sync")?);
                let receipt = state::read(&export.join("manifest.json"))?
                    .ok_or_else(|| invalid("Missing recovery receipt".into()))?;
                ensure!(
                    receipt["sandbox_id"] == state["sandbox_id"],
                    "Receipt identity mismatch"
                );
                ensure!(
                    state["host_sources"].is_object(),
                    "Missing base sources: migration required"
                );
                migration = Some(
                    json!({"base":state["host_sources"],"remote":receipt["files"],"directory":export.join("project")}),
                );
            }
        }
        op.build = Some(driver.build(desired, directory, migration.as_ref())?);
        op.phase = Phase::Built;
        atomic_json(&path, &op)?;
    }
    let mut build = op
        .build
        .clone()
        .ok_or_else(|| invalid("Build is missing from the journal".into()))?;
    if let Some(profile) = &storage {
        let evidence = driver.prepare_storage(
            profile,
            &directory.join(format!("storage-{}", op.owner)),
            &op.owner,
            &desired["context"],
        )?;
        ensure!(evidence.is_object(), "Missing storage evidence");
        if let Some(original) = build.get("storage") {
            ensure!(*original == evidence, "Original storage evidence changed");
        } else {
            build
                .as_object_mut()
                .ok_or_else(|| invalid("Build is not an object".into()))?
                .insert("storage".into(), evidence);
            op.build = Some(build.clone());
            atomic_json(&path, &op)?;
        }
    }
    if driver.sandbox(&op.sandbox_name)?.is_none() {
        driver.create_profile(
            &op.sandbox_name,
            &build,
            &op.owner,
            &desired["evaluated"]["config"],
        )?;
    }
    let start = std::time::Instant::now();
    let observed = loop {
        if let Some(observed) = driver.sandbox(&op.sandbox_name)? {
            ensure!(
                observed["labels"]["ladyshell.owner"] == op.owner,
                "Resource with the same name is owned by another operation"
            );
            if observed["phase"] == "Ready" {
                break observed;
            }
            ensure!(
                observed["phase"] != "Error",
                "Sandbox is in an error state: inspect OpenShell before recovery"
            );
        }
        ensure!(
            start.elapsed() < std::time::Duration::from_secs(60),
            "Sandbox is not ready: apply can resume"
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    let effective = driver.validate_profile(&op.sandbox_name, &build)?;
    if let Some(evidence) = build.get("storage") {
        driver.verify_storage(&op.sandbox_name, evidence)?;
    }
    atomic_json(
        &directory.join(format!("policy-{}.json", op.owner)),
        &effective,
    )?;
    let mut retained = state
        .as_ref()
        .and_then(|s| s["retained"].as_array())
        .cloned()
        .unwrap_or_default();
    if let Some(state) = &state {
        if driver.sandbox(text(state, "sandbox_name")?)?.is_some() {
            retained.push(json!({"sandbox_name":state["sandbox_name"],"sandbox_id":state["sandbox_id"],"context":state["context"]}));
        }
    }
    let mut result = build;
    let fields = result
        .as_object_mut()
        .ok_or_else(|| invalid("Build is not an object".into()))?;
    fields.extend(json!({"schema_version":2,"context":desired["context"],"desired_hash":desired_hash,"desired_inputs":desired,"sandbox_name":op.sandbox_name,"sandbox_id":observed["id"],"policy_hash":observed["policy_hash"],"owner":op.owner,"owner_label":"ladyshell.owner","retained":retained,"sync":desired["evaluated"]["config"]["sync"],"snapshot_binary":"/usr/local/bin/ladyshell"}).as_object().ok_or_else(||invalid("Result is not an object".into()))?.clone());
    op.result = Some(result.clone());
    op.phase = Phase::Publishing;
    atomic_json(&path, &op)?;
    atomic_json(&directory.join("state.json"), &result)?;
    driver.published(directory)?;
    op.phase = Phase::Complete;
    atomic_json(&path, &op)?;
    Ok(result)
}
fn verify_storage(state: &Value, driver: &mut impl Driver) -> Result<()> {
    if let Some(evidence) = state.get("storage") {
        driver.verify_storage(text(state, "sandbox_name")?, evidence)?;
    }
    Ok(())
}
pub struct NativeDriver {
    pub backend: Backend,
}
impl Driver for NativeDriver {
    fn preflight(&mut self, desired: &Value) -> Result<()> {
        if desired["evaluated"]["config"].get("storage").is_some() {
            broker::preflight(&self.backend, desired)?;
        }
        Ok(())
    }
    fn prepare_storage(
        &mut self,
        profile: &crate::storage::Profile,
        directory: &Path,
        owner: &str,
        context: &Value,
    ) -> Result<Value> {
        broker::prepare(&self.backend, profile, directory, owner, context)
    }
    fn verify_storage(&mut self, name: &str, evidence: &Value) -> Result<()> {
        broker::verify(&self.backend, name, evidence)
    }
    fn create_profile(
        &mut self,
        name: &str,
        build: &Value,
        owner: &str,
        config: &Value,
    ) -> Result<()> {
        if build["image_profile"] == "openshell-wasi" {
            broker::create(&self.backend, name, build, owner)
        } else {
            self.create(name, build, owner, text(&config["sandbox"], "provider")?)
        }
    }
    fn validate_profile(&mut self, name: &str, build: &Value) -> Result<Value> {
        if build["image_profile"] == "openshell-wasi" {
            broker::validate(&self.backend, name, build)
        } else {
            self.validate(name, text(build, "codex_binary")?)
        }
    }
    fn published(&mut self, directory: &Path) -> Result<()> {
        if directory.join("continuous-staging.json").try_exists()? {
            return Ok(());
        }
        crate::associations::register(directory)
    }
    fn observe(&mut self, state: Option<&Value>) -> Result<Value> {
        self.backend.observe(state)
    }
    fn sandbox(&mut self, name: &str) -> Result<Option<Value>> {
        self.backend.sandbox(name)
    }
    fn build(
        &mut self,
        desired: &Value,
        directory: &Path,
        migration: Option<&Value>,
    ) -> Result<Value> {
        image::build(desired, directory, migration)
    }
    fn capture(&mut self, state: &Value, directory: &Path) -> Result<Value> {
        crate::sync::sync(state, directory, &self.backend, false)
    }
    fn create(&mut self, name: &str, build: &Value, owner: &str, provider: &str) -> Result<()> {
        self.backend.verify_provider(provider)?;
        self.backend.call(&[
            "sandbox",
            "create",
            "--name",
            name,
            "--from",
            text(build, "image_id")?,
            "--policy",
            text(build, "policy_path")?,
            "--provider",
            provider,
            "--no-auto-providers",
            "--label",
            &format!("ladyshell.owner={owner}"),
            "--detach",
            "--",
            "/bin/sleep",
            "infinity",
        ])?;
        Ok(())
    }
    fn validate(&mut self, name: &str, binary: &str) -> Result<Value> {
        self.backend.validate_policy(name, binary)
    }
    fn restore(&mut self, state: &Value) -> Result<()> {
        image::load_archive(text(state, "archive")?, text(state, "image_id")?)
    }
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
