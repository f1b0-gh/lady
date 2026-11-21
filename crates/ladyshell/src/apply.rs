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
    let state = state::load(directory)?;
    let path = directory.join("operation.json");
    let mut operation = state::read(&path)?
        .map(serde_json::from_value::<Operation>)
        .transpose()?;
    let desired_hash = plan::digest(desired)?;
    if let Some(op) = operation.as_ref().filter(|op| op.phase != Phase::Complete) {
        ensure!(
            op.schema_version == 2 && op.desired_hash == desired_hash,
            "Opération interrompue pour d’autres entrées : reprendre ses entrées originales"
        );
        if op.phase == Phase::Publishing && state == op.result {
            let result = op
                .result
                .clone()
                .ok_or_else(|| invalid("Résultat de publication absent".into()))?;
            let observed = driver
                .sandbox(text(&result, "sandbox_name")?)?
                .ok_or_else(|| invalid("Sandbox publiée absente".into()))?;
            ensure!(
                observed["id"] == result["sandbox_id"]
                    && observed["policy_hash"] == result["policy_hash"]
                    && observed["phase"] == "Ready",
                "Publication interrompue et ressource divergente"
            );
            driver.validate(
                text(&result, "sandbox_name")?,
                text(&result, "codex_binary")?,
            )?;
            driver.published(directory)?;
            let mut completed = op.clone();
            completed.phase = Phase::Complete;
            atomic_json(&path, &completed)?;
            return Ok(result);
        }
        ensure!(
            op.state_before == state,
            "État modifié pendant opération interrompue"
        );
        if let Some(state) = &state {
            ensure!(
                serde_json::to_value(driver.sandbox(text(state, "sandbox_name")?)?)?
                    == op.observed_before["sandbox"],
                "Préconditions sandbox modifiées pendant reprise"
            );
        }
    } else {
        let saved = state::read(&directory.join("plan.json"))?
            .ok_or_else(|| invalid("Exécuter plan avant apply".into()))?;
        let observed = driver.observe(state.as_ref())?;
        plan::verify(&saved, desired, state.as_ref(), &observed)?;
        if saved["actions"].as_array().is_some_and(|a| a.is_empty()) {
            driver.published(directory)?;
            return state.ok_or_else(|| invalid("État absent pour plan vide".into()));
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
                .ok_or_else(|| invalid("Identité de création invalide".into()))?
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
    let mut op = operation.ok_or_else(|| invalid("Journal absent".into()))?;
    if op.restore_only {
        let state = state.ok_or_else(|| invalid("État de restauration absent".into()))?;
        driver.restore(&state)?;
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
                    .ok_or_else(|| invalid("Reçu de récupération absent".into()))?;
                ensure!(
                    receipt["sandbox_id"] == state["sandbox_id"],
                    "Identité du reçu divergente"
                );
                ensure!(
                    state["host_sources"].is_object(),
                    "Sources de base absentes : migration requise"
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
    let build = op
        .build
        .clone()
        .ok_or_else(|| invalid("Construction absente du journal".into()))?;
    if driver.sandbox(&op.sandbox_name)?.is_none() {
        driver.create(
            &op.sandbox_name,
            &build,
            &op.owner,
            text(&desired["evaluated"]["config"]["sandbox"], "provider")?,
        )?;
    }
    let start = std::time::Instant::now();
    let observed = loop {
        if let Some(observed) = driver.sandbox(&op.sandbox_name)? {
            ensure!(
                observed["labels"]["ladyshell.owner"] == op.owner,
                "Ressource homonyme détenue par une autre opération"
            );
            if observed["phase"] == "Ready" {
                break observed;
            }
            ensure!(
                observed["phase"] != "Error",
                "Sandbox en erreur : examiner OpenShell avant reprise"
            );
        }
        ensure!(
            start.elapsed() < std::time::Duration::from_secs(60),
            "Sandbox non prête : apply peut reprendre"
        );
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    let effective = driver.validate(&op.sandbox_name, text(&build, "codex_binary")?)?;
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
        .ok_or_else(|| invalid("Construction non objet".into()))?;
    fields.extend(json!({"schema_version":2,"context":desired["context"],"desired_hash":desired_hash,"desired_inputs":desired,"sandbox_name":op.sandbox_name,"sandbox_id":observed["id"],"policy_hash":observed["policy_hash"],"owner":op.owner,"owner_label":"ladyshell.owner","retained":retained,"sync":desired["evaluated"]["config"]["sync"],"snapshot_binary":"/usr/local/bin/ladyshell"}).as_object().ok_or_else(||invalid("Résultat non objet".into()))?.clone());
    op.result = Some(result.clone());
    op.phase = Phase::Publishing;
    atomic_json(&path, &op)?;
    atomic_json(&directory.join("state.json"), &result)?;
    driver.published(directory)?;
    op.phase = Phase::Complete;
    atomic_json(&path, &op)?;
    Ok(result)
}
pub struct NativeDriver {
    pub backend: Backend,
}
impl Driver for NativeDriver {
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
