//! Qualified local Docker OpenShell adapter. Runtime identity includes the
//! container start observation: OpenShell 0.1.4 reuses its generation annotation.
use super::{
    host::{self, Driver, Observation},
    invalid,
    model::Acknowledgement,
};
use crate::{
    error::{ensure, Result},
    openshell::Backend,
    request::Desired,
    state,
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
pub struct Native;
impl Driver for Native {
    fn can_swap_source(&mut self, current: &Value) -> Result<bool> {
        let backend = Backend::new(&current["context"])?;
        backend.verify_execution(current)?;
        let bytes = backend.call(&[
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            state::text(current, "sandbox_name")?,
            "--",
            "/usr/local/bin/ladyshell",
            "cs-worker-profile",
        ])?;
        let value = crate::json::parse(&bytes)?;
        ensure!(
            value["schema_version"] == 1,
            "Unknown worker source-storage profile"
        );
        value["warm_source_swap"]
            .as_bool()
            .ok_or_else(|| invalid("Worker source-storage capability is missing"))
    }
    fn observe(&mut self, current: &Value) -> Result<Observation> {
        let backend = Backend::new(&current["context"])?;
        let value = backend
            .runtime_identity(state::text(current, "sandbox_name")?)?
            .ok_or_else(|| invalid("Sandbox is absent"))?;
        let label = current["owner_label"].as_str().unwrap_or("ladyshell.owner");
        let runtime = docker_runtime(current, &value)?;
        ensure!(
            backend
                .runtime_identity(state::text(current, "sandbox_name")?)?
                .as_ref()
                == Some(&value),
            "Gateway identity changed during Docker observation"
        );
        Ok(Observation {
            sandbox_id: state::text(&value, "id")?.into(),
            owner: state::text(&value["labels"], label)?.into(),
            runtime,
            phase: state::text(&value, "phase")?.into(),
        })
    }
    fn verify(&mut self, current: &Value) -> Result<()> {
        let backend = Backend::new(&current["context"])?;
        backend.verify_execution(current)?;
        crate::run::verify_provider(&backend, current)
    }
    fn export(&mut self, current: &Value, directory: &Path) -> Result<Value> {
        crate::sync::sync(
            current,
            directory,
            &Backend::new(&current["context"])?,
            false,
        )
    }
    fn stop(&mut self, current: &Value) -> Result<()> {
        Backend::new(&current["context"])?.call(&[
            "sandbox",
            "stop",
            state::text(current, "sandbox_name")?,
        ])?;
        Ok(())
    }
    fn start(&mut self, current: &Value) -> Result<()> {
        Backend::new(&current["context"])?.call(&[
            "sandbox",
            "start",
            state::text(current, "sandbox_name")?,
        ])?;
        Ok(())
    }
    fn apply(&mut self, current: &Value, bundle: &[u8]) -> Result<Acknowledgement> {
        let backend = Backend::new(&current["context"])?;
        backend.verify_execution(current)?;
        let mut command = backend.command();
        command.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            state::text(current, "sandbox_name")?,
            "--",
            "/usr/local/bin/ladyshell",
            "cs-worker",
        ]);
        let bytes =
            crate::process::capture_input(command, bundle, Duration::from_secs(300), 1024 * 1024)?;
        Ok(serde_json::from_value(crate::json::parse(&bytes)?)?)
    }
    fn inventory(&mut self, current: &Value) -> Result<crate::snapshot::Inventory> {
        crate::sync::observe_inventory(current, &Backend::new(&current["context"])?)
    }
}
pub fn runtime_binding(current: &Value, gateway: &Value, container: &Value) -> Result<String> {
    let labels = &container["labels"];
    ensure!(
        gateway["id"] == current["sandbox_id"]
            && labels["openshell.ai/sandbox-id"] == current["sandbox_id"]
            && labels["openshell.ai/sandbox-name"] == current["sandbox_name"]
            && labels["openshell.ai/sandbox-workspace"] == current["context"]["workspace"]
            && labels["openshell.ai/isolation-role"] == "sandbox"
            && labels["openshell.ai/managed-by"] == "openshell"
            && container["image"] == current["image_id"],
        "Local Docker runtime does not match owned OpenShell sandbox"
    );
    let id = state::text(container, "id")?;
    let started = state::text(&container["state"], "StartedAt")?;
    ensure!(
        super::model::digest(id) && !started.starts_with("0001-"),
        "Docker runtime has not started"
    );
    if gateway["phase"] == "Ready" {
        ensure!(
            container["state"]["Running"] == true
                && container["state"]["Paused"] == false
                && container["state"]["Restarting"] == false,
            "Docker workload is not running normally"
        );
    }
    if gateway["phase"] == "Stopped" {
        ensure!(
            container["state"]["Running"] == false,
            "Docker workload is still running after stop"
        );
    }
    crate::plan::digest(
        &json!({"profile":"openshell-local-docker-v1","sandbox":current["sandbox_id"],"container":id,"started_at":started,"gateway_generation":gateway["runtime_generation"]}),
    )
}
fn docker_runtime(current: &Value, gateway: &Value) -> Result<String> {
    let endpoint = if let Ok(value) = std::env::var("DOCKER_HOST") {
        value
    } else {
        let mut context = std::process::Command::new("docker");
        context.args([
            "context",
            "inspect",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ]);
        String::from_utf8(crate::process::capture(
            context,
            Duration::from_secs(30),
            4096,
        )?)?
        .trim()
        .to_owned()
    };
    ensure!(
        endpoint.starts_with("unix:///"),
        "CS currently qualifies a local Docker Unix-socket daemon only"
    );
    let mut list = std::process::Command::new("docker");
    list.args([
        "ps",
        "-a",
        "--no-trunc",
        "--filter",
        &format!(
            "label=openshell.ai/sandbox-id={}",
            state::text(current, "sandbox_id")?
        ),
        "--filter",
        "label=openshell.ai/isolation-role=sandbox",
        "--format",
        "{{.ID}}",
    ]);
    let ids = String::from_utf8(crate::process::capture(
        list,
        Duration::from_secs(30),
        4096,
    )?)?;
    let ids: Vec<_> = ids.lines().filter(|s| !s.is_empty()).collect();
    ensure!(ids.len()==1 && super::model::digest(ids[0]),"CS requires exactly one matching local Docker workload; remote/other runtime profiles are not qualified");
    let mut inspect = std::process::Command::new("docker");
    inspect.args(["inspect",ids[0],"--format",r#"{"id":{{json .Id}},"state":{{json .State}},"labels":{{json .Config.Labels}},"image":{{json .Image}}}"#]);
    let container = crate::json::parse(&crate::process::capture(
        inspect,
        Duration::from_secs(30),
        64 * 1024,
    )?)?;
    let binding = runtime_binding(current, gateway, &container)?;
    let mut info = std::process::Command::new("docker");
    info.args(["info", "--format", "{{.ID}}"]);
    let daemon = String::from_utf8(crate::process::capture(
        info,
        Duration::from_secs(30),
        4096,
    )?)?;
    ensure!(
        !daemon.trim().is_empty(),
        "Docker daemon identity is missing"
    );
    crate::plan::digest(&json!({"endpoint":endpoint,"daemon":daemon.trim(),"runtime":binding}))
}
pub fn admit(current: &Value) -> Result<()> {
    host::admit(current, &mut Native)
}
pub fn initialize(directory: &Path, task: &str) -> Result<Value> {
    let current = state::load(directory)?.ok_or_else(|| invalid("State is missing"))?;
    ensure!(
        current["desired_inputs"]["artifacts"]["ladyshell"]["sha256"]
            == crate::environment_lock::artifact_hash(&std::env::current_exe()?)?,
        "Sandbox runtime lacks this exact CS implementation; create a new sandbox first"
    );
    host::initialize_with(directory, &mut Native, task)
}
pub fn refresh(args: &Desired, attempt: &str, context: &Value) -> Result<Value> {
    ensure!(super::model::token(attempt), "Invalid refresh attempt");
    let frozen = {
        let lock = state::StateLock::acquire(&args.state)?;
        let root = lock
            .directory
            .join("continuous")
            .join(attempt)
            .join("input");
        host::freeze(&args.project, &root)?;
        root
    };
    let mut inputs = args.clone();
    inputs.project = frozen;
    let desired = crate::app::desired(&inputs)?;
    host::refresh_with(&args.state, &mut Native, &desired, attempt, context)
}
pub fn status(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current = state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing"))?;
    let s = host::session(&current)?;
    let observed = Native.observe(&current)?;
    Ok(
        json!({"continuous":s,"observed":observed,"checkpoint":current["continuous_checkpoint"],"selection":current["continuous_selection"],"replacement":current["continuous_replacement"]}),
    )
}

impl host::ReplacementDriver for Native {
    fn create(&mut self, desired: &Value, directory: &Path) -> Result<Value> {
        let lock = state::StateLock::acquire(directory)?;
        let _lease = state::SessionLock::acquire(&lock.directory, true)?;
        let retained = freeze_resources(desired, &lock.directory.join("construction-resources"))?;
        let desired = &retained;
        let backend = Backend::new(&desired["context"])?;
        let existing = state::load(&lock.directory)?;
        let operation = state::read(&lock.directory.join("operation.json"))?;
        if operation.as_ref().is_none_or(|o| o["phase"] == "complete") {
            let observed = backend.observe(existing.as_ref())?;
            let plan = crate::plan::plan(desired, existing.as_ref(), &observed)?;
            crate::files::publish_json(&lock.directory.join("plan.json"), &plan, true)?;
        }
        crate::apply::apply_with(
            desired,
            &lock.directory,
            &mut crate::apply::NativeDriver { backend },
        )
    }
    fn retire(&mut self, previous: &Value) -> Result<()> {
        let backend = Backend::new(&previous["context"])?;
        let name = state::text(previous, "sandbox_name")?;
        // This deletion is reached only after a durable activation records the exact old ID.
        let Some(observed) = backend.sandbox_identity(name)? else {
            return Ok(());
        };
        let label = previous["owner_label"]
            .as_str()
            .unwrap_or("ladyshell.owner");
        ensure!(
            observed["id"] == previous["sandbox_id"]
                && observed["labels"][label] == previous["owner"],
            "Old sandbox identity changed; retirement refused"
        );
        backend.call(&["sandbox", "delete", name])?;
        ensure!(
            backend.sandbox_identity(name)?.is_none(),
            "Old sandbox retirement not yet confirmed"
        );
        Ok(())
    }
}

/// Copy only recipe bytes authenticated by the native environment lock. Nix
/// consumes this retained tree, so a later source-checkout edit cannot change it.
pub fn freeze_resources(desired: &Value, destination: &Path) -> Result<Value> {
    let hashes = desired["environment_lock"]["recipes_sha256"]
        .as_object()
        .ok_or_else(|| invalid("Recipe identities missing"))?;
    ensure!(!hashes.is_empty(), "Recipe identities are empty");
    let source = Path::new(state::text(desired, "resources")?);
    let mut expected = std::collections::BTreeMap::new();
    for (name, value) in hashes {
        ensure!(
            !name.starts_with("runtime-source/"),
            "CS audit-runtime replacement needs a separate resource profile"
        );
        let path = if name.starts_with("resources/")
            || name.starts_with("crates/ladyshell/resources/audit/")
        {
            name.clone()
        } else {
            format!("nix/{name}")
        };
        crate::snapshot::validate_path(&path)?;
        let hash = value
            .as_str()
            .filter(|h| super::model::digest(h))
            .ok_or_else(|| invalid("Invalid locked recipe digest"))?;
        expected.insert(path, hash.to_owned());
    }
    if !destination.try_exists()? {
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("Resource destination parent missing"))?;
        state::create_directory(parent)?;
        let stage = tempfile::Builder::new()
            .prefix(".resources-")
            .tempdir_in(parent)?;
        for (path, hash) in &expected {
            let bytes =
                crate::files::read_limited(&source.join(path), crate::snapshot::FILE_LIMIT)?;
            ensure!(
                crate::files::hash(&bytes) == *hash,
                "Locked recipe changed before replacement: {path}"
            );
            crate::image::write_source(stage.path(), path, &bytes, false)?;
            crate::files::open_regular(&stage.path().join(path))?.sync_all()?;
        }
        super::worker::sync_tree(stage.path())?;
        std::fs::rename(stage.path(), destination)?;
        crate::files::open_directory(parent)?.sync_all()?;
    }
    let inventory = crate::snapshot::inventory(destination)?;
    ensure!(
        inventory.len() == expected.len()
            && inventory
                .iter()
                .all(|(p, e)| expected.get(p) == Some(&e.sha256)),
        "Retained construction resources changed"
    );
    let mut result = desired.clone();
    result["resources"] = json!(destination);
    Ok(result)
}
pub fn replace(directory: &Path) -> Result<Value> {
    let result = host::replace_with(directory, &mut Native)?;
    crate::associations::register(directory)?;
    Ok(result)
}
