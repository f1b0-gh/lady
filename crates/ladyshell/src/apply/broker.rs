//! Qualified fixed-broker provisioning on the original local OpenShell daemon.
use super::invalid;
use crate::{
    continuous::{host::Driver as RuntimeDriver, native::Native},
    environment_lock::atomic_json,
    error::{ensure, Result},
    openshell::Backend,
    policy, process,
    state::{self, text},
    storage::{self, Driver, Filesystem, PinnedDocker, Profile, Receipt},
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};

use crate::sandbox_worker::{BINARY, CONTROL_ARGS, PROTOCOL};
fn initialized_reply(reply: &Value, token: &str) -> Result<()> {
    ensure!(
        *reply == json!({"format":1,"token":token,"accepting":true}),
        "Broker lifecycle initialization refused or capability changed"
    );
    Ok(())
}
fn lifecycle_reply(reply: &Value, token: &str, cleanup: bool) -> Result<()> {
    if cleanup && *reply == json!({"format":1,"token":token,"accepting":false}) {
        return Ok(());
    }
    initialized_reply(reply, token)
}
fn verify_protocol(original: &Value, expected: &Value, cleanup: bool) -> Result<()> {
    let mut sealed = expected.clone();
    sealed["reply"]["accepting"] = json!(false);
    ensure!(
        original == expected || (cleanup && *original == sealed),
        "Original broker lifecycle capability changed"
    );
    Ok(())
}
fn protocol(evidence: &Value, binding: &Value) -> Result<Value> {
    let token = crate::plan::digest(&json!({"format":1,"binding":binding,"storage":evidence}))?;
    Ok(
        json!({"format":1, "request":{"format":1,"action":"initialize","token":token},
        "reply":{"format":1,"token":token,"accepting":true}}),
    )
}
fn qualified_gateway(value: &Value) -> Result<()> {
    let server = url::Url::parse(text(value, "server")?)
        .map_err(|_| invalid("Invalid gateway URL".into()))?;
    ensure!(
        value["status"] == "healthy"
            && value["version"] == "0.1.4"
            && server.scheme() == "https"
            && matches!(server.host_str(), Some("127.0.0.1" | "[::1]")),
        "Broker requires qualified local OpenShell 0.1.4"
    );
    let drivers = value["compute_drivers"]
        .as_array()
        .ok_or_else(|| invalid("Missing compute drivers".into()))?;
    ensure!(
        drivers.len() == 1
            && drivers[0]["name"] == "docker"
            && drivers[0]["capabilities"]["driver_name"] == "docker"
            && drivers[0]["capabilities"]["driver_version"] == "0.1.4",
        "Unqualified OpenShell compute driver"
    );
    Ok(())
}
fn gateway(backend: &Backend) -> Result<Value> {
    let value = crate::json::parse(&backend.call(&["gateway", "info", "--output", "json"])?)?;
    qualified_gateway(&value)?;
    Ok(
        json!({"version":value["version"],"server":value["server"],"compute_drivers":value["compute_drivers"]}),
    )
}
pub(super) fn preflight(backend: &Backend, desired: &Value) -> Result<()> {
    let config: crate::config::ResolvedConfig =
        serde_json::from_value(desired["evaluated"]["config"].clone())?;
    config.validate_broker()?;
    ensure!(
        desired["context"]["gateway"] == backend.gateway
            && desired["context"]["workspace"] == backend.workspace,
        "Broker backend differs from desired context"
    );
    gateway(backend)?;
    PinnedDocker::select()?;
    Ok(())
}
pub(super) fn prepare(
    backend: &Backend,
    profile: &Profile,
    directory: &Path,
    owner: &str,
    context: &Value,
) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let selected = PinnedDocker::select()?;
    let identity = json!({"format":1,"docker":selected.identity()?,"gateway":gateway(backend)?,"context":context,"owner":owner});
    let path = directory.join("backend.json");
    if let Some(original) = state::read(&path)? {
        unchanged(&original, &identity)?;
    } else {
        atomic_json(&path, &identity)?;
    }
    // Resource intents and receipts have their own nested journal/lock.
    let receipts = storage::prepare(
        &directory.join("volumes"),
        profile,
        owner,
        &backend.workspace,
        &mut PinnedDocker::from_identity(&identity["docker"])?,
    )?;
    lock.verify_directory()?;
    Ok(json!({"format":1,"directory":directory,"backend":identity,"receipts":receipts}))
}
pub(crate) fn bound(backend: &Backend, evidence: &Value) -> Result<PinnedDocker> {
    ensure!(
        evidence["format"] == 1
            && evidence["backend"]["context"]["gateway"] == backend.gateway
            && evidence["backend"]["context"]["workspace"] == backend.workspace,
        "Storage backend context changed"
    );
    unchanged(&evidence["backend"]["gateway"], &gateway(backend)?)?;
    unchanged(
        &evidence["backend"]["docker"],
        PinnedDocker::select()?.identity()?,
    )?;
    PinnedDocker::from_identity(&evidence["backend"]["docker"])
}
pub(super) fn prepare_creation(
    backend: &Backend,
    name: &str,
    build: &Value,
    owner: &str,
) -> Result<()> {
    crate::config::identifier(name)?;
    text(build, "image_id")?;
    text(build, "policy_path")?;
    let evidence = &build["storage"];
    let mut docker = bound(backend, evidence)?;
    ensure!(
        evidence["backend"]["owner"] == owner,
        "Storage owner changed"
    );
    ensure!(
        !Path::new(text(evidence, "directory")?)
            .join("binding.json")
            .try_exists()?,
        "Original broker runtime is missing; replacement requires a separate deployment"
    );
    let receipts = receipts(evidence)?;
    check_volumes(&mut docker, &receipts)?;
    Ok(())
}
pub(super) fn create(backend: &Backend, name: &str, build: &Value, owner: &str) -> Result<()> {
    let evidence = &build["storage"];
    let mut docker = bound(backend, evidence)?;
    ensure!(
        evidence["backend"]["owner"] == owner,
        "Storage owner changed"
    );
    ensure!(
        !Path::new(text(evidence, "directory")?)
            .join("binding.json")
            .try_exists()?,
        "Original broker runtime is missing; replacement requires a separate deployment"
    );
    let receipts = receipts(evidence)?;
    check_volumes(&mut docker, &receipts)?;
    let mounts = receipts
        .iter()
        .map(|r| {
            json!({"type":"volume", "source":r.intent().name(),
        "target":r.intent().target(),"read_only":false})
        })
        .collect::<Vec<_>>();
    backend.call(&[
        "sandbox",
        "create",
        "--name",
        name,
        "--from",
        text(build, "image_id")?,
        "--policy",
        text(build, "policy_path")?,
        "--no-auto-providers",
        "--cpu",
        "1",
        "--memory",
        "512Mi",
        "--driver-config-json",
        &json!({"docker":{"mounts":mounts}}).to_string(),
        "--label",
        &format!("ladyshell.owner={owner}"),
        "--detach",
        "--",
        "/bin/sleep",
        "infinity",
    ])?;
    Ok(())
}
pub(crate) fn receipts(evidence: &Value) -> Result<Vec<Receipt>> {
    let receipts: Vec<Receipt> = serde_json::from_value(evidence["receipts"].clone())?;
    ensure!(receipts.len() == 3, "Missing original storage receipts");
    for receipt in &receipts {
        ensure!(
            receipt.intent().labels()["ladyshell.owner"] == evidence["backend"]["owner"],
            "Storage receipt owner changed"
        );
    }
    Ok(receipts)
}
fn check_volumes(docker: &mut PinnedDocker, receipts: &[Receipt]) -> Result<()> {
    for receipt in receipts {
        receipt.verify(
            &docker
                .observe(&receipt.intent().name())?
                .ok_or_else(|| invalid("Original volume missing".into()))?,
        )?;
    }
    Ok(())
}
fn unchanged(original: &Value, observed: &Value) -> Result<()> {
    ensure!(
        original == observed,
        "Original broker deployment identity changed"
    );
    Ok(())
}
fn policy(backend: &Backend, name: &str) -> Result<Value> {
    let value =
        crate::json::parse(&backend.call(&["policy", "get", name, "--full", "--output", "json"])?)?;
    policy::validate_broker_effective(&value["policy"])?;
    Ok(value["policy"].clone())
}
fn exec(backend: &Backend, name: &str, args: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut command = backend.command();
    command
        .args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            name,
            "--",
        ])
        .args(args);
    process::capture_input(command, input, Duration::from_secs(30), 16384)
}
pub(crate) fn validate(backend: &Backend, name: &str, build: &Value) -> Result<Value> {
    validate_inner(backend, name, build, false)
}
pub(crate) fn validate_for_cleanup(backend: &Backend, name: &str, build: &Value) -> Result<Value> {
    validate_inner(backend, name, build, true)
}
fn validate_inner(backend: &Backend, name: &str, build: &Value, cleanup: bool) -> Result<Value> {
    let evidence = &build["storage"];
    bound(backend, evidence)?;
    let observed = backend
        .sandbox(name)?
        .ok_or_else(|| invalid("Broker sandbox missing".into()))?;
    ensure!(
        observed["labels"]["ladyshell.owner"] == evidence["backend"]["owner"]
            && observed["phase"] == "Ready",
        "Broker ownership or readiness changed"
    );
    let current = json!({"sandbox_name":name,"sandbox_id":observed["id"],"owner":evidence["backend"]["owner"],
        "context":evidence["backend"]["context"],"image_id":build["image_id"],"policy_hash":observed["policy_hash"]});
    let runtime = serde_json::to_value(Native.observe(&current)?)?;
    let binding = json!({"current":current,"runtime":runtime});
    let directory = Path::new(text(evidence, "directory")?);
    let lock = state::StateLock::acquire_existing(directory)?;
    let path = directory.join("binding.json");
    if let Some(original) = state::read(&path)? {
        unchanged(&original, &binding)?;
    } else {
        atomic_json(&path, &binding)?;
    }
    let effective = policy(backend, name)?;
    ensure!(
        String::from_utf8(exec(backend, name, &["/bin/id", "-u"], b"")?)?.trim() == "10001",
        "Incorrect broker UID"
    );
    ensure!(
        String::from_utf8(exec(backend, name, &["/bin/readlink", "-f", BINARY], b"")?)?.trim()
            == text(build, "broker_binary")?,
        "Broker binary changed"
    );
    ensure!(
        String::from_utf8(exec(
            backend,
            name,
            &["/usr/local/bin/ladyshell", "--version"],
            b""
        )?)?
        .starts_with("ladyshell "),
        "Receiver artifact invalid"
    );
    let reply = exec(
        backend,
        name,
        &CONTROL_ARGS,
        &serde_json::to_vec(&json!({"format":1,"action":"probe"}))?,
    )?;
    ensure!(
        crate::json::parse(&reply)? == json!({"format":1,"protocol":PROTOCOL}),
        "Broker protocol mismatch"
    );
    let measured = measure(backend, evidence, &binding)?;
    let path = directory.join("mounts.json");
    if let Some(original) = state::read(&path)? {
        unchanged(&original, &measured)?;
    } else {
        atomic_json(&path, &measured)?;
    }
    let mut expected = protocol(evidence, &binding)?;
    let path = directory.join("protocol.json");
    let original = state::read(&path)?;
    if let Some(original) = &original {
        verify_protocol(original, &expected, cleanup)?;
    }
    let reply = crate::json::parse(&exec(
        backend,
        name,
        &CONTROL_ARGS,
        &serde_json::to_vec(&expected["request"])?,
    )?)?;
    lifecycle_reply(&reply, text(&expected["request"], "token")?, cleanup)?;
    expected["reply"] = reply;
    unchanged(
        &binding["runtime"],
        &serde_json::to_value(Native.observe(&current)?)?,
    )?;
    lock.verify_directory()?;
    atomic_json(&path, original.as_ref().unwrap_or(&expected))?;
    Ok(effective)
}
fn measure(backend: &Backend, evidence: &Value, binding: &Value) -> Result<Value> {
    let current = &binding["current"];
    let name = text(current, "sandbox_name")?;
    let mut docker = bound(backend, evidence)?;
    unchanged(
        &binding["runtime"],
        &serde_json::to_value(Native.observe(current)?)?,
    )?;
    let observed = backend
        .sandbox(name)?
        .ok_or_else(|| invalid("Broker sandbox missing".into()))?;
    ensure!(
        observed["id"] == current["sandbox_id"]
            && observed["policy_hash"] == current["policy_hash"],
        "Broker sandbox or policy changed"
    );
    policy(backend, name)?;
    let receipts = receipts(evidence)?;
    check_volumes(&mut docker, &receipts)?;
    let stats: Vec<Filesystem> = serde_json::from_slice(&exec(
        backend,
        name,
        &["/usr/local/bin/ladyshell", "broker-storage-probe"],
        b"",
    )?)?;
    let mut command = docker.command()?;
    command.args([
        "ps",
        "--all",
        "--no-trunc",
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
    let ids = String::from_utf8(process::capture(command, Duration::from_secs(30), 4096)?)?;
    let ids = ids.lines().collect::<Vec<_>>();
    ensure!(
        ids.len() == 1 && ids[0].len() == 64,
        "Unique local broker runtime required"
    );
    let mut command = docker.command()?;
    command.args(["inspect", ids[0], "--format", "{{json .Mounts}}"]);
    let mounts = crate::json::parse(&process::capture(command, Duration::from_secs(30), 65536)?)?;
    storage::verify_mounts(&receipts, &mounts, &stats)?;
    unchanged(
        &binding["runtime"],
        &serde_json::to_value(Native.observe(current)?)?,
    )?;
    // Availability changes with work; retain only identity and hard ceilings.
    Ok(json!(stats
        .iter()
        .map(|f| json!({"target":f.target,"device":f.device,"bytes":f.bytes,"inodes":f.inodes}))
        .collect::<Vec<_>>()))
}
pub(crate) fn verify(backend: &Backend, name: &str, evidence: &Value) -> Result<()> {
    verify_inner(backend, name, evidence, false)
}
fn verify_inner(backend: &Backend, name: &str, evidence: &Value, cleanup: bool) -> Result<()> {
    let directory = Path::new(text(evidence, "directory")?);
    let lock = state::StateLock::acquire_existing(directory)?;
    let binding = state::read(&directory.join("binding.json"))?
        .ok_or_else(|| invalid("Missing original broker runtime".into()))?;
    ensure!(
        binding["current"]["sandbox_name"] == name,
        "Broker deployment name changed"
    );
    let original_protocol = state::read(&directory.join("protocol.json"))?
        .ok_or_else(|| invalid("Missing original broker lifecycle capability".into()))?;
    verify_protocol(&original_protocol, &protocol(evidence, &binding)?, cleanup)?;
    let original = state::read(&directory.join("mounts.json"))?
        .ok_or_else(|| invalid("Missing original mounted caps".into()))?;
    unchanged(&original, &measure(backend, evidence, &binding)?)?;
    lock.verify_directory()
}
pub(crate) fn verify_state(backend: &Backend, current: &Value) -> Result<()> {
    verify_state_inner(backend, current, false)
}
pub(crate) fn verify_state_for_cleanup(backend: &Backend, current: &Value) -> Result<()> {
    verify_state_inner(backend, current, true)
}
fn verify_state_inner(backend: &Backend, current: &Value, cleanup: bool) -> Result<()> {
    let evidence = &current["storage"];
    let directory = Path::new(text(evidence, "directory")?);
    let binding = state::read(&directory.join("binding.json"))?
        .ok_or_else(|| invalid("Missing original broker runtime".into()))?;
    for field in [
        "sandbox_name",
        "sandbox_id",
        "owner",
        "context",
        "image_id",
        "policy_hash",
    ] {
        ensure!(
            binding["current"].get(field) == current.get(field),
            "Broker state differs from original runtime: {field}"
        );
    }
    verify_inner(backend, text(current, "sandbox_name")?, evidence, cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn broker_initialization_requires_original_correlation_and_open_generation() {
        let token = "a".repeat(64);
        assert!(
            initialized_reply(&json!({"format":1,"token":token,"accepting":true}), &token).is_ok()
        );
        for reply in [
            json!({"format":1,"token":token,"accepting":false}),
            json!({"format":1,"token":"b".repeat(64),"accepting":true}),
            json!({"format":1,"token":token,"accepting":true,"retired":true}),
            json!({"Err":"unsupported"}),
        ] {
            assert!(initialized_reply(&reply, &token).is_err());
        }
    }
    #[test]
    fn sealed_initialization_is_eligible_only_for_cleanup() -> Result<()> {
        let token = "a".repeat(64);
        let sealed = json!({"format":1,"token":token,"accepting":false});
        assert!(lifecycle_reply(&sealed, &token, false).is_err());
        lifecycle_reply(&sealed, &token, true)?;
        for reply in [
            json!({"format":1,"token":"b".repeat(64),"accepting":false}),
            json!({"format":1,"token":token,"accepting":false,"retired":true}),
        ] {
            assert!(lifecycle_reply(&reply, &token, true).is_err());
        }
        let expected = protocol(
            &json!({"volumes":"original"}),
            &json!({"runtime":"original"}),
        )?;
        let mut retained = expected.clone();
        retained["reply"]["accepting"] = json!(false);
        assert!(verify_protocol(&retained, &expected, false).is_err());
        verify_protocol(&retained, &expected, true)?;
        retained["request"]["token"] = json!("b".repeat(64));
        assert!(verify_protocol(&retained, &expected, true).is_err());
        Ok(())
    }
    #[test]
    fn backend_selection_refuses_unqualified_versions_and_remote_gateways() {
        let original = json!({"status":"healthy","version":"0.1.4","server":"https://127.0.0.1:17670",
            "compute_drivers":[{"name":"docker","capabilities":{"driver_name":"docker","driver_version":"0.1.4"}}]});
        assert!(qualified_gateway(&original).is_ok());
        for (key, value) in [
            ("version", json!("0.1.5")),
            ("server", json!("https://remote.example")),
            ("compute_drivers", json!([])),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(qualified_gateway(&changed).is_err());
        }
    }
    #[test]
    fn runtime_recovery_rejects_changed_mount_identity_or_process_incarnation() {
        let original = json!({"runtime":"start-a","devices":[1,2,3]});
        assert!(unchanged(&original, &original).is_ok());
        for changed in [
            json!({"runtime":"start-b","devices":[1,2,3]}),
            json!({"runtime":"start-a","devices":[4,2,3]}),
        ] {
            assert!(unchanged(&original, &changed).is_err());
        }
    }
}
