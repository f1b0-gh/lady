//! Explicit image qualification. Requires reviewed ELF inputs and Nix/Docker.
use ladyshell::{app, environment_lock::atomic_json, image, request::BrokerDesired};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn docker(args: &[&str]) -> Result<Vec<u8>> {
    let mut command = Command::new("docker");
    command.args(args);
    Ok(ladyshell::process::capture(
        command,
        Duration::from_secs(60),
        1024 * 1024,
    )?)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local Docker"]
fn qualified_fixed_image_builds_from_explicit_locked_artifacts() -> Result<()> {
    qualify(false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_provisions_with_original_mounted_caps() -> Result<()> {
    qualify(true)
}
fn qualify(provision: bool) -> Result<()> {
    let base =
        std::env::var_os("LADYSHELL_BROKER_IMAGE_EVIDENCE").ok_or("evidence directory required")?;
    let worker =
        std::env::var_os("LADYSHELL_BROKER_WORKER").ok_or("reviewed broker worker required")?;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix("image-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(base)?
        .keep();
    eprintln!("Broker image evidence: {}", root.display());
    let owner = ladyshell::files::hash(root.as_os_str().as_encoded_bytes())[..12].to_owned();
    let name = format!("broker-qualification-{owner}");
    let tag = format!("ladyshell-{name}-broker:nix");
    let project = root.join("project");
    let state = root.join("state");
    fs::create_dir(&project)?;
    ladyshell::state::create_directory(&state)?;
    let gateway = if provision {
        std::env::var("LADYSHELL_STORAGE_TEST_GATEWAY")?
    } else {
        "unused".into()
    };
    ladyshell::config::identifier(&gateway)?;
    fs::write(
        project.join("README.md"),
        "Synthetic immutable broker input\n",
    )?;
    let config = root.join("broker.ncl");
    fs::write(
        &config,
        format!(
            r#"{{schema_version = 1, name = "{name}",
        image = {{backend = "nix", profile = "openshell-wasi", platform = "x86_64-linux"}},
        sources = {{include = ["README.md"], exclude = []}}, tools = {{}},
        missions = {{dev = {{tools = [], include = [], depends_on = [], checks = []}}}},
        sandbox = {{gateway = "{gateway}", workspace = "default"}},
        storage = {{control = {{bytes = 65536, inodes = 32}},
            artifacts = {{bytes = 262144, inodes = 64}}, incoming = {{bytes = 262144, inodes = 64}}}},
    }}"#
        ),
    )?;
    let args = BrokerDesired {
        config,
        project,
        state: state.clone(),
        resources: Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf(),
        worker: worker.into(),
        runtime: Path::new(env!("CARGO_BIN_EXE_ladyshell")).to_path_buf(),
        lock: Some(root.join("broker.lock.json")),
        ladybom: None,
        mission: "dev".into(),
    };
    app::lock_broker(&args)?;
    let desired = app::desired_broker(&args)?;
    atomic_json(&root.join("desired.json"), &desired)?;
    if !docker(&["image", "ls", "--format", "{{.Repository}}:{{.Tag}}", &tag])?.is_empty() {
        return Err("qualification tag already exists".into());
    }
    let result = if provision {
        app::make_broker_plan(&args).and_then(|_| app::apply_broker(&args))
    } else {
        image::build(&desired, &state, None)
    };
    let result = result
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
        .and_then(|built| {
            if provision {
                verify_recovery(&args, &root, &built)?;
            }
            Ok(built)
        });
    if let Err(error) = &result {
        eprintln!("Broker qualification failed: {error}");
    }
    // Even interrupted publication retains the original creation intent.
    if provision {
        if let Some(op) = ladyshell::state::read(&state.join("operation.json"))? {
            let backend = ladyshell::openshell::Backend::new(&desired["context"])?;
            let name = ladyshell::state::text(&op, "sandbox_name")?;
            if let Some(observed) = backend.sandbox_identity(name)? {
                if observed["labels"]["ladyshell.owner"] != op["owner"]
                    || op["result"]
                        .get("sandbox_id")
                        .is_some_and(|id| *id != observed["id"])
                {
                    return Err("owned sandbox changed before cleanup".into());
                }
                backend.call(&["sandbox", "delete", name])?;
                if backend.sandbox_identity(name)?.is_some() {
                    return Err("sandbox deletion unconfirmed".into());
                }
            }
            let volume_directory = state
                .join(format!("storage-{}", ladyshell::state::text(&op, "owner")?))
                .join("volumes");
            if volume_directory.join("storage.json").exists() {
                let identity = ladyshell::state::read(
                    &volume_directory
                        .parent()
                        .ok_or("volume parent")?
                        .join("backend.json"),
                )?
                .ok_or("backend receipt missing")?;
                ladyshell::storage::remove(
                    &volume_directory,
                    &mut ladyshell::storage::PinnedDocker::from_identity(&identity["docker"])?,
                )?;
            }
        }
    }

    // Build records are written before image loading, including validation failure.
    let mut owned = Vec::new();
    for entry in fs::read_dir(&state)? {
        let path = entry?.path().join("broker-build.json");
        if !path.exists() {
            continue;
        }
        let receipt: Value =
            serde_json::from_slice(&ladyshell::files::read_limited(&path, 65536)?)?;
        if receipt["desired_hash"] != ladyshell::plan::digest(&desired)? {
            return Err("build receipt differs from original desired inputs".into());
        }
        if let Some(id) = receipt["image_id"].as_str() {
            let present = docker(&["image", "ls", "--format", "{{.ID}}", &tag])?;
            if !present.is_empty() {
                let bytes = docker(&["image", "inspect", &tag, "--format", "{{.Id}}"])?;
                if String::from_utf8(bytes)?.trim() != id {
                    return Err("image tag replaced".into());
                }
                docker(&["image", "rm", &tag])?;
                if !docker(&["image", "ls", "--format", "{{.ID}}", &tag])?.is_empty() {
                    return Err("owned image tag deletion unconfirmed".into());
                }
            }
        }
        owned.push(receipt);
    }
    if !docker(&["image", "ls", "--format", "{{.ID}}", &tag])?.is_empty() {
        return Err("unreconciled image tag; retain original build evidence".into());
    }
    atomic_json(
        &root.join("cleanup.json"),
        &json!({"owned_image_tag":tag,"removed":true,"builds":owned}),
    )?;
    let built = result?;
    assert_eq!(built["image_profile"], "openshell-wasi");
    assert!(built.get("codex_binary").is_none());
    assert!(built["broker_binary"]
        .as_str()
        .ok_or("binary")?
        .ends_with("-ladyshell-lo-executor/bin/lo-executor-worker"));
    atomic_json(&root.join("result.json"), &built)?;
    Ok(())
}

fn verify_recovery(args: &BrokerDesired, root: &Path, current: &Value) -> Result<()> {
    use ladyshell::continuous::host::Driver;
    let backend = ladyshell::openshell::Backend::new(&current["context"])?;
    backend.verify_execution(current)?;
    let inventory = ladyshell::continuous::native::Native.inventory(current)?;
    atomic_json(&root.join("inventory.json"), &inventory)?;
    let planned = app::make_broker_plan(args)?;
    assert_eq!(planned["actions"], json!([]));
    assert_eq!(app::apply_broker(args)?, *current);
    let name = ladyshell::state::text(current, "sandbox_name")?;
    let before = serde_json::to_value(ladyshell::continuous::native::Native.observe(current)?)?;
    backend.call(&["sandbox", "stop", name])?;
    backend.call(&["sandbox", "start", name])?;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let observed = backend
            .sandbox_identity(name)?
            .ok_or("restarted sandbox missing")?;
        if observed["phase"] == "Ready" {
            break;
        }
        if observed["phase"] == "Error" || std::time::Instant::now() >= deadline {
            return Err("restarted sandbox did not become ready".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let after = serde_json::to_value(ladyshell::continuous::native::Native.observe(current)?)?;
    assert_ne!(before["runtime"], after["runtime"]);
    let error = backend
        .verify_execution(current)
        .err()
        .ok_or("lost volatile runtime was silently readmitted")?;
    assert!(
        error
            .to_string()
            .contains("Original broker deployment identity changed"),
        "{error}"
    );
    atomic_json(
        &root.join("recovery.json"),
        &json!({"initial_verification":true,"empty_plan_rechecked":true,
        "before":before,"after":after,"old_incarnation_refused":true}),
    )?;
    Ok(())
}
