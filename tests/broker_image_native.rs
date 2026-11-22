//! Explicit image qualification. Requires reviewed ELF inputs and Nix/Docker.
use ladyshell::{app, environment_lock::atomic_json, image, request::BrokerDesired};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command, time::Duration};
#[path = "support/broker_cancel.rs"]
mod cancel;
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
    qualify(false, false, None, false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_provisions_with_original_mounted_caps() -> Result<()> {
    qualify(true, false, None, false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_destroy_retains_export_at_full_capacity() -> Result<()> {
    qualify(true, true, None, false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_cancellation_after_creation_preserves_original_intent() -> Result<()> {
    qualify(true, false, Some(cancel::Boundary::Creation), false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_cancellation_after_validation_exports_bound_generation() -> Result<()> {
    qualify(true, false, Some(cancel::Boundary::Validation), false)
}
#[test]
#[ignore = "requires explicit evidence root, reviewed worker ELF, Nix and local OpenShell"]
fn qualified_broker_cancellation_exports_sealed_generation_without_initialization_receipt(
) -> Result<()> {
    qualify(
        true,
        false,
        Some(cancel::Boundary::SealedInitialization),
        false,
    )
}
#[test]
#[ignore = "requires reviewed worker ELF, Nix and local OpenShell; this tests transport, not LO admission"]
fn ordinary_retained_receiver_runs_the_fixed_broker_and_preserves_its_reply() -> Result<()> {
    qualify(true, true, None, true)
}
#[path = "support/broker_receiver.rs"]
mod receiver;
fn qualify(
    provision: bool,
    ordinary_destroy: bool,
    interruption: Option<cancel::Boundary>,
    retained_receiver: bool,
) -> Result<()> {
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let result = if let Some(boundary) = interruption {
            app::make_broker_plan(&args).and_then(|_| cancel::apply(&desired, &state, boundary))
        } else if provision {
            app::make_broker_plan(&args).and_then(|_| app::apply_broker(&args))
        } else {
            image::build(&desired, &state, None)
        };
        result
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
            .and_then(|built| {
                if retained_receiver {
                    receiver::verify(&root, &state)?;
                }
                if ordinary_destroy {
                    verify_sealed_export(&root, &built, Some(&state))?;
                    assert!(app::make_broker_plan(&args).is_err());
                    assert!(app::apply_broker(&args).is_err());
                } else if provision && interruption.is_none() {
                    verify_recovery(&args, &root, &built)?;
                }
                Ok(built)
            })
    }))
    .unwrap_or_else(|_| {
        Err("qualification panicked; original journals retained for cleanup".into())
    });
    if let Err(error) = &result {
        eprintln!("Broker qualification failed: {error}");
    }
    cleanup(&root, &state, &desired, &tag, provision)?;
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
    verify_sealed_export(root, current, None)?;
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

fn verify_sealed_export(root: &Path, current: &Value, destroy_state: Option<&Path>) -> Result<()> {
    let backend = ladyshell::openshell::Backend::new(&current["context"])?;
    let name = ladyshell::state::text(current, "sandbox_name")?;
    let protocol = ladyshell::state::read(
        &Path::new(ladyshell::state::text(&current["storage"], "directory")?).join("protocol.json"),
    )?
    .ok_or("ordinary provisioning did not retain broker initialization")?;
    assert_eq!(protocol["reply"]["Ok"]["accepting"], true);
    let command = |args: &[&str]| {
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
        command
    };
    let error = ladyshell::process::capture(command(&["/bin/bash", "-c",
        "export LC_ALL=C; for i in {1..32}; do printf '%4096s' '' || exit; done > /var/lib/ladyshell/broker/control/fill"]),
        Duration::from_secs(30), 16384).err().ok_or("control byte cap not enforced")?;
    assert!(
        error.to_string().contains("No space left on device"),
        "{error}"
    );
    let byte_failure = error.to_string();
    let error = ladyshell::process::capture(command(&["/bin/bash", "-c",
        "export LC_ALL=C; for i in $(/bin/seq 1 64); do /bin/touch /var/lib/ladyshell/broker/control/fill-$i || exit 83; done"]),
        Duration::from_secs(30), 16384).err().ok_or("control inode cap not enforced")?;
    assert!(
        error.to_string().contains("No space left on device"),
        "{error}"
    );
    let inode_failure = error.to_string();
    let full: Vec<ladyshell::storage::Filesystem> =
        serde_json::from_slice(&ladyshell::process::capture(
            command(&["/usr/local/bin/ladyshell", "broker-storage-probe"]),
            Duration::from_secs(30),
            16384,
        )?)?;
    assert_eq!(full[0].available_bytes, 0);
    assert_eq!(full[0].available_inodes, 0);
    atomic_json(
        &root.join("full-storage.json"),
        &json!({"full":full,"byte_failure":byte_failure,"inode_failure":inode_failure}),
    )?;
    if let Some(state) = destroy_state {
        let args = ladyshell::request::Destroy {
            state: state.to_owned(),
            discard_work: false,
        };
        let result = ladyshell::destroy::run(&args)?;
        assert_eq!(result["deleted"], true);
        let receipt: ladyshell::storage::export::Receipt =
            serde_json::from_value(result["export"]["receipt"].clone())?;
        let archive = fs::File::open(ladyshell::state::text(&result["export"], "path")?)?;
        assert_eq!(
            ladyshell::storage::export::verify(&receipt.request, archive)?,
            receipt
        );
        assert!(backend.sandbox(name)?.is_none());
        use ladyshell::storage::Driver;
        let mut docker = ladyshell::storage::PinnedDocker::from_identity(
            &current["storage"]["backend"]["docker"],
        )?;
        let volumes: Vec<ladyshell::storage::Receipt> =
            serde_json::from_value(current["storage"]["receipts"].clone())?;
        for volume in &volumes {
            assert!(docker.observe(&volume.intent().name())?.is_none());
        }
        assert_eq!(ladyshell::destroy::run(&args)?, result);
        atomic_json(
            &root.join("ordinary-destroy.json"),
            &json!({"full":full,"byte_failure":byte_failure,
            "inode_failure":inode_failure,"destroy":result,"original_volumes_absent":true,"retry_idempotent":true}),
        )?;
        return Ok(());
    }
    let token = "f".repeat(64);
    let sealed = ladyshell::process::capture_input(
        command(&[
            "/usr/local/bin/lo-executor-worker",
            "broker",
            "/var/lib/ladyshell/broker/control",
            "/var/lib/ladyshell/broker/artifacts",
            "/var/lib/ladyshell/broker/incoming",
        ]),
        &serde_json::to_vec(&json!({"format":1,"operation":{"kind":"seal","token":token}}))?,
        Duration::from_secs(30),
        16384,
    )?;
    assert_eq!(
        ladyshell::json::parse(&sealed)?,
        json!({"Ok":{"token":token,"accepting":false}})
    );
    let request = ladyshell::storage::export::Request {
        format: 1,
        token,
        profile: serde_json::from_value(
            current["desired_inputs"]["evaluated"]["config"]["storage"].clone(),
        )?,
    };
    let mut archive = tempfile::NamedTempFile::new_in(root)?;
    let receipt = ladyshell::storage::export::capture(
        &request,
        command(&["/usr/local/bin/ladyshell", "broker-export"]),
        archive.as_file_mut(),
        Duration::from_secs(30),
    )?;
    backend.verify_execution(current)?;
    let archive_path = root.join("sealed-broker.tar");
    archive.persist_noclobber(&archive_path)?;
    ladyshell::files::open_directory(root)?.sync_all()?;
    atomic_json(
        &root.join("sealed-export.json"),
        &json!({"full":full,"byte_failure":byte_failure,
        "inode_failure":inode_failure,"sealed_at_full_capacity":true,"archive":archive_path,"receipt":receipt}),
    )?;
    Ok(())
}

fn cleanup(root: &Path, state: &Path, desired: &Value, tag: &str, provision: bool) -> Result<()> {
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
    for entry in fs::read_dir(state)? {
        let path = entry?.path().join("broker-build.json");
        if !path.exists() {
            continue;
        }
        let receipt: Value =
            serde_json::from_slice(&ladyshell::files::read_limited(&path, 65536)?)?;
        if receipt["desired_hash"] != ladyshell::plan::digest(desired)? {
            return Err("build receipt differs from original desired inputs".into());
        }
        if let Some(id) = receipt["image_id"].as_str() {
            let present = docker(&["image", "ls", "--format", "{{.ID}}", tag])?;
            if !present.is_empty() {
                let bytes = docker(&["image", "inspect", tag, "--format", "{{.Id}}"])?;
                if String::from_utf8(bytes)?.trim() != id {
                    return Err("image tag replaced".into());
                }
                docker(&["image", "rm", tag])?;
                if !docker(&["image", "ls", "--format", "{{.ID}}", tag])?.is_empty() {
                    return Err("owned image tag deletion unconfirmed".into());
                }
            }
        }
        owned.push(receipt);
    }
    if !docker(&["image", "ls", "--format", "{{.ID}}", tag])?.is_empty() {
        return Err("unreconciled image tag; retain original build evidence".into());
    }
    atomic_json(
        &root.join("cleanup.json"),
        &json!({"owned_image_tag":tag,"removed":true,"builds":owned}),
    )?;
    Ok(())
}

#[test]
#[ignore = "requires explicit retained fixture evidence; deletes only original owned fixture resources"]
fn cleanup_retained_broker_qualification() -> Result<()> {
    let root = std::path::PathBuf::from(
        std::env::var_os("LADYSHELL_BROKER_CLEANUP_EVIDENCE")
            .ok_or("retained fixture evidence required")?,
    );
    let desired = ladyshell::state::read(&root.join("desired.json"))?
        .ok_or("original desired inputs missing")?;
    let config = &desired["evaluated"]["config"];
    if config["image"]["profile"] != "openshell-wasi" {
        return Err("not a broker fixture".into());
    }
    let tag = format!(
        "ladyshell-{}-broker:nix",
        ladyshell::state::text(config, "name")?
    );
    let state = root.join("state");
    cleanup(
        &root,
        &state,
        &desired,
        &tag,
        state.join("operation.json").exists(),
    )
}
