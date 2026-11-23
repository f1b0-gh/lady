//! Explicit mounted-cap qualification. Journals survive; owned resources do not.
use ladyshell::{
    continuous::host::Driver as RuntimeDriver,
    environment_lock::atomic_json,
    openshell::Backend,
    policy,
    storage::{self, Driver, Filesystem, Limits, Profile},
};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn docker(args: &[&str]) -> Result<Vec<u8>> {
    let mut command = Command::new("docker");
    command.args(args);
    Ok(ladyshell::process::capture(
        command,
        Duration::from_secs(30),
        1024 * 1024,
    )?)
}
#[test]
#[ignore = "requires explicit evidence root, local OpenShell Docker gateway and reviewed image with Python"]
fn qualified_openshell_enforces_each_owned_byte_and_inode_cap() -> Result<()> {
    let base = std::env::var_os("LADYSHELL_STORAGE_TEST_ROOT").ok_or("evidence root required")?;
    let image =
        std::env::var("LADYSHELL_STORAGE_TEST_IMAGE").map_err(|_| "reviewed image required")?;
    let image = String::from_utf8(docker(&[
        "image", "inspect", &image, "--format", "{{.Id}}",
    ])?)?
    .trim()
    .to_owned();
    let gateway =
        std::env::var("LADYSHELL_STORAGE_TEST_GATEWAY").map_err(|_| "gateway required")?;
    let context = json!({"gateway":gateway,"workspace":"default"});
    let backend = Backend::new(&context)?;
    let directory = tempfile::Builder::new()
        .prefix("mounted-")
        .tempdir_in(base)?
        .keep();
    let owner = ladyshell::files::hash(directory.as_os_str().as_encoded_bytes())[..32].to_owned();
    let name = format!("ls-cap-{}", &owner[..12]);
    let profile = Profile {
        control: Limits {
            bytes: 65536,
            inodes: 32,
        },
        artifacts: Limits {
            bytes: 262144,
            inodes: 64,
        },
        incoming: Limits {
            bytes: 262144,
            inodes: 64,
        },
    };
    let mut evidence = json!({"format":1,"name":name,"owner":owner,"context":context,"image":image,"deleted":false});
    atomic_json(&directory.join("qualification.json"), &evidence)?;
    eprintln!(
        "OpenShell cap qualification journal: {}",
        directory.display()
    );
    let journal = directory.join("volumes");
    let policy_path = directory.join("policy.json");
    atomic_json(&policy_path, &policy::broker_policy())?;
    let result = (|| -> Result<()> {
        let receipts =
            storage::prepare(&journal, &profile, &owner, "default", &mut storage::Docker)?;
        let mounts = receipts.iter().map(|r| json!({"type":"volume","source":r.intent().name(),"target":r.intent().target(),"read_only":false})).collect::<Vec<_>>();
        let driver_config = json!({"docker":{"mounts":mounts}}).to_string();
        backend.call(&[
            "sandbox",
            "create",
            "--name",
            &name,
            "--from",
            &image,
            "--policy",
            policy_path.to_str().ok_or("policy path")?,
            "--no-auto-providers",
            "--cpu",
            "1",
            "--memory",
            "128Mi",
            "--driver-config-json",
            &driver_config,
            "--label",
            &format!("ladyshell.owner={owner}"),
            "--detach",
            "--",
            "/bin/sleep",
            "infinity",
        ])?;
        let deadline = Instant::now() + Duration::from_secs(60);
        let observed = loop {
            let observed = backend.sandbox_identity(&name)?.ok_or("sandbox missing")?;
            if observed["labels"]["ladyshell.owner"] != owner {
                return Err("owner changed".into());
            }
            evidence["sandbox_id"] = observed["id"].clone();
            atomic_json(&directory.join("qualification.json"), &evidence)?;
            if observed["phase"] == "Ready" {
                break observed;
            }
            if observed["phase"] == "Error" || Instant::now() >= deadline {
                return Err("sandbox not ready".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        let current = json!({"sandbox_name":name,"sandbox_id":observed["id"],
            "owner":owner,"context":context,"image_id":image});
        let before = ladyshell::continuous::native::Native.observe(&current)?;
        let effective: Value = serde_json::from_slice(
            &backend.call(&["policy", "get", &name, "--full", "--output", "json"])?,
        )?;
        atomic_json(&directory.join("effective-policy.json"), &effective)?;
        policy::validate_broker_effective(&effective["policy"])?;
        let stats: Vec<Filesystem> = serde_json::from_slice(&backend.call(&[
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            &name,
            "--",
            "/bin/python3",
            "-I",
            "-c",
            include_str!("storage_openshell.py"),
        ])?)?;
        let ids = String::from_utf8(docker(&[
            "ps",
            "--all",
            "--no-trunc",
            "--filter",
            &format!(
                "label=openshell.ai/sandbox-id={}",
                observed["id"].as_str().ok_or("id")?
            ),
            "--filter",
            "label=openshell.ai/isolation-role=sandbox",
            "--format",
            "{{.ID}}",
        ])?)?;
        let ids = ids.lines().collect::<Vec<_>>();
        if ids.len() != 1 {
            return Err("unique Docker workload required".into());
        }
        let mounts: Value = serde_json::from_slice(&docker(&[
            "inspect",
            ids[0],
            "--format",
            "{{json .Mounts}}",
        ])?)?;
        for receipt in &receipts {
            receipt.verify(
                &storage::Docker
                    .observe(&receipt.intent().name())?
                    .ok_or("volume missing")?,
            )?;
        }
        storage::verify_mounts(&receipts, &mounts, &stats)?;
        let after = ladyshell::continuous::native::Native.observe(&current)?;
        if serde_json::to_value(before)? != serde_json::to_value(&after)? {
            return Err("runtime changed during qualification".into());
        }
        evidence["runtime"] = serde_json::to_value(after)?;
        evidence["filesystems"] = serde_json::to_value(stats)?;
        evidence["hard_caps_passed"] = json!(true);
        atomic_json(&directory.join("qualification.json"), &evidence)?;
        Ok(())
    })();
    // Reconcile only the retained name/owner; never remove another sandbox or
    // delete its attached volumes. A failed cleanup leaves the journal for retry.
    let cleanup = cleanup(&backend, &name, &owner, &evidence, &journal);
    if cleanup.is_ok() {
        evidence["deleted"] = json!(true);
        atomic_json(&directory.join("qualification.json"), &evidence)?;
    }
    if let Err(error) = &result {
        eprintln!("Qualification failed: {error}");
    }
    cleanup?;
    result
}
fn cleanup(
    backend: &Backend,
    name: &str,
    owner: &str,
    evidence: &Value,
    journal: &Path,
) -> Result<()> {
    if let Some(observed) = backend.sandbox_identity(name)? {
        if observed["labels"]["ladyshell.owner"] != owner
            || evidence
                .get("sandbox_id")
                .is_some_and(|id| *id != observed["id"])
        {
            return Err("cleanup identity mismatch".into());
        }
        backend.call(&["sandbox", "delete", name])?;
        if backend.sandbox_identity(name)?.is_some() {
            return Err("sandbox deletion unconfirmed".into());
        }
    }
    if journal.join("storage.json").exists() {
        storage::remove(journal, &mut storage::Docker)?;
    }
    Ok(())
}
