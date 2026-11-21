use ladyshell::{associations, environment_lock::atomic_json};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn registry(root: &Path) -> PathBuf {
    root.join("xdg/ladyshell/associations")
}

fn seed(root: &Path, id: &str) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let project = root.join("project");
    fs::create_dir_all(&project)?;
    let directory = root.join(id);
    ladyshell::state::create_directory(&directory)?;
    atomic_json(
        &directory.join("state.json"),
        &json!({"schema_version":2,"sandbox_name":id,"sandbox_id":id,"policy_hash":"hash","codex_binary":"codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"gateway","workspace":"default"},"desired_inputs":{"project":project},"secret":"must-not-appear"}),
    )?;
    associations::register_at(&registry(root), &directory)?;
    Ok(directory)
}

fn invoke(root: &Path, json: bool) -> std::io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
    command
        .arg("list")
        .env("XDG_STATE_HOME", root.join("xdg"))
        .env("HOME", root.join("home"))
        .env("PATH", root)
        .env("FIXTURE", root);
    if json {
        command.arg("--json");
    }
    command.output()
}

fn rewrite(directory: &Path, field: &str, value: Value) -> Result {
    let path = directory.join("state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&path)?)?;
    state[field] = value;
    atomic_json(&path, &state)?;
    Ok(())
}

fn receipt(directory: &Path, id: &str, deleted: bool) -> Result {
    atomic_json(
        &directory.join("destroy.json"),
        &json!({"schema_version":1,"sandbox_name":id,"sandbox_id":id,"context":{"gateway":"gateway","workspace":"default"},"owner":"owner","deleted":deleted}),
    )?;
    Ok(())
}

#[test]
fn lists_retained_instances_without_provider_calls_or_file_changes() -> Result {
    let root = tempfile::tempdir()?;
    let stopped = seed(root.path(), "stopped")?;
    rewrite(&stopped, "phase", json!("Stopped"))?;
    rewrite(
        &stopped,
        "retained",
        json!([{"sandbox_name":"previous","sandbox_id":"previous-id","context":{"gateway":"old-gateway","workspace":"default"}}]),
    )?;
    let deleted = seed(root.path(), "deleted")?;
    receipt(&deleted, "deleted", true)?;
    let pending = seed(root.path(), "pending")?;
    receipt(&pending, "pending", false)?;
    let recreated = seed(root.path(), "recreated")?;
    receipt(&recreated, "older-identity", true)?;
    fs::write(
        root.path().join("openshell"),
        "#!/bin/sh\nprintf called > \"$FIXTURE/provider-called\"\nexit 99\n",
    )?;
    fs::set_permissions(
        root.path().join("openshell"),
        fs::Permissions::from_mode(0o700),
    )?;
    let before = tree(root.path())?;
    let output = invoke(root.path(), true)?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["scope"], "registered_local_states");
    assert_eq!(report["provider_checked"], false);
    assert_eq!(report["complete"], true);
    assert_eq!(report["excluded_deleted"], 1);
    let instances = report["instances"].as_array().ok_or("instances missing")?;
    assert_eq!(instances.len(), 4);
    let find = |id: &str| instances.iter().find(|entry| entry["sandbox_id"] == id);
    let stopped_entry = find("stopped").ok_or("stopped instance omitted")?;
    assert_eq!(stopped_entry["recorded_status"], "retained");
    assert_eq!(stopped_entry["directory"], json!(stopped));
    assert_eq!(stopped_entry["project"], json!(root.path().join("project")));
    assert_eq!(
        find("previous-id").ok_or("previous missing")?["kind"],
        "previous"
    );
    assert_eq!(
        find("pending").ok_or("pending missing")?["recorded_status"],
        "deletion_pending"
    );
    assert!(
        find("recreated").is_some(),
        "Old deletion must not hide a replacement"
    );
    assert!(find("deleted").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-appear"));
    let human = invoke(root.path(), false)?;
    assert!(human.status.success(), "{human:?}");
    let text = String::from_utf8(human.stdout)?;
    assert!(text.contains("stopped") && text.contains("previous-id"));
    assert!(text.contains("OpenShell was not queried"));
    assert_eq!(
        tree(root.path())?,
        before,
        "Listing must not modify files or invoke OpenShell"
    );
    Ok(())
}

#[test]
fn absent_registry_is_empty_without_creating_state_directories() -> Result {
    let root = tempfile::tempdir()?;
    let before = tree(root.path())?;
    let output = invoke(root.path(), true)?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["instances"], json!([]));
    assert_eq!(report["complete"], true);
    assert_eq!(tree(root.path())?, before);
    Ok(())
}

#[test]
fn stale_missing_and_invalid_entries_remain_visible_without_hiding_valid_instances() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "valid")?;
    let stale = seed(root.path(), "stale")?;
    rewrite(&stale, "sandbox_id", json!("replacement"))?;
    let missing = seed(root.path(), "missing")?;
    fs::remove_file(missing.join("state.json"))?;
    fs::remove_dir(&missing)?;
    fs::write(registry(root.path()).join("invalid.json"), b"{invalid}")?;
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(
        report["instances"]
            .as_array()
            .ok_or("instances missing")?
            .len(),
        1
    );
    assert_eq!(report["instances"][0]["sandbox_id"], "valid");
    let diagnostics = report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?;
    for code in ["stale_association", "missing_state", "invalid_association"] {
        assert!(
            diagnostics.iter().any(|entry| entry["code"] == code),
            "Missing {code}: {report}"
        );
    }
    assert!(
        !missing.exists(),
        "Listing must not recreate a missing state"
    );
    Ok(())
}

#[test]
fn hostile_links_and_special_files_are_rejected_without_being_followed() -> Result {
    let root = tempfile::tempdir()?;
    let linked = seed(root.path(), "linked")?;
    let state = linked.join("state.json");
    let target = root.path().join("private.json");
    fs::rename(&state, &target)?;
    symlink(&target, &state)?;
    symlink(&target, registry(root.path()).join("hostile.json"))?;
    let fifo = registry(root.path()).join("fifo.json");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())?;
    // SAFETY: c_path is a live NUL-terminated path in the synthetic test directory.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["instances"], json!([]));
    assert_eq!(
        report["diagnostics"]
            .as_array()
            .ok_or("diagnostics missing")?
            .len(),
        3
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-appear"));
    fs::remove_file(&fifo)?;
    let saved = root.path().join("saved-registry");
    fs::rename(registry(root.path()), &saved)?;
    symlink(&saved, registry(root.path()))?;
    assert!(
        !invoke(root.path(), true)?.status.success(),
        "Symlinked registry must be refused"
    );
    Ok(())
}

#[test]
fn deletion_receipts_match_the_complete_recorded_identity_including_previous_instances() -> Result {
    let root = tempfile::tempdir()?;
    let directory = seed(root.path(), "current")?;
    rewrite(
        &directory,
        "retained",
        json!([{"sandbox_name":"previous","sandbox_id":"previous","context":{"gateway":"gateway","workspace":"default"}}]),
    )?;
    receipt(&directory, "previous", true)?;
    let output = invoke(root.path(), true)?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["excluded_deleted"], 1);
    assert_eq!(
        report["instances"]
            .as_array()
            .ok_or("instances missing")?
            .len(),
        1
    );
    assert_eq!(report["instances"][0]["sandbox_id"], "current");
    receipt(&directory, "current", true)?;
    let output = invoke(root.path(), true)?;
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["instances"][0]["sandbox_id"], "previous");
    for (field, value) in [
        ("sandbox_name", json!("other-name")),
        ("sandbox_id", json!("other-id")),
        ("owner", json!("other-owner")),
        (
            "context",
            json!({"gateway":"other-gateway","workspace":"default"}),
        ),
        (
            "context",
            json!({"gateway":"gateway","workspace":"other-workspace"}),
        ),
    ] {
        receipt(&directory, "current", true)?;
        let path = directory.join("destroy.json");
        let mut receipt: Value = serde_json::from_slice(&fs::read(&path)?)?;
        receipt[field] = value;
        atomic_json(&path, &receipt)?;
        let output = invoke(root.path(), true)?;
        assert!(output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            report["excluded_deleted"], 0,
            "Mismatched {field} must not hide an instance"
        );
        assert_eq!(
            report["instances"]
                .as_array()
                .ok_or("instances missing")?
                .len(),
            2
        );
    }
    Ok(())
}

#[test]
fn malformed_receipts_and_previous_records_do_not_disappear_silently() -> Result {
    let root = tempfile::tempdir()?;
    let directory = seed(root.path(), "valid")?;
    fs::write(directory.join("destroy.json"), b"{\"deleted\":true}")?;
    rewrite(&directory, "retained", json!([{"sandbox_id":"incomplete"}]))?;
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["instances"][0]["sandbox_id"], "valid");
    assert_eq!(report["excluded_deleted"], 0);
    let diagnostics = report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?;
    for code in ["invalid_deletion_receipt", "invalid_retained_instance"] {
        assert!(
            diagnostics.iter().any(|entry| entry["code"] == code),
            "Missing {code}"
        );
    }
    Ok(())
}

#[test]
fn missing_or_busy_registry_lock_is_refused_without_creating_it() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "valid")?;
    let held = ladyshell::state::StateLock::acquire(&registry(root.path()))?;
    assert!(!invoke(root.path(), true)?.status.success());
    drop(held);
    fs::remove_file(registry(root.path()).join(".lock"))?;
    let before = tree(root.path())?;
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["diagnostics"][0]["code"], "missing_registry_lock");
    assert_eq!(tree(root.path())?, before);
    Ok(())
}

#[test]
fn registry_limit_is_reported_as_incomplete() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "valid")?;
    for index in 0..1000 {
        fs::write(
            registry(root.path()).join(format!("invalid-{index}.json")),
            b"{}",
        )?;
    }
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert!(report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?
        .iter()
        .any(|entry| entry["code"] == "registry_limit"));
    Ok(())
}

#[test]
fn human_inventory_escapes_terminal_control_characters() -> Result {
    let root = tempfile::tempdir()?;
    let directory = seed(root.path(), "valid")?;
    rewrite(&directory, "sandbox_name", json!("name\n\u{1b}[2J"))?;
    associations::register_at(&registry(root.path()), &directory)?;
    let output = invoke(root.path(), false)?;
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout)?;
    assert!(!text.contains('\u{1b}'));
    assert!(text.contains("name\\n\\u001b[2J"));
    Ok(())
}

#[test]
fn non_utf8_registry_entry_is_reported_without_panicking() -> Result {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir()?;
    seed(root.path(), "valid")?;
    let name = std::ffi::OsString::from_vec(b"invalid-\xff.json".to_vec());
    fs::write(registry(root.path()).join(name), b"invalid")?;
    let output = invoke(root.path(), true)?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["instances"][0]["sandbox_id"], "valid");
    assert_eq!(report["diagnostics"][0]["code"], "invalid_association");
    assert!(report["diagnostics"][0]["association"].is_null());
    assert!(report["diagnostics"][0]["association_display"]
        .as_str()
        .ok_or("display missing")?
        .contains("\\xFF"));
    let invalid_root = root
        .path()
        .join(std::ffi::OsString::from_vec(b"root-\xff".to_vec()));
    let output = invoke(&invalid_root, true)?;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    Ok(())
}

fn tree(root: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut found = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            found.push((path.clone(), Vec::new()));
            found.extend(tree(&path)?);
        } else {
            found.push((path.clone(), fs::read(path)?));
        }
    }
    found.sort();
    Ok(found)
}
