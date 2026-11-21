use ladyshell::{associations, environment_lock::atomic_json};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn seed(root: &Path, id: &str) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let project = root.join("project");
    fs::create_dir_all(&project)?;
    let state = root.join(id);
    ladyshell::state::create_directory(&state)?;
    atomic_json(
        &state.join("state.json"),
        &json!({"schema_version":2,"sandbox_name":id,"sandbox_id":id,"policy_hash":"hash","codex_binary":"codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"gateway","workspace":"default"},"desired_inputs":{"project":project},"secret":"must-not-appear"}),
    )?;
    associations::register_at(&root.join("xdg/ladyshell/associations"), &state)?;
    Ok(state)
}
fn command(root: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
    c.arg("manage")
        .args(args)
        .env("XDG_STATE_HOME", root.join("xdg"))
        .env("HOME", root.join("home"))
        .env("PATH", root);
    c
}
fn invoke(root: &Path, args: &[&str]) -> std::io::Result<Output> {
    command(root, args).output()
}
fn ok(root: &Path, args: &[&str]) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let out = invoke(root, args)?;
    assert!(out.status.success(), "{args:?}: {out:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("must-not-appear"));
    Ok(serde_json::from_slice(&out.stdout)?)
}
#[test]
fn persists_import_metadata_filters_and_history_across_processes() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "one")?;
    seed(root.path(), "two")?;
    let refresh = ok(root.path(), &["refresh"])?;
    assert_eq!(refresh["complete"], true);
    assert_eq!(refresh["observed"], 2);
    let list = ok(root.path(), &["list"])?;
    assert_eq!(list["instances"].as_array().map(Vec::len), Some(2));
    let id = list["instances"][0]["id"].as_str().ok_or("ID missing")?;
    ok(
        root.path(),
        &[
            "annotate",
            id,
            "--label",
            "team=core",
            "--note",
            "retained work",
        ],
    )?;
    let filtered = ok(root.path(), &["list", "--label", "team=core"])?;
    assert_eq!(filtered["instances"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        filtered["instances"][0]["metadata"]["note"],
        "retained work"
    );
    let before = ok(root.path(), &["history", id])?;
    ok(root.path(), &["refresh"])?;
    assert_eq!(ok(root.path(), &["history", id])?, before);
    ok(root.path(), &["annotate", id, "--archive"])?;
    assert_eq!(
        ok(root.path(), &["list"])?["instances"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        ok(root.path(), &["list", "--include-archived"])?["instances"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    ok(
        root.path(),
        &["annotate", id, "--unarchive", "--remove-label", "team"],
    )?;
    assert_eq!(
        ok(root.path(), &["show", id])?["metadata"]["archived"],
        false
    );
    Ok(())
}
#[test]
fn partial_refresh_keeps_unobserved_rows_and_reports_diagnostics() -> Result {
    let root = tempfile::tempdir()?;
    let state = seed(root.path(), "one")?;
    ok(root.path(), &["refresh"])?;
    fs::remove_file(state.join("state.json"))?;
    let result = invoke(root.path(), &["refresh"])?;
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["complete"], false);
    let list = ok(root.path(), &["list"])?;
    assert_eq!(list["instances"][0]["observed"], false);
    assert_eq!(list["instances"][0]["recorded_status"], "retained");
    assert_eq!(list["last_refresh"]["complete"], false);
    Ok(())
}
#[test]
fn reads_do_not_create_database_and_bad_limits_fail() -> Result {
    let root = tempfile::tempdir()?;
    assert!(!invoke(root.path(), &["list"])?.status.success());
    assert!(!root.path().join("xdg").exists());
    seed(root.path(), "one")?;
    ok(root.path(), &["refresh"])?;
    assert!(!invoke(root.path(), &["list", "--limit", "0"])?
        .status
        .success());
    assert!(!invoke(root.path(), &["list", "--limit", "1001"])?
        .status
        .success());
    assert!(!invoke(root.path(), &["show", "unknown"])?.status.success());
    Ok(())
}
#[test]
fn deletion_requires_matching_receipt_and_is_available_in_history() -> Result {
    let root = tempfile::tempdir()?;
    let state = seed(root.path(), "one")?;
    ok(root.path(), &["refresh"])?;
    atomic_json(
        &state.join("destroy.json"),
        &json!({"schema_version":1,"sandbox_name":"one","sandbox_id":"one","context":{"gateway":"gateway","workspace":"default"},"owner":"owner","deleted":true}),
    )?;
    ok(root.path(), &["refresh"])?;
    assert_eq!(ok(root.path(), &["list"])?["instances"], json!([]));
    let list = ok(root.path(), &["list", "--include-deleted"])?;
    assert_eq!(list["instances"][0]["recorded_status"], "deleted");
    assert!(state.join("state.json").exists());
    Ok(())
}

#[test]
fn replacement_preserves_previous_identity_and_metadata() -> Result {
    let root = tempfile::tempdir()?;
    let state = seed(root.path(), "one")?;
    ok(root.path(), &["refresh"])?;
    let list = ok(root.path(), &["list"])?;
    let id = list["instances"][0]["id"].as_str().ok_or("ID missing")?;
    ok(root.path(), &["annotate", id, "--note", "old identity"])?;
    let mut value: Value = serde_json::from_slice(&fs::read(state.join("state.json"))?)?;
    value["sandbox_id"] = json!("replacement");
    atomic_json(&state.join("state.json"), &value)?;
    associations::register_at(&root.path().join("xdg/ladyshell/associations"), &state)?;
    ok(root.path(), &["refresh"])?;
    let old = ok(root.path(), &["show", id])?;
    assert_eq!(old["observed"], false);
    assert_eq!(old["metadata"]["note"], "old identity");
    let list = ok(root.path(), &["list"])?;
    assert_eq!(list["instances"].as_array().map(Vec::len), Some(2));
    let new = list["instances"]
        .as_array()
        .ok_or("no rows")?
        .iter()
        .find(|r| r["sandbox_id"] == "replacement")
        .ok_or("replacement missing")?;
    assert_eq!(new["metadata"]["note"], "");
    assert_eq!(new["observed"], true);
    Ok(())
}

#[test]
fn concurrent_annotations_merge_without_lost_labels() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "one")?;
    ok(root.path(), &["refresh"])?;
    let list = ok(root.path(), &["list"])?;
    let id = list["instances"][0]["id"].as_str().ok_or("ID missing")?;
    let children = (0..8)
        .map(|i| {
            command(
                root.path(),
                &["annotate", id, "--label", &format!("key{i}=yes")],
            )
            .stdout(std::process::Stdio::null())
            .spawn()
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    for mut child in children {
        assert!(child.wait()?.success());
    }
    let row = ok(root.path(), &["show", id])?;
    assert_eq!(
        row["metadata"]["labels"].as_object().map(|o| o.len()),
        Some(8)
    );
    let history = ok(root.path(), &["history", id, "--limit", "3"])?;
    assert_eq!(history["events"].as_array().map(Vec::len), Some(3));
    let cursor = history["next"].as_i64().ok_or("cursor absent")?.to_string();
    let rest = ok(root.path(), &["history", id, "--after", &cursor])?;
    assert_eq!(rest["events"].as_array().map(Vec::len), Some(6));
    Ok(())
}

#[test]
fn rejects_hostile_database_and_sidecar_paths_without_modification() -> Result {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir()?;
    seed(root.path(), "one")?;
    let dir = root.path().join("xdg/ladyshell/management");
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let db = dir.join("catalog.sqlite3");
    let target = root.path().join("untouched");
    fs::write(&target, b"untouched")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
    symlink(&target, &db)?;
    assert!(!invoke(root.path(), &["refresh"])?.status.success());
    assert_eq!(fs::read(&target)?, b"untouched");
    fs::remove_file(&db)?;
    fs::hard_link(&target, &db)?;
    assert!(!invoke(root.path(), &["refresh"])?.status.success());
    assert_eq!(fs::read(&target)?, b"untouched");
    fs::remove_file(&db)?;
    ok(root.path(), &["refresh"])?;
    symlink(&target, dir.join("catalog.sqlite3-journal"))?;
    assert!(
        !invoke(root.path(), &["annotate", &"a".repeat(64), "--note", "x"])?
            .status
            .success()
    );
    assert_eq!(fs::read(&target)?, b"untouched");
    Ok(())
}

#[test]
fn pagination_and_invalid_annotations_preserve_catalogue() -> Result {
    let root = tempfile::tempdir()?;
    for id in ["one", "two", "three"] {
        seed(root.path(), id)?;
    }
    ok(root.path(), &["refresh"])?;
    let first = ok(root.path(), &["list", "--limit", "2"])?;
    let cursor = first["next"].as_str().ok_or("cursor missing")?;
    let second = ok(root.path(), &["list", "--limit", "2", "--after", cursor])?;
    assert_eq!(second["instances"].as_array().map(Vec::len), Some(1));
    assert_eq!(second["next"], Value::Null);
    let id = first["instances"][0]["id"].as_str().ok_or("ID missing")?;
    let original = ok(root.path(), &["show", id])?;
    assert!(
        !invoke(root.path(), &["annotate", id, "--note", &"x".repeat(4097)])?
            .status
            .success()
    );
    assert!(!invoke(
        root.path(),
        &["annotate", id, "--label", "a=x", "--remove-label", "a"]
    )?
    .status
    .success());
    assert!(!invoke(
        root.path(),
        &["annotate", id, "--label", "key=x", "--label", "key=y"]
    )?
    .status
    .success());
    assert!(
        !invoke(root.path(), &["annotate", id, "--label", "bad key=x"])?
            .status
            .success()
    );
    assert_eq!(ok(root.path(), &["show", id])?, original);
    Ok(())
}
