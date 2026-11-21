use ladyshell::{
    publication_recovery,
    publish::{Options, Prepared},
    snapshot,
    sources::FileRecord,
};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(path: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()?;
    if !o.status.success() {
        return Err(String::from_utf8_lossy(&o.stderr).into_owned().into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
#[test]
fn accepted_but_unconfirmed_push_is_reconciled_idempotently_without_remote_config() -> Result {
    let _serial = SERIAL.lock().map_err(|e| e.to_string())?;
    let t = tempfile::tempdir()?;
    let project = t.path().join("project");
    let remote = t.path().join("remote");
    let state = t.path().join("state");
    fs::create_dir(&project)?;
    fs::create_dir(&remote)?;
    ladyshell::state::create_directory(&state)?;
    git(&remote, &["init", "--bare"])?;
    git(&project, &["init", "-b", "draft"])?;
    git(&project, &["config", "user.name", "test"])?;
    git(&project, &["config", "user.email", "test@example.invalid"])?;
    fs::write(project.join("a"), "before")?;
    git(&project, &["add", "a"])?;
    git(&project, &["commit", "-m", "base"])?;
    git(
        &project,
        &["remote", "add", "origin", remote.to_str().ok_or("remote")?],
    )?;
    let prepared = Prepared::new(
        &project,
        &Options {
            remote: "origin".into(),
            branch: "draft".into(),
            message: "export".into(),
            policy: None,
        },
    )?;
    let export = t.path().join("export");
    fs::create_dir_all(export.join("project"))?;
    fs::write(export.join("project/a"), "after")?;
    fs::write(project.join("a"), "after")?;
    let files: std::collections::BTreeMap<_, _> = snapshot::inventory(&export.join("project"))?
        .into_iter()
        .map(|(p, e)| {
            (
                p,
                FileRecord {
                    sha256: e.sha256,
                    executable: e.executable,
                },
            )
        })
        .collect();
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(&json!({"schema_version":2,"files":files}))?,
    )?;
    let report = json!({"applied":true,"conflicts":[],"export":export,"changes":[{"path":"a","action":"modify"}]});
    let mut receipt = prepared.publish(&report, &state)?;
    receipt["phase"] = json!("push_unconfirmed");
    receipt["confirmed"] = json!(false);
    fs::write(
        state.join("publication.json"),
        serde_json::to_vec(&receipt)?,
    )?;
    git(
        &project,
        &["remote", "set-url", "origin", "/nonexistent/changed"],
    )?;
    let status = publication_recovery::status(&state)?;
    assert_eq!(status["remote_status"], "commit");
    let first = publication_recovery::reconcile(&state, false, false)?;
    assert_eq!(first["phase"], "published");
    let second = publication_recovery::reconcile(&state, false, false)?;
    assert_eq!(first, second);
    assert!(git(&project, &["status", "--porcelain"])?.is_empty());
    Ok(())
}
#[test]
fn corrupted_and_legacy_pending_receipts_fail_closed() -> Result {
    let _serial = SERIAL.lock().map_err(|e| e.to_string())?;
    let t = tempfile::tempdir()?;
    let directory = t.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    fs::write(directory.join("publication.json"), b"{bad")?;
    assert!(publication_recovery::ensure_available(&directory).is_err());
    assert!(publication_recovery::reconcile(&directory, true, false).is_err());
    fs::write(
        directory.join("publication.json"),
        serde_json::to_vec(&json!({"schema_version":1,"confirmed":false,"commit":"a".repeat(40)}))?,
    )?;
    assert!(publication_recovery::ensure_available(&directory).is_err());
    assert!(publication_recovery::reconcile(&directory, true, false).is_err());
    let receipt: Value = publication_recovery::reconcile(&directory, false, true)?;
    assert_eq!(receipt["phase"], "abandoned");
    publication_recovery::ensure_available(&directory)?;
    Ok(())
}
