use ladyshell::{
    checkout, snapshot,
    sources::{FileRecord, Snapshot},
};
use serde_json::json;
use std::{fs, path::Path};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn provisioning_state_cannot_checkout_or_refresh_a_task() -> Result {
    let root = tempfile::tempdir()?;
    let parent = root.path().join("parent");
    ladyshell::state::create_directory(&parent)?;
    let _lease = ladyshell::state::SessionLock::acquire(&parent, false)?;
    let child = parent.join("replacement");
    ladyshell::state::create_directory(&child)?;
    fs::write(child.join("continuous-staging.json"), b"{}")?;
    // No state/export/backend is available: admission must refuse before any
    // lookup or effect, independently of the parent's distinct session lease.
    let error = checkout::run(&json!({}), &child, true)
        .err()
        .ok_or("checkout admitted")?;
    assert!(error.to_string().contains("provisioning state"));
    let error = ladyshell::tasks::refresh(&child, "HEAD")
        .err()
        .ok_or("refresh admitted")?;
    assert!(error.to_string().contains("provisioning state"));
    assert!(!child.join("checkout-pending.json").exists());
    assert!(!child.join("refresh.json").exists());
    Ok(())
}
fn records(root: &Path) -> ladyshell::error::Result<Snapshot> {
    Ok(snapshot::inventory(root)?
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
        .collect())
}
#[test]
fn root_files_nested_additions_deletions_and_local_work_survive() -> Result {
    let t = tempfile::tempdir()?;
    let host = t.path().join("host");
    let export = t.path().join("export");
    let state = t.path().join("state");
    fs::create_dir(&host)?;
    fs::create_dir_all(export.join("project/reports"))?;
    fs::create_dir(&state)?;
    fs::write(host.join("README.md"), "old")?;
    fs::write(host.join("gone"), "remove")?;
    fs::write(host.join("local"), "original")?;
    let base = records(&host)?;
    fs::write(host.join("local"), "host edit")?;
    fs::write(export.join("project/README.md"), "new")?;
    fs::write(export.join("project/local"), "original")?;
    fs::write(export.join("project/reports/a.md"), "report")?;
    let remote = records(&export.join("project"))?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(&json!({"schema_version":2,"sandbox_id":"s","files":remote}))?,
    )?;
    let s = json!({"sandbox_id":"s","host_sources":base,"last_sync":export,"desired_inputs":{"project":host,"evaluated":{"config":{"sources":{"include":[],"exclude":[]}}}}});
    let preview = checkout::run(&s, &state, false)?;
    assert_eq!(preview["conflicts"], json!([]));
    assert_eq!(fs::read_to_string(host.join("README.md"))?, "old");
    checkout::run(&s, &state, true)?;
    assert_eq!(fs::read_to_string(host.join("README.md"))?, "new");
    assert_eq!(fs::read_to_string(host.join("local"))?, "host edit");
    assert_eq!(fs::read_to_string(host.join("reports/a.md"))?, "report");
    assert!(!host.join("gone").exists());
    let next = ladyshell::state::read(&state.join("state.json"))?.ok_or("missing state")?;
    assert_eq!(checkout::run(&next, &state, false)?["changes"], json!([]));
    Ok(())
}
#[test]
fn conflict_prevents_all_writes_and_symlinks_are_refused() -> Result {
    let t = tempfile::tempdir()?;
    let host = t.path().join("host");
    let export = t.path().join("export");
    let state = t.path().join("state");
    fs::create_dir(&host)?;
    fs::create_dir_all(export.join("project"))?;
    fs::create_dir(&state)?;
    fs::write(host.join("a"), "base")?;
    let base = records(&host)?;
    fs::write(host.join("a"), "local")?;
    fs::write(export.join("project/a"), "remote")?;
    fs::write(export.join("project/b"), "new")?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_id":"s","files":records(&export.join("project"))?}),
        )?,
    )?;
    let s = json!({"sandbox_id":"s","host_sources":base,"last_sync":export,"desired_inputs":{"project":host}});
    assert_eq!(checkout::run(&s, &state, false)?["conflicts"], json!(["a"]));
    assert!(checkout::run(&s, &state, true).is_err());
    assert!(!host.join("b").exists());
    fs::remove_file(host.join("a"))?;
    std::os::unix::fs::symlink("/etc/passwd", host.join("a"))?;
    assert!(checkout::run(&s, &state, true).is_err());
    Ok(())
}
#[test]
fn interrupted_import_resumes_and_backup_metadata_cannot_overwrite_project_data() -> Result {
    let t = tempfile::tempdir()?;
    let host = t.path().join("host");
    let export = t.path().join("export");
    let state = t.path().join("state");
    fs::create_dir(&host)?;
    fs::create_dir_all(export.join("project"))?;
    fs::create_dir(&state)?;
    for name in ["a", "receipt.json"] {
        fs::write(host.join(name), "before")?;
        fs::write(export.join("project").join(name), "after")?;
    }
    let base = records(&host)?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_id":"s","files":records(&export.join("project"))?}),
        )?,
    )?;
    let s = json!({"sandbox_id":"s","host_sources":base,"last_sync":export,"desired_inputs":{"project":host}});
    let result = checkout::run(&s, &state, true)?;
    let backup = Path::new(result["backup"].as_str().ok_or("no backup")?);
    assert_eq!(
        fs::read_to_string(backup.join("project/receipt.json"))?,
        "before"
    );
    // Reproduce a crash after the first file was written, before state publication.
    fs::write(host.join("receipt.json"), "before")?;
    fs::copy(
        backup.join("receipt.json"),
        state.join("checkout-pending.json"),
    )?;
    let mut persisted = s.clone();
    persisted["schema_version"] = json!(2);
    for key in [
        "sandbox_name",
        "policy_hash",
        "codex_binary",
        "owner",
        "desired_hash",
        "image_id",
        "project_snapshot",
        "build_dir",
    ] {
        persisted[key] = json!("fixture");
    }
    persisted["context"] = json!({"gateway":"invalid/gateway","workspace":"default"});
    fs::set_permissions(&state, {
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o700)
    })?;
    fs::write(state.join("state.json"), serde_json::to_vec(&persisted)?)?;
    ladyshell::app::sync(&ladyshell_cli::cli::SyncArgs {
        state: Some(state.clone()),
        dry_run: false,
        apply: true,
        export: false,
        json: false,
    })?;
    assert_eq!(fs::read_to_string(host.join("receipt.json"))?, "after");
    assert!(!state.join("checkout-pending.json").exists());
    Ok(())
}

#[test]
fn executable_mode_and_project_exclusions_are_preserved() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir()?;
    let host = t.path().join("host");
    let export = t.path().join("export");
    let state = t.path().join("state");
    fs::create_dir(&host)?;
    fs::create_dir_all(export.join("project"))?;
    fs::create_dir(&state)?;
    fs::write(host.join("private.log"), "retain")?;
    let base = records(&host)?;
    fs::write(export.join("project/run"), "#!/bin/sh\n")?;
    fs::set_permissions(
        export.join("project/run"),
        fs::Permissions::from_mode(0o755),
    )?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_id":"s","files":records(&export.join("project"))?}),
        )?,
    )?;
    let s = json!({"sandbox_id":"s","host_sources":base,"last_sync":export,"desired_inputs":{"project":host,"evaluated":{"config":{"sources":{"exclude":["private.log"]}}}}});
    checkout::run(&s, &state, true)?;
    assert_eq!(fs::read_to_string(host.join("private.log"))?, "retain");
    assert_ne!(
        fs::metadata(host.join("run"))?.permissions().mode() & 0o111,
        0
    );
    Ok(())
}
#[test]
fn replacement_preserves_private_host_permissions() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let t = tempfile::tempdir()?;
    let host = t.path().join("host");
    let export = t.path().join("export");
    let state = t.path().join("state");
    fs::create_dir(&host)?;
    fs::create_dir_all(export.join("project"))?;
    fs::create_dir(&state)?;
    fs::write(host.join("notes.txt"), "before")?;
    fs::set_permissions(host.join("notes.txt"), fs::Permissions::from_mode(0o600))?;
    let base = records(&host)?;
    fs::write(export.join("project/notes.txt"), "after")?;
    fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_id":"s","files":records(&export.join("project"))?}),
        )?,
    )?;
    let s = json!({"sandbox_id":"s","host_sources":base,"last_sync":export,"desired_inputs":{"project":host}});
    let result = checkout::run(&s, &state, true)?;
    assert_eq!(
        fs::metadata(host.join("notes.txt"))?.permissions().mode() & 0o777,
        0o600
    );
    let backup = Path::new(result["backup"].as_str().ok_or("no backup")?);
    fs::write(host.join("notes.txt"), "before")?;
    fs::set_permissions(host.join("notes.txt"), fs::Permissions::from_mode(0o400))?;
    fs::copy(
        backup.join("receipt.json"),
        state.join("checkout-pending.json"),
    )?;
    assert!(checkout::run(&s, &state, true).is_err());
    assert_eq!(
        fs::metadata(host.join("notes.txt"))?.permissions().mode() & 0o777,
        0o400
    );
    Ok(())
}
