use ladyshell::tasks;
use serde_json::Value;
use std::{path::Path, process::Command};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(p: &Path, args: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(p).args(args).output()?;
    if !o.status.success() {
        return Err(String::from_utf8(o.stderr)?.into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
#[test]
fn task_worktrees_are_isolated_and_repeated_start_preserves_work() -> Result {
    let root = tempfile::tempdir()?;
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("code"), "base")?;
    git(&repo, &["add", "code"])?;
    git(&repo, &["commit", "-m", "base"])?;
    let a = tasks::prepare(&repo, &root.path().join("task-a"), "agent/a", "HEAD")?;
    let b = tasks::prepare(&repo, &root.path().join("task-b"), "agent/b", "HEAD")?;
    let ap = Path::new(a["project"].as_str().ok_or("path")?);
    std::fs::write(ap.join("code"), "agent a")?;
    let bp = Path::new(b["project"].as_str().ok_or("path")?);
    assert_eq!(std::fs::read_to_string(bp.join("code"))?, "base");
    let again = tasks::prepare(&repo, &root.path().join("task-a"), "agent/a", "HEAD")?;
    assert_eq!(again["project"], a["project"]);
    assert_eq!(std::fs::read_to_string(ap.join("code"))?, "agent a");
    assert!(tasks::prepare(&repo, &root.path().join("task-a"), "agent/other", "HEAD").is_err());
    Ok(())
}
#[test]
fn preview_rejects_exports_outside_owned_state() -> Result {
    let d = tempfile::tempdir()?;
    assert!(tasks::inspect(d.path(), Some(Path::new("/tmp/unrelated-export"))).is_err());
    Ok(())
}
#[test]
fn completion_refuses_active_session_before_deletion() -> Result {
    let d = tempfile::tempdir()?;
    let state = d.path().join("state");
    ladyshell::state::create_directory(&state)?;
    let _lease = ladyshell::state::SessionLock::acquire(&state, false)?;
    let error = tasks::complete(&state)
        .err()
        .ok_or("accepted active session")?;
    assert!(error.to_string().contains(".sessions"));
    Ok(())
}
#[test]
fn task_status_retains_publication_even_after_teardown() -> Result {
    let d = tempfile::tempdir()?;
    let state = d.path().join("state");
    ladyshell::state::create_directory(&state)?;
    std::fs::write(
        state.join("publication.json"),
        br#"{"schema_version":1,"confirmed":false,"commit":"retained"}"#,
    )?;
    std::fs::write(state.join("destroy.json"), br#"{"deleted":true}"#)?;
    let s: Value = tasks::status(&state)?;
    assert_eq!(s["publication"]["confirmed"], false);
    assert_eq!(s["cleanup"]["deleted"], true);
    Ok(())
}
#[test]
fn task_checkout_disables_executable_filters_and_preserves_blob_bytes() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(
        repo.join(".gitattributes"),
        "code filter=trap text eol=crlf\n",
    )?;
    std::fs::write(repo.join("code"), "line\n")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let sentinel = root.path().join("executed");
    let script = root.path().join("filter-trap");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf executed > '{}'\ncat\n",
            sentinel.display()
        ),
    )?;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))?;
    for suffix in ["smudge", "clean", "process"] {
        git(
            &repo,
            &[
                "config",
                &format!("filter.trap.{suffix}"),
                script.to_str().ok_or("script")?,
            ],
        )?;
    }
    git(&repo, &["config", "filter.trap.required", "true"])?;
    git(&repo, &["config", "submodule.recurse", "true"])?;
    let task = tasks::prepare(&repo, &root.path().join("task"), "agent/filtered", "HEAD")?;
    let project = Path::new(task["project"].as_str().ok_or("project")?);
    assert!(!sentinel.exists());
    assert_eq!(std::fs::read(project.join("code"))?, b"line\n");
    tasks::prepare(&repo, &root.path().join("task"), "agent/filtered", "HEAD")?;
    assert!(!sentinel.exists());
    let path = root.path().join("task/task.json");
    let mut interrupted: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    interrupted["phase"] = serde_json::json!("preparing");
    std::fs::write(&path, serde_json::to_vec(&interrupted)?)?;
    assert!(tasks::prepare(&repo, &root.path().join("task"), "agent/filtered", "HEAD").is_err());
    Ok(())
}
#[test]
fn task_submodule_entries_are_refused_without_materializing_worktrees() -> Result {
    let root = tempfile::tempdir()?;
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("code"), "base")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let head = git(&repo, &["rev-parse", "HEAD"])?;
    git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head},submodule"),
        ],
    )?;
    git(&repo, &["commit", "-m", "submodule"])?;
    let task = root.path().join("task");
    assert!(tasks::prepare(&repo, &task, "agent/submodule", "HEAD").is_err());
    assert!(!task.join("project").exists());
    Ok(())
}

#[test]
fn task_restart_inputs_keep_the_original_working_directory() -> Result {
    let root = tempfile::tempdir()?;
    let repo = root.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("code"), "base")?;
    git(&repo, &["add", "code"])?;
    git(&repo, &["commit", "-m", "base"])?;
    let directory = root.path().join("task");
    let desired = ladyshell::request::Desired {
        project: repo,
        state: directory.join("state"),
        config: "missing-task-fixture.ncl".into(),
        resources: "resources".into(),
        codex: "runtime/codex".into(),
        codex_code_mode_host: "runtime/code-host".into(),
        lock: Some("runtime/lock.json".into()),
        ladybom: Some("runtime/report.json".into()),
        mission: "dev".into(),
    };
    assert!(tasks::start(desired, &directory, "agent/restart", "HEAD").is_err());
    let task: Value = serde_json::from_slice(&std::fs::read(directory.join("task.json"))?)?;
    for key in [
        "config",
        "resources",
        "codex",
        "codex_code_mode_host",
        "lock",
        "ladybom",
    ] {
        let path = Path::new(task["inputs"][key].as_str().ok_or("input path")?);
        assert!(
            path.is_absolute(),
            "{key} lost its original working directory"
        );
        assert!(path.starts_with(std::env::current_dir()?));
    }
    Ok(())
}

#[test]
fn integration_refresh_refuses_stack_membership_before_successor_or_sync() -> Result {
    use serde_json::json;
    let root = tempfile::tempdir()?;
    let parent = root.path().join("parent");
    let child = root.path().join("child");
    let stack = root.path().join("stack");
    for dir in [&parent, &child] {
        ladyshell::state::create_directory(dir)?;
    }
    let p1 = "a".repeat(40);
    let p2 = "b".repeat(40);
    let publication = |head: &str| json!({"confirmed":true,"base":"0".repeat(40),"commit":head});
    std::fs::write(
        parent.join("publication.json"),
        serde_json::to_vec(&publication(&p1))?,
    )?;
    let binding = json!({"schema_version":1,"stack":stack,"parent":parent,"parent_head":p1});
    std::fs::write(
        child.join("stack-binding.json"),
        serde_json::to_vec(&binding)?,
    )?;
    assert!(ladyshell::stacks::ensure_current(&child).is_ok());
    for phase in ["current", "stale", "interrupted", "root"] {
        if phase == "stale" {
            std::fs::write(
                parent.join("publication.json"),
                serde_json::to_vec(&publication(&p2))?,
            )?;
            assert!(ladyshell::stacks::ensure_current(&child).is_err());
        }
        if phase == "interrupted" {
            std::fs::write(
                child.join("refresh.json"),
                br#"{"phase":"prepared","next_directory":"never-created"}"#,
            )?;
        }
        if phase == "root" {
            std::fs::write(
                child.join("stack-binding.json"),
                serde_json::to_vec(
                    &json!({"schema_version":1,"stack":stack,"parent":null,"parent_head":null}),
                )?,
            )?;
        }
        let before = std::fs::read(child.join("stack-binding.json"))?;
        let directories = std::fs::read_dir(root.path())?.count();
        let error = tasks::refresh(&child, "HEAD")
            .err()
            .ok_or("refresh detached stack")?;
        assert!(error.to_string().contains("restack"), "{phase}: {error}");
        assert_eq!(std::fs::read(child.join("stack-binding.json"))?, before);
        assert_eq!(std::fs::read_dir(root.path())?.count(), directories);
        assert!(!child.join("exports").exists());
        assert!(!child.join("destroy.json").exists());
    }
    assert_eq!(
        std::fs::read(child.join("refresh.json"))?,
        br#"{"phase":"prepared","next_directory":"never-created"}"#
    );
    Ok(())
}

#[test]
fn retained_inspection_reports_verified_sizes_and_unavailable_worker_evidence() -> Result {
    use serde_json::json;
    let t = tempfile::tempdir()?;
    let state = t.path().join("state");
    let project = t.path().join("project");
    let export = state.join("exports/saved");
    ladyshell::state::create_directory(&state)?;
    std::fs::create_dir(&project)?;
    std::fs::create_dir_all(export.join("project"))?;
    std::fs::write(project.join("code"), "before")?;
    let original = ladyshell::snapshot::inventory(&project)?;
    let records = |inventory: ladyshell::snapshot::Inventory| -> Value {
        Value::Object(
            inventory
                .into_iter()
                .map(|(p, e)| (p, json!({"sha256":e.sha256,"executable":e.executable})))
                .collect(),
        )
    };
    std::fs::write(export.join("project/code"), "after")?;
    std::fs::write(export.join("project/new"), "new")?;
    let exported = records(ladyshell::snapshot::inventory(&export.join("project"))?);
    std::fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(&json!({"schema_version":2,"sandbox_id":"fixture","files":exported}))?,
    )?;
    std::fs::write(
        state.join("state.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"sandbox_name":"fixture","sandbox_id":"fixture","owner":"fixture","policy_hash":"fixture","codex_binary":"fixture","desired_hash":"fixture","image_id":"fixture","project_snapshot":export.join("project"),"build_dir":t.path(),"context":{"gateway":"fixture","workspace":"default"},"desired_inputs":{"project":project},"host_sources":records(original),"sync":{"destination":"exports"},"last_sync":export}),
        )?,
    )?;
    let report = tasks::inspect(&state, Some(&export))?;
    assert_eq!(report["scope"], "verified_retained_export");
    assert_eq!(report["included_files"]["code"]["size"], 5);
    assert_eq!(report["diff_size"]["before_bytes"], 6);
    assert_eq!(report["diff_size"]["after_bytes"], 8);
    assert_eq!(report["diff_size"]["byte_delta"], 2);
    assert_eq!(report["worker_exclusions"]["available"], false);
    std::fs::write(
        state.join("checkout-pending.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"sandbox_id":"fixture","project":project,"export":export,"backup":state.join("backup"),"remote":exported,"changes":[]}),
        )?,
    )?;
    let pending = tasks::inspect(&state, Some(&export))?;
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["diff_size"]["available"], false);
    std::fs::remove_file(state.join("checkout-pending.json"))?;
    std::fs::write(export.join("project/code"), "tampered")?;
    assert!(tasks::inspect(&state, Some(&export)).is_err());
    Ok(())
}
#[test]
fn live_inspection_refuses_active_sessions_without_contacting_worker() -> Result {
    let t = tempfile::tempdir()?;
    let directory = t.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    let _lease = ladyshell::state::SessionLock::acquire(&directory, false)?;
    assert!(tasks::inspect_live(&directory).is_err());
    Ok(())
}
#[test]
fn inspection_cli_and_worker_protocol_are_explicit_and_compatible() -> Result {
    use ladyshell_cli::cli::validate_args;
    for args in [
        vec!["ladyshell", "task", "inspect", "--state", "state", "--live"],
        vec!["ladyshell", "snapshot-preview", "--exclude", "custom"],
        vec!["ladyshell", "snapshot-list"],
        vec!["ladyshell", "snapshot-file", "code"],
    ] {
        assert!(validate_args(&args).is_ok(), "{args:?}");
    }
    assert!(validate_args(&[
        "ladyshell",
        "task",
        "inspect",
        "--state",
        "state",
        "--live",
        "--export",
        "export"
    ])
    .is_err());
    assert!(ladyshell::sync::parse_preview(
        br#"{"schema_version":1,"schema_version":1,"entries":{}}"#,
        &[]
    )
    .is_err());
    assert!(ladyshell::sync::parse_preview(br#"{"schema_version":1,"entries":{".env":{"disposition":"included","kind":"file","size":1}}}"#, &[]).is_err());
    Ok(())
}
