//! Host task worktrees, retained work inspection, and owned sandbox completion.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    files, state,
};
use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, path::Path};
fn git(root: &Path, args: &[&str]) -> Result<String> {
    let mut git = crate::publish::Git::new(root)?;
    git.configure(vec![
        "submodule.recurse=false".into(),
        "fetch.recurseSubmodules=false".into(),
        "core.autocrlf=false".into(),
    ]);
    git.text(args)
}
pub fn prepare(repository: &Path, directory: &Path, branch: &str, base: &str) -> Result<Value> {
    let repository = std::fs::canonicalize(repository)?;
    let directory = files::absolute(directory)?;
    ensure!(
        !directory.starts_with(&repository),
        "Task directory must be outside the source checkout"
    );
    ensure!(
        !base.is_empty() && !base.starts_with('-') && !base.contains(['\0', '\n', '\r']),
        "Invalid task base"
    );
    git(&repository, &["check-ref-format", "--branch", branch])?;
    let base = git(
        &repository,
        &["rev-parse", "--verify", &format!("{base}^{{commit}}")],
    )?;
    let lock = state::StateLock::acquire(&directory)?;
    let path = lock.directory.join("task.json");
    let project = lock.directory.join("project");
    let intent = json!({"schema_version":1,"repository":repository,"project":project,"branch":branch,"base":base,"state":lock.directory.join("state"),"phase":"preparing"});
    if let Some(previous) = state::read(&path)? {
        for key in ["schema_version", "repository", "project", "branch", "base"] {
            ensure!(
                previous[key] == intent[key],
                "Task already belongs to another request: {key}"
            );
        }
        if project.exists() {
            ensure!(
                previous["phase"] != "preparing",
                "Task checkout preparation was interrupted; inspect retained work before recovery"
            );
            ensure!(
                git(&project, &["symbolic-ref", "--short", "HEAD"])? == branch,
                "Task checkout branch changed"
            );
            return Ok(previous);
        }
    } else {
        ensure!(!project.exists(), "Task checkout path already exists");
        atomic_json(&path, &intent)?;
    }
    // Inspect before creating a branch; task snapshots do not materialize links or
    // fetch submodule objects on the credential-bearing host.
    let objects = crate::publish::Git::new(&repository)?;
    let listing = objects.call(&["ls-tree", "-r", "-z", &base])?;
    let mut blobs = Vec::new();
    for row in listing.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let row = std::str::from_utf8(row).map_err(|e| invalid(e.to_string()))?;
        let (meta, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("Invalid task tree entry".into()))?;
        crate::snapshot::validate_path(path)?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        ensure!(fields.len()==3&&fields[1]=="blob"&&["100644","100755"].contains(&fields[0]),"Tasks support regular file snapshots only; submodules and links require an explicit workflow");
        blobs.push((path.to_owned(), fields[0].to_owned(), fields[2].to_owned()));
    }
    git(
        &repository,
        &[
            "worktree",
            "add",
            "--no-checkout",
            "-b",
            branch,
            project
                .to_str()
                .ok_or_else(|| invalid("Non-UTF8 task path".into()))?,
            &base,
        ],
    )?;
    // Populate the index without a checkout, then write exact object bytes. Even
    // built-in text/eol/encoding attributes must not transform the snapshot.
    git(&project, &["read-tree", &base])?;
    for (path, mode, oid) in blobs {
        let target = project.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, objects.call(&["cat-file", "blob", &oid])?)?;
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(if mode == "100755" { 0o700 } else { 0o600 }),
        )?;
    }
    let mut ready = intent;
    ready["phase"] = json!("prepared");
    atomic_json(&path, &ready)?;
    Ok(ready)
}
pub fn start(
    mut desired: crate::request::Desired,
    directory: &Path,
    branch: &str,
    base: &str,
) -> Result<Value> {
    let mut task = prepare(&desired.project, directory, branch, base)?;
    desired.project = state::text(&task, "project")?.into();
    desired.state = state::text(&task, "state")?.into();
    task["inputs"] = json!({"config":desired.config,"resources":desired.resources,"codex":desired.codex,"codex_code_mode_host":desired.codex_code_mode_host,"lock":desired.lock,"ladybom":desired.ladybom,"mission":desired.mission});
    for key in [
        "config",
        "resources",
        "codex",
        "codex_code_mode_host",
        "lock",
        "ladybom",
    ] {
        if let Some(path) = task["inputs"][key].as_str() {
            task["inputs"][key] = json!(files::absolute(Path::new(path))?);
        }
    }
    atomic_json(&directory.join("task.json"), &task)?;
    crate::app::make_plan(&desired)?;
    let current = crate::app::apply(&desired)?;
    task["phase"] = json!("active");
    task["sandbox_id"] = current["sandbox_id"].clone();
    atomic_json(&directory.join("task.json"), &task)?;
    Ok(task)
}
pub fn status(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current = state::read(&lock.directory.join("state.json"))?;
    let publication = state::read(&lock.directory.join("publication.json"))?;
    let cleanup = state::read(&lock.directory.join("destroy.json"))?;
    let review = state::read(&lock.directory.join("review.json"))?;
    Ok(
        json!({"state":current,"publication":publication,"review":review,"cleanup":cleanup,"checkout_recovery_pending":lock.directory.join("checkout-pending.json").exists()}),
    )
}
fn selected_export(
    current: &Value,
    directory: &Path,
    selected: Option<&Path>,
) -> Result<std::path::PathBuf> {
    let export = match selected {
        Some(p) => files::absolute(p)?,
        None => state::text(current, "last_sync")?.into(),
    };
    let retained = directory.join(state::text(&current["sync"], "destination")?);
    ensure!(
        export.starts_with(&retained) && export != retained,
        "Select a retained export belonging to this state"
    );
    files::open_directory(&export)?;
    let manifest = state::read(&export.join("manifest.json"))?
        .ok_or_else(|| invalid("Export manifest missing".into()))?;
    crate::continuous::host::ensure_ready(current)?;
    crate::continuous::host::verify_export(current, &manifest)?;
    ensure!(
        manifest["sandbox_id"] == current["sandbox_id"],
        "Export belongs to another sandbox"
    );
    crate::publication_checks::export_digest(&export)?;
    Ok(export)
}
pub fn inspect(directory: &Path, selected: Option<&Path>) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let export = selected_export(&current, &lock.directory, selected)?;
    let mut candidate = current.clone();
    candidate["last_sync"] = json!(export);
    let mut report = crate::checkout::run(&candidate, &lock.directory, false)?;
    let pending = report["pending"] == true;
    let included = crate::snapshot::inventory_filtered(
        &export.join("project"),
        &crate::sync::exclusions(&current)?,
    )?;
    let project = Path::new(state::text(&current["desired_inputs"], "project")?);
    let mut before_bytes = 0usize;
    let mut after_bytes = 0usize;
    if let Some(changes) = report["changes"].as_array_mut().filter(|_| !pending) {
        for change in changes {
            let path = change["path"]
                .as_str()
                .ok_or_else(|| invalid("Missing change path".into()))?;
            let before = if change["action"] == "add" {
                0
            } else {
                crate::snapshot::local_bytes(project, path)?.0.size
            };
            let after = included.get(path).map_or(0, |entry| entry.size);
            before_bytes += before;
            after_bytes += after;
            change["before_bytes"] = json!(before);
            change["after_bytes"] = json!(after);
        }
    }
    report["scope"] = json!("verified_retained_export");
    report["included_reason"] =
        json!("Verified regular files admitted by the current source policy");
    report["included_bytes"] = json!(included.values().map(|entry| entry.size).sum::<usize>());
    report["included_files"] = json!(included);
    report["selected_export"] = json!(export);
    report["diff_size"] = if pending {
        json!({"available":false,"reason":"Checkout recovery journal is pending; its changes may already be partially applied"})
    } else {
        json!({"available":true,"basis":"checkout_changes", "before_bytes":before_bytes,"after_bytes":after_bytes,"byte_delta": after_bytes as i64 - before_bytes as i64})
    };
    report["worker_exclusions"] = json!({"available":false,"reason":"Retained exports contain no excluded-worker metadata; use task inspect --live"});
    report["worker_unsupported_types"] =
        json!({"available":false,"reason":"Retained exports contain only verified regular files"});
    report["checks"] = json!(state::read(&export.join("checks.json"))?);
    report["excluded_patterns"] = json!(crate::sync::exclusions(&current)?);
    report["history_mode"] = json!("file_snapshot");
    report["unsupported"] = json!([
        "sandbox Git/Jujutsu history",
        "submodule objects",
        "LFS object transfer"
    ]);
    Ok(report)
}
pub fn salvage(directory: &Path, selected: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::publication_recovery::ensure_available(&lock.directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let export = selected_export(&current, &lock.directory, Some(selected))?;
    let mut candidate = current;
    candidate["last_sync"] = json!(export);
    crate::checkout::run(&candidate, &lock.directory, true)
}
pub fn complete(directory: &Path) -> Result<Value> {
    let verifiers = crate::publication_checks::cleanup(directory)?;
    if state::read(&directory.join("state.json"))?
        .is_some_and(|s| s["kind"] == "host_restack_candidate")
    {
        let lock = state::StateLock::acquire(directory)?;
        let _lease = state::SessionLock::acquire(&lock.directory, true)?;
        let result = json!({"kind":"host_restack_candidate","sandbox_created":false,"evidence_retained":true,"complete":true,"verifier_cleanup":verifiers});
        atomic_json(&lock.directory.join("completion.json"), &result)?;
        return Ok(result);
    }

    // destroy owns the exclusive lease and always exports before deleting.
    let cleanup = crate::destroy::run(&crate::request::Destroy {
        state: directory.to_owned(),
        discard_work: false,
    })?;
    let mut result = status(directory)?;
    result["cleanup"] = cleanup;
    result["verifier_cleanup"] = verifiers;
    Ok(result)
}
pub fn refresh(directory: &Path, upstream: &str) -> Result<Value> {
    crate::continuous::host::execution_directory(directory)?;
    ensure!(
        !upstream.is_empty()
            && !upstream.starts_with('-')
            && !upstream.contains(['\0', '\n', '\r']),
        "Invalid upstream revision"
    );
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    ensure!(
        state::read(&lock.directory.join("stack-binding.json"))?.is_none(),
        "Stack-bound tasks cannot refresh automatically; restack explicitly without detaching the dependency"
    );
    crate::run::ensure_no_pending(&lock.directory)?;
    crate::publication_recovery::ensure_available(&lock.directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    ensure!(
        crate::continuous::host::session(&current)?.is_none(),
        "Use cs checkpoint/refresh for a continuous task"
    );
    let backend = crate::openshell::Backend::new(&current["context"])?;
    let captured = crate::sync::sync(&current, &lock.directory, &backend, true)?;
    let report = crate::checkout::run(&captured, &lock.directory, true)?;
    ensure!(
        report["conflicts"] == json!([]),
        "Preserved unfinished changes; resolve checkout conflicts before refresh"
    );
    let project = Path::new(state::text(&current["desired_inputs"], "project")?);
    ensure!(
        git(
            project,
            &["status", "--porcelain=v1", "--untracked-files=all"]
        )?
        .is_empty(),
        "Unfinished edits were retained and synced; publish or checkpoint them before refresh"
    );
    let base = git(project, &["rev-parse", "HEAD"])?;
    let target = git(
        project,
        &["rev-parse", "--verify", &format!("{upstream}^{{commit}}")],
    )?;
    // Resolve content without executing hooks, checkout filters or merge drivers.
    // Fast-forward is the supported automatic refresh; divergent histories keep
    // their exact export and require explicit stack restacking first.
    git(project, &["merge-base", "--is-ancestor", &base, &target]).map_err(|e| {
        e.context(
            "Upstream is divergent; retained work is unchanged. Restack explicitly before refresh",
        )
    })?;
    let parent = lock
        .directory
        .parent()
        .ok_or_else(|| invalid("Managed task parent is missing".into()))?;
    let task = state::read(&parent.join("task.json"))?
        .ok_or_else(|| invalid("Refresh requires a managed task created with task start".into()))?;
    ensure!(
        task["state"] == json!(lock.directory),
        "Managed task state binding changed"
    );
    let inputs = &task["inputs"];
    let optional = |key: &str| -> Result<Option<std::path::PathBuf>> {
        if inputs[key].is_null() {
            Ok(None)
        } else {
            Ok(Some(state::text(inputs, key)?.into()))
        }
    };
    let next_directory = parent.join(format!("refresh-{}", &target[..12]));
    let branch = refresh_branch(parent, state::text(&task, "branch")?, &target)?;
    let desired = crate::request::Desired {
        project: project.to_owned(),
        state: next_directory.join("state"),
        config: state::text(inputs, "config")?.into(),
        resources: state::text(inputs, "resources")?.into(),
        codex: state::text(inputs, "codex")?.into(),
        codex_code_mode_host: state::text(inputs, "codex_code_mode_host")?.into(),
        lock: optional("lock")?,
        ladybom: optional("ladybom")?,
        mission: state::text(inputs, "mission")?.into(),
    };
    let mut receipt = json!({"schema_version":1,"base":base,"target":target,"export":captured["last_sync"],"phase":"prepared","next_directory":next_directory});
    atomic_json(&lock.directory.join("refresh.json"), &receipt)?;
    let next = start(desired, &next_directory, &branch, &target)?;
    receipt["phase"] = json!("refreshed");
    receipt["next_task"] = next;
    atomic_json(&lock.directory.join("refresh.json"), &receipt)?;
    drop(_lease);
    drop(lock);
    match complete(directory) {
        Ok(cleanup) => receipt["previous_cleanup"] = cleanup,
        Err(e) => receipt["cleanup_error"] = json!(e.to_string()),
    }
    atomic_json(&directory.join("refresh.json"), &receipt)?;
    Ok(receipt)
}
fn refresh_branch(directory: &Path, branch: &str, target: &str) -> Result<String> {
    // Flat refs avoid Git's branch/directory collision. The digest identifies the
    // request; prepare's retained binding still owns the checkout and retry.
    let inputs =
        json!({"schema_version":1,"task_directory":directory,"branch":branch,"target":target});
    Ok(format!(
        "ladyshell-refresh-{}",
        files::hash(&serde_json::to_vec(&inputs)?)
    ))
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

/// Explicit current-worker inspection, independent of retained exports.
pub fn inspect_live(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let backend = crate::openshell::Backend::new(&current["context"])?;
    let preview = crate::sync::observe_preview(&current, &backend)?;
    let blocking_paths: Vec<_> = preview
        .entries
        .iter()
        .filter(|(_, entry)| {
            !matches!(
                entry.disposition,
                ladybom::inventory::Disposition::Included
                    | ladybom::inventory::Disposition::ExcludedByPolicy
            )
        })
        .map(|(path, _)| path)
        .collect();
    Ok(
        json!({"scope":"live_worker_metadata", "blocking_paths":blocking_paths, "verified_source_bytes":false,
        "preview":preview, "excluded_subtree_counts":null,
        "diff_size":{"available":false,"reason":"Metadata alone cannot establish content changes; export and inspect verified bytes"},
        "warning":"File exclusions are not a complete secret detector. This observation does not authorize publication."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn refresh_fixture() -> Result<(tempfile::TempDir, std::path::PathBuf, Value, String)> {
        let root = tempfile::tempdir()?;
        let repository = root.path().join("repo");
        std::fs::create_dir(&repository)?;
        git(&repository, &["init", "-b", "main"])?;
        git(&repository, &["config", "user.name", "Fixture"])?;
        git(
            &repository,
            &["config", "user.email", "fixture@example.invalid"],
        )?;
        std::fs::write(repository.join("code"), "base")?;
        git(&repository, &["add", "."])?;
        git(&repository, &["commit", "-m", "base"])?;
        let original = prepare(&repository, &root.path().join("task"), "agent/perf", "HEAD")?;
        std::fs::write(repository.join("code"), "upstream")?;
        git(&repository, &["commit", "-am", "upstream"])?;
        let target = git(&repository, &["rev-parse", "HEAD"])?;
        Ok((root, repository, original, target))
    }

    #[test]
    fn refresh_successor_worktree_preserves_original_and_retry_edits() -> Result<()> {
        let (root, repository, original, target) = refresh_fixture()?;
        let directory = root.path().join("task");
        let branch = refresh_branch(&directory, "agent/perf", &target)?;
        let next_directory = directory.join(format!("refresh-{}", &target[..12]));
        let successor = prepare(&repository, &next_directory, &branch, &target)?;
        let project = Path::new(state::text(&successor, "project")?);
        assert_eq!(std::fs::read(project.join("code"))?, b"upstream");
        std::fs::write(project.join("code"), "unfinished successor edits")?;
        let repeated = refresh_branch(&directory, "agent/perf", &target)?;
        assert_eq!(repeated, branch);
        let again = prepare(&repository, &next_directory, &repeated, &target)?;
        assert_eq!(again, successor);
        assert_eq!(
            std::fs::read(project.join("code"))?,
            b"unfinished successor edits"
        );
        let original_project = Path::new(state::text(&original, "project")?);
        assert_eq!(std::fs::read(original_project.join("code"))?, b"base");
        assert_eq!(
            git(original_project, &["symbolic-ref", "--short", "HEAD"])?,
            "agent/perf"
        );
        assert_eq!(
            git(&repository, &["rev-parse", "agent/perf"])?,
            original["base"]
        );
        assert_eq!(git(&repository, &["rev-parse", &branch])?, target);
        assert_eq!(
            git(&repository, &["symbolic-ref", "--short", "HEAD"])?,
            "main"
        );
        assert_eq!(std::fs::read(repository.join("code"))?, b"upstream");
        Ok(())
    }

    #[test]
    fn refresh_successor_ref_occupancy_refuses_unrelated_request() -> Result<()> {
        let (root, repository, original, target) = refresh_fixture()?;
        let directory = root.path().join("task");
        let branch = refresh_branch(&directory, "agent/perf", &target)?;
        // Even the expected target and generated name cannot authorize adoption
        // of a checkout bound to another task directory.
        let unrelated_directory = root.path().join("unrelated-task");
        let unrelated = prepare(&repository, &unrelated_directory, &branch, &target)?;
        let unrelated_project = Path::new(state::text(&unrelated, "project")?);
        std::fs::write(unrelated_project.join("code"), "unrelated unfinished edits")?;
        let unrelated_receipt = std::fs::read(unrelated_directory.join("task.json"))?;
        let refs = git(&repository, &["show-ref"])?;
        let worktrees = git(&repository, &["worktree", "list", "--porcelain"])?;
        let next_directory = directory.join(format!("refresh-{}", &target[..12]));
        assert!(prepare(&repository, &next_directory, &branch, &target).is_err());
        let retained = std::fs::read(next_directory.join("task.json"))?;
        assert!(prepare(&repository, &next_directory, &branch, &target).is_err());
        assert_eq!(std::fs::read(next_directory.join("task.json"))?, retained);
        assert_eq!(git(&repository, &["show-ref"])?, refs);
        assert_eq!(
            git(&repository, &["worktree", "list", "--porcelain"])?,
            worktrees
        );
        assert_eq!(git(&repository, &["rev-parse", &branch])?, target);
        assert_eq!(
            std::fs::read(unrelated_project.join("code"))?,
            b"unrelated unfinished edits"
        );
        assert_eq!(
            std::fs::read(unrelated_directory.join("task.json"))?,
            unrelated_receipt
        );
        assert!(!next_directory.join("project").exists());
        assert_eq!(std::fs::read(repository.join("code"))?, b"upstream");
        assert_eq!(
            std::fs::read(Path::new(state::text(&original, "project")?).join("code"))?,
            b"base"
        );
        Ok(())
    }

    #[test]
    fn refresh_successor_generations_distinguish_tasks_branches_and_full_targets() -> Result<()> {
        let (root, repository, original, target) = refresh_fixture()?;
        let directory = root.path().join("task");
        let first = refresh_branch(&directory, "agent/perf", &target)?;
        assert!(!first.contains('/'));
        assert!(first.starts_with("ladyshell-refresh-"));
        assert_eq!(first.len(), "ladyshell-refresh-".len() + 64);
        let other_task = refresh_branch(&root.path().join("other-task"), "agent/perf", &target)?;
        let other_branch = refresh_branch(&directory, "agent/other", &target)?;
        let mut same_prefix_target = target.clone();
        let last = if target.ends_with('0') { "1" } else { "0" };
        same_prefix_target.replace_range(target.len() - 1.., last);
        let full_target = refresh_branch(&directory, "agent/perf", &same_prefix_target)?;
        let earlier = refresh_branch(&directory, "agent/perf", state::text(&original, "base")?)?;
        let branches = [&first, &other_task, &other_branch, &full_target, &earlier];
        for (index, branch) in branches.iter().enumerate() {
            assert!(!branches[..index].contains(branch));
        }
        let first_directory = directory.join(format!("refresh-{}", &target[..12]));
        prepare(&repository, &first_directory, &first, &target)?;
        let next = refresh_branch(&first_directory, &first, &target)?;
        assert_ne!(next, first);
        prepare(
            &repository,
            &first_directory.join("refresh-next"),
            &next,
            &target,
        )?;
        prepare(
            &repository,
            &root.path().join("other-task/refresh"),
            &other_task,
            &target,
        )?;
        prepare(
            &repository,
            &root.path().join("other-branch"),
            &other_branch,
            &target,
        )?;
        assert_eq!(
            git(&repository, &["rev-parse", "agent/perf"])?,
            original["base"]
        );
        Ok(())
    }

    #[test]
    fn refresh_successor_keeps_failed_legacy_preparation_binding() -> Result<()> {
        let (root, repository, _original, target) = refresh_fixture()?;
        let directory = root.path().join("task");
        let next_directory = directory.join(format!("refresh-{}", &target[..12]));
        let legacy_branch = format!("agent/perf/refresh-{}", &target[..12]);
        assert!(prepare(&repository, &next_directory, &legacy_branch, &target).is_err());
        let retained = std::fs::read(next_directory.join("task.json"))?;
        let refs = git(&repository, &["show-ref"])?;
        let branch = refresh_branch(&directory, "agent/perf", &target)?;
        let error = prepare(&repository, &next_directory, &branch, &target)
            .err()
            .ok_or_else(|| invalid("Accepted another preparation request".into()))?;
        assert!(error.to_string().contains("another request: branch"));
        assert_eq!(std::fs::read(next_directory.join("task.json"))?, retained);
        assert_eq!(git(&repository, &["show-ref"])?, refs);
        assert!(!next_directory.join("project").exists());
        Ok(())
    }

    #[test]
    fn refresh_status_does_not_execute_content_filters() -> Result<()> {
        let root = tempfile::tempdir()?;
        let repository = root.path().join("repo");
        std::fs::create_dir(&repository)?;
        git(&repository, &["init", "-b", "main"])?;
        git(&repository, &["config", "user.name", "Fixture"])?;
        git(
            &repository,
            &["config", "user.email", "fixture@example.invalid"],
        )?;
        std::fs::write(repository.join("code"), "base")?;
        git(&repository, &["add", "."])?;
        git(&repository, &["commit", "-m", "base"])?;
        let sentinel = root.path().join("executed");
        let trap = root.path().join("trap");
        std::fs::write(
            &trap,
            format!(
                "#!/bin/sh\nprintf executed > '{}'\ncat\n",
                sentinel.display()
            ),
        )?;
        std::fs::set_permissions(&trap, std::fs::Permissions::from_mode(0o700))?;
        std::fs::write(repository.join(".gitattributes"), "code filter=trap\n")?;
        let trap = trap
            .to_str()
            .ok_or_else(|| invalid("Non-UTF8 fixture path".into()))?;
        for suffix in ["clean", "smudge", "process"] {
            git(
                &repository,
                &["config", &format!("filter.trap.{suffix}"), trap],
            )?;
        }
        std::fs::write(repository.join("code"), "updated after checkout")?;
        // Exercise the exact status helper used after refresh retains the export.
        git(
            &repository,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        ensure!(
            !sentinel.exists(),
            "Refresh status executed a project filter"
        );
        Ok(())
    }
}
