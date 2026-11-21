//! Dependency tracking and conflict-aware restacking of host snapshot checkpoints.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    files,
    publish::Git,
    state,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
fn publication(directory: &Path) -> Result<Value> {
    let value = state::read(&directory.join("publication.json"))?
        .ok_or_else(|| invalid("Publication is missing".into()))?;
    ensure!(
        value["confirmed"] == true,
        "Stack checkpoints must be confirmed publications"
    );
    for key in ["base", "commit"] {
        crate::publish::oid(state::text(&value, key)?)?;
    }
    Ok(value)
}
fn manifest(directory: &Path) -> Result<Value> {
    Ok(state::read(&directory.join("stack.json"))?
        .unwrap_or_else(|| json!({"schema_version":1,"entries":[]})))
}
/// Check host-retained parent bindings while the caller holds this state's lock.
/// Keep the returned ancestor locks alive until the protected effect finishes.
pub fn guard(directory: &Path) -> Result<Vec<state::StateLock>> {
    let mut cursor = files::absolute(directory)?;
    let mut seen = BTreeSet::from([cursor.clone()]);
    let mut guards = Vec::new();
    while let Some(binding) = state::read(&cursor.join("stack-binding.json"))? {
        ensure!(binding["schema_version"] == 1, "Unsupported stack binding");
        ensure!(
            Path::new(state::text(&binding, "stack")?).is_absolute(),
            "Stack binding must name an absolute host state path"
        );
        if binding["parent"].is_null() {
            ensure!(
                binding["parent_head"].is_null(),
                "Root stack binding has a parent revision"
            );
            break;
        }
        let parent = Path::new(state::text(&binding, "parent")?);
        ensure!(
            parent.is_absolute(),
            "Stack parent must be an absolute host state path"
        );
        let parent = files::absolute(parent)?;
        ensure!(seen.insert(parent.clone()), "Stack dependency cycle");
        let lock = state::StateLock::acquire(&parent)?;
        let expected = state::text(&binding, "parent_head")?;
        crate::publish::oid(expected)?;
        ensure!(
            publication(&lock.directory)?["commit"] == expected,
            "Stack parent checkpoint changed; restack before publication, review or merge"
        );
        cursor = lock.directory.clone();
        guards.push(lock);
    }
    Ok(guards)
}
pub fn ensure_current(directory: &Path) -> Result<()> {
    let _guards = guard(directory)?;
    Ok(())
}
fn bind(source: &Path, stack: &Path, parent: Option<&Path>, head: Option<&str>) -> Result<()> {
    atomic_json(
        &source.join("stack-binding.json"),
        &json!({"schema_version":1,"stack":stack,"parent":parent,"parent_head":head}),
    )
}
pub fn record(directory: &Path, source: &Path, parent: Option<&Path>) -> Result<Value> {
    let source_lock = state::StateLock::acquire(source)?;
    let source = source_lock.directory.clone();
    ensure!(
        files::absolute(directory)? != source,
        "Stack directory must differ from its checkpoint state"
    );
    let lock = state::StateLock::acquire(directory)?;
    let parent = parent.map(files::absolute).transpose()?;
    ensure!(
        parent.as_ref() != Some(&source),
        "A stack checkpoint cannot depend on itself"
    );
    let mut ancestors = guard(&source)?;
    if let Some(parent) = &parent {
        if !ancestors.iter().any(|lock| lock.directory == *parent) {
            let parent_lock = state::StateLock::acquire(parent)?;
            let mut more = guard(parent)?;
            ancestors.push(parent_lock);
            ancestors.append(&mut more);
        }
    }
    let receipt = publication(&source)?;
    let git = Git::new(Path::new(state::text(&receipt, "project")?))?;
    git.call(&[
        "merge-base",
        "--is-ancestor",
        state::text(&receipt, "base")?,
        state::text(&receipt, "commit")?,
    ])?;
    let mut data = manifest(&lock.directory)?;
    ensure!(data["schema_version"] == 1, "Unsupported stack manifest");
    let entries = data["entries"]
        .as_array_mut()
        .ok_or_else(|| invalid("Invalid stack manifest".into()))?;
    let mut seen = BTreeSet::from([source.clone()]);
    let mut cursor = parent.clone();
    let mut parent_head = None;
    while let Some(path) = cursor {
        ensure!(seen.insert(path.clone()), "Stack dependency cycle");
        let entry = entries
            .iter()
            .find(|e| e["state"] == json!(path))
            .ok_or_else(|| invalid("Record the parent checkpoint first".into()))?;
        if parent_head.is_none() {
            parent_head = Some(publication(&path)?["commit"].clone());
        }
        cursor = entry["parent"].as_str().map(PathBuf::from);
    }
    let old = entries.iter().position(|e| e["state"] == json!(source));
    let base = if let Some(i) = old {
        ensure!(
            entries[i]["parent"] == json!(parent),
            "Changing a checkpoint dependency requires explicit restacking"
        );
        ensure!(
            receipt["base"] == entries[i]["head"] || receipt["commit"] == entries[i]["head"],
            "Checkpoint history was rewritten; restack explicitly"
        );
        entries[i]["base"].clone()
    } else {
        receipt["base"].clone()
    };
    if let Some(head) = &parent_head {
        ensure!(
            &base == head,
            "Child base is not the exact current parent checkpoint"
        );
    }
    let entry = json!({"state":source,"base":base,"head":receipt["commit"],"parent":parent,"parent_head":parent_head});
    if let Some(i) = old {
        entries[i] = entry;
    } else {
        entries.push(entry);
    }
    bind(
        &source,
        &lock.directory,
        parent.as_deref(),
        parent_head.as_ref().and_then(Value::as_str),
    )?;
    atomic_json(&lock.directory.join("stack.json"), &data)?;
    Ok(data)
}
pub fn status(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    status_locked(&lock.directory)
}
fn status_locked(directory: &Path) -> Result<Value> {
    let data = manifest(directory)?;
    ensure!(data["schema_version"] == 1, "Unsupported stack manifest");
    let entries = data["entries"]
        .as_array()
        .ok_or_else(|| invalid("Invalid stack manifest".into()))?;
    let mut results = Vec::new();
    let mut stale = BTreeSet::new();
    for entry in entries {
        let path = state::text(entry, "state")?;
        let current = publication(Path::new(path))?;
        let changed = current["commit"] != entry["head"];
        let parent_changed = if let Some(parent) = entry["parent"].as_str() {
            publication(Path::new(parent))?["commit"] != entry["parent_head"]
        } else {
            false
        };
        if changed || parent_changed {
            stale.insert(path.to_owned());
        }
        let mut result = entry.clone();
        result["current_head"] = current["commit"].clone();
        result["unrecorded_checkpoint"] = json!(changed);
        result["stale_parent"] = json!(parent_changed);
        results.push(result);
    }
    for _ in 0..results.len() {
        for entry in &mut results {
            if entry["parent"].as_str().is_some_and(|p| stale.contains(p)) {
                entry["stale_parent"] = json!(true);
                stale.insert(state::text(entry, "state")?.to_owned());
            }
        }
    }
    Ok(
        json!({"schema_version":1,"ready":stale.is_empty(),"entries":results,"history_mode":"host_snapshot_checkpoints"}),
    )
}
/// Materialize a new task candidate; the old worktree, signed commits and review
/// stay intact. Required checks and a new review are required before integration.
pub fn restack(directory: &Path, source: &Path) -> Result<Value> {
    restack_onto(directory, source, None)
}
pub fn restack_onto(directory: &Path, source: &Path, onto: Option<&Path>) -> Result<Value> {
    let source_lock = state::StateLock::acquire(source)?;
    let source = source_lock.directory.clone();
    ensure!(
        files::absolute(directory)? != source,
        "Stack directory must differ from its checkpoint state"
    );
    let lock = state::StateLock::acquire(directory)?;
    let data = manifest(&lock.directory)?;
    let entry = data["entries"]
        .as_array()
        .and_then(|a| a.iter().find(|e| e["state"] == json!(source)))
        .ok_or_else(|| invalid("Checkpoint is not in this stack".into()))?;
    let parent = match onto {
        Some(path) => files::absolute(path)?,
        None => PathBuf::from(state::text(entry, "parent")?),
    };
    ensure!(
        parent != source,
        "A stack checkpoint cannot depend on itself"
    );
    ensure!(
        data["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|e| e["state"] == json!(parent))),
        "Record the target parent checkpoint first"
    );
    let parent_lock = state::StateLock::acquire(&parent)?;
    let _ancestors = guard(&parent_lock.directory)?;
    let parent_publication = publication(&parent)?;
    let child = publication(&source)?;
    ensure!(
        child["commit"] == entry["head"],
        "Record the latest child checkpoint before restacking"
    );
    let project = Path::new(state::text(&child, "project")?);
    let git = Git::new(project)?;
    let new_base = state::text(&parent_publication, "commit")?;
    let mut merge = Git::new(project)?;
    let keys = match merge.call(&[
        "config",
        "--null",
        "--name-only",
        "--get-regexp",
        r"^merge\..*\.driver$",
    ]) {
        Ok(v) => v,
        Err(Error::ProcessExit { status, .. }) if status.code() == Some(1) => vec![],
        Err(e) => return Err(e),
    };
    let mut config = vec!["merge.default=text".into()];
    for key in keys.split(|b| *b == 0).filter(|k| !k.is_empty()) {
        config.push(format!(
            "{}=/usr/bin/false",
            std::str::from_utf8(key).map_err(|e| invalid(e.to_string()))?
        ));
    }
    merge.configure(config);
    let tree=merge.text(&["merge-tree","--write-tree","--no-messages","--merge-base",state::text(entry,"base")?,new_base,state::text(entry,"head")?]).map_err(|e|e.context("Restack has content conflicts or unavailable objects; original tasks and reviews remain unchanged"))?;
    crate::publish::oid(&tree)?;
    let identity = files::hash(&serde_json::to_vec(&json!([
        entry, parent, new_base, tree
    ]))?);
    let candidate = lock.directory.join(format!("restack-{}", &identity[..16]));
    let branch = format!("agent/restack-{}", &identity[..16]);
    let task = crate::tasks::prepare(project, &candidate, &branch, new_base)?;
    let candidate_state = candidate.join("state");
    let _candidate_lock = state::StateLock::acquire(&candidate_state)?;
    bind(
        &candidate_state,
        &lock.directory,
        Some(&parent),
        Some(new_base),
    )?;
    let export = candidate_state.join("exports/restacked");
    state::create_directory(&export)?;
    state::create_directory(&export.join("project"))?;
    for row in git
        .call(&["ls-tree", "-r", "-z", &tree])?
        .split(|b| *b == 0)
        .filter(|r| !r.is_empty())
    {
        let row = std::str::from_utf8(row).map_err(|e| invalid(e.to_string()))?;
        let (meta, path) = row
            .split_once('\t')
            .ok_or_else(|| invalid("Invalid restack tree entry".into()))?;
        crate::snapshot::validate_path(path)?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob" && ["100644", "100755"].contains(&fields[0]),
            "Restack supports regular file snapshots only"
        );
        let target = export.join("project").join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = git.call(&["cat-file", "blob", fields[2]])?;
        std::fs::write(&target, bytes)?;
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(if fields[0] == "100755" { 0o700 } else { 0o600 }),
        )?;
    }
    let records = |p: &Path| -> Result<Value> {
        Ok(Value::Object(
            crate::snapshot::inventory(p)?
                .into_iter()
                .map(|(p, e)| (p, json!({"sha256":e.sha256,"executable":e.executable})))
                .collect(),
        ))
    };
    let candidate_project = Path::new(state::text(&task, "project")?);
    let original =
        state::load(&source)?.ok_or_else(|| invalid("Source task state is missing".into()))?;
    let sandbox_id = format!("restack-{identity}");
    let candidate_value = json!({"schema_version":2,"kind":"host_restack_candidate","sandbox_name":format!("candidate-{}",&identity[..8]),"sandbox_id":sandbox_id,"owner":identity,"policy_hash":original["policy_hash"],"desired_hash":identity,"project_snapshot":export.join("project"),"build_dir":candidate,"desired_inputs":{"project":candidate_project,"evaluated":{"config":{"sources":{"exclude":[]}}}},"context":original["context"],"image_id":original["image_id"],"codex_binary":original["codex_binary"],"host_sources":records(candidate_project)?,"sync":{"destination":"exports","mode":"files"},"last_sync":export});
    atomic_json(
        &export.join("manifest.json"),
        &json!({"schema_version":2,"origin":"host_restack","sandbox_id":sandbox_id,"files":records(&export.join("project"))?}),
    )?;
    atomic_json(&candidate_state.join("state.json"), &candidate_value)?;
    let result = json!({"candidate":task,"export":export,"source_state":source,"old_head":entry["head"],"old_base":entry["base"],"new_base":new_base,"tree":tree,"requires_checks":true,"requires_new_review":true});
    atomic_json(&candidate.join("restack.json"), &result)?;
    Ok(result)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
