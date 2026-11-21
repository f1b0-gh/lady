//! Publish preserved work without repeating the agent execution.
use crate::{
    error::{ensure, Error, Result},
    files,
    publish::{Git, Options, Prepared},
    snapshot,
    sources::{FileRecord, Snapshot},
    state,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, path::Path};
pub fn run(directory: &Path, export: &Path, options: &Options) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::run::ensure_no_pending(&lock.directory)?;
    crate::publication_recovery::ensure_available(&lock.directory)?;
    let mut current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let export = files::absolute(export)?;
    ensure!(
        export.starts_with(
            lock.directory
                .join(state::text(&current["sync"], "destination")?)
        ),
        "Select an export retained by this state"
    );
    let manifest = state::read(&export.join("manifest.json"))?
        .ok_or_else(|| invalid("Export is missing".into()))?;
    ensure!(
        manifest["sandbox_id"] == current["sandbox_id"],
        "Export belongs to another sandbox"
    );
    crate::publication_checks::export_digest(&export)?;
    current["last_sync"] = json!(export);
    let preview = crate::checkout::run(&current, &lock.directory, false)?;
    ensure!(
        preview["conflicts"] == json!([]),
        "Retained export conflicts with host edits; inspect before publishing"
    );
    let project = Path::new(state::text(&current["desired_inputs"], "project")?);
    let prepared = Prepared::for_retained(project, options)?;
    if let Some(checks) = prepared.policy().and_then(|p| p.checks.as_ref()) {
        if crate::publication_checks::revalidate(&export, checks).is_err() {
            crate::publication_checks::verify(&current, &lock.directory, &export, checks)?;
        }
    }
    let applied = crate::checkout::run(&current, &lock.directory, true)?;
    ensure!(
        applied["conflicts"] == json!([]),
        "Host changed while applying retained export"
    );
    let excluded = crate::sync::exclusions(&current)?;
    let actual: Snapshot = snapshot::inventory_filtered(project, &excluded)?
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
    let exported: Snapshot = serde_json::from_value(manifest["files"].clone())?;
    ensure!(
        actual == exported,
        "Host files differ from retained export; unrelated edits are preserved"
    );
    let git = Git::new(project)?;
    let spec = crate::config::Sources {
        include: vec![],
        exclude: excluded,
    };
    let mut base = Snapshot::new();
    for entry in git
        .call(&["ls-tree", "-r", "-z", "HEAD"])?
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
    {
        let entry = std::str::from_utf8(entry).map_err(|e| invalid(e.to_string()))?;
        let (meta, path) = entry
            .split_once('\t')
            .ok_or_else(|| invalid("Invalid tree entry".into()))?;
        snapshot::validate_path(path)?;
        if crate::sources::excluded(path, &spec) {
            continue;
        }
        let fields: Vec<_> = meta.split_whitespace().collect();
        ensure!(
            fields.len() == 3 && fields[1] == "blob" && ["100644", "100755"].contains(&fields[0]),
            "Only regular file snapshots can be republished"
        );
        base.insert(
            path.into(),
            FileRecord {
                sha256: files::hash(&git.call(&["cat-file", "blob", fields[2]])?),
                executable: fields[0] == "100755",
            },
        );
    }
    let paths: BTreeSet<_> = base.keys().chain(exported.keys()).collect();
    let changes:Vec<_>=paths.into_iter().filter(|p|base.get(*p)!=exported.get(*p)).map(|p|json!({"path":p,"action":if !exported.contains_key(p){"delete"}else if !base.contains_key(p){"add"}else{"modify"}})).collect();
    prepared.publish(
        &json!({"export":export,"applied":true,"conflicts":[],"changes":changes}),
        &lock.directory,
    )
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
