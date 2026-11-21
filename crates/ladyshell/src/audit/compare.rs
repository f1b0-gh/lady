use super::{model::VerifiedRun, verify};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub fn compare(old: &VerifiedRun, new: &VerifiedRun) -> Value {
    let a: BTreeMap<_, _> = old.sources.files.iter().map(|f| (&f.path, f)).collect();
    let b: BTreeMap<_, _> = new.sources.files.iter().map(|f| (&f.path, f)).collect();
    let source_paths: BTreeSet<_> = a.keys().chain(b.keys()).copied().collect();
    let changed_sources: Vec<_> = source_paths
        .into_iter()
        .filter(|p| a.get(p) != b.get(p))
        .collect();
    let before: BTreeMap<_, _> = old
        .findings
        .iter()
        .filter_map(|f| f["fingerprint"].as_str().map(|id| (id, f)))
        .collect();
    let after: BTreeMap<_, _> = new
        .findings
        .iter()
        .filter_map(|f| f["fingerprint"].as_str().map(|id| (id, f)))
        .collect();
    let fingerprints: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    let conditions_changed = old.metadata.config_sha256 != new.metadata.config_sha256
        || old.metadata.toolchain_sha256 != new.metadata.toolchain_sha256
        || old.metadata.method_sha256 != new.metadata.method_sha256
        || old.metadata.profile != new.metadata.profile
        || old.metadata.scope_paths != new.metadata.scope_paths;
    let changes: Vec<_> = fingerprints.iter().filter_map(|id| {
        if before.get(id) == after.get(id) { None }
        else { Some(json!({"fingerprint":id,"change":if !before.contains_key(id) {"added"} else if !after.contains_key(id) {"removed"} else {"modified"}})) }
    }).collect();
    // There is no sound per-finding dependency graph yet: invalidate conservatively.
    let mut requires_revalidation: BTreeSet<_> = fingerprints
        .into_iter()
        .filter(|id| {
            conditions_changed
                || !changed_sources.is_empty()
                || before.get(id) != after.get(id)
                || before
                    .get(id)
                    .is_some_and(|f| f["verdict"] == "needs_validation")
        })
        .collect();
    for run in [old, new] {
        let resolved = resolved_fingerprints(run);
        for unit in &run.coverage {
            requires_revalidation.extend(candidates(unit).filter(|f| !resolved.contains(f)));
        }
    }
    let resolved = resolved_fingerprints(old);
    let prior_gaps: Vec<_> = old
        .coverage
        .iter()
        .filter(|u| verify::coverage_pending(u) || candidates(u).any(|f| !resolved.contains(f)))
        .map(|u| &u["coverage_id"])
        .collect();
    json!({"schema_version":1,"operation":"compare","old":verify::summary(old),"new":verify::summary(new),"changed_sources":changed_sources,"conditions_changed":conditions_changed,"coverage_changed":old.coverage != new.coverage,"findings_changes":changes,"requires_revalidation":requires_revalidation,"prior_gaps":prior_gaps,"confirmed_transferred":false})
}

fn resolved_fingerprints(run: &VerifiedRun) -> BTreeSet<&str> {
    run.findings
        .iter()
        .filter(|f| f["verdict"] != "needs_validation")
        .filter_map(|f| f["fingerprint"].as_str())
        .collect()
}

fn candidates(unit: &Value) -> impl Iterator<Item = &str> {
    std::iter::once(unit)
        .chain(unit["attempts"].as_array().into_iter().flatten())
        .flat_map(|attempt| {
            attempt["result_fingerprints"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
}
