//! Explicit bulk deletion from independently verified host states, never from
//! cached catalogue rows. Each current identity retains the single-state checks.
use crate::{
    associations::{self, Association},
    error::{Error, Result},
    instances,
    request::{Destroy, DestroyAll},
    state,
};
use serde_json::{json, Value};
use std::path::Path;

pub fn all(args: &DestroyAll) -> Result<Value> {
    all_at(&associations::registry()?, args)
}

/// Dry-run is read-only and provider-free. Execution is best effort across
/// independent states, with explicit per-instance failures and no implicit purge.
pub fn all_at(registry: &Path, args: &DestroyAll) -> Result<Value> {
    let inventory = instances::list_at(registry)?;
    let mut report = json!({"schema_version":1,"scope":"registered_local_current_states",
        "dry_run":args.dry_run,"discard_work":args.discard_work,
        "inventory_complete":inventory["complete"],"complete":inventory["complete"],
        "diagnostics":inventory["diagnostics"],"candidates":[],"blocked":[],"results":[],
        "deleted":0,"already_deleted":inventory["excluded_deleted"]});
    let entries = inventory["instances"]
        .as_array()
        .ok_or_else(|| invalid("Invalid inventory".into()))?;
    let mut candidates = Vec::new();
    let mut blocked = Vec::new();
    for entry in entries {
        if entry["kind"] == "current" {
            candidates.push(entry.clone());
        } else {
            blocked.push(json!({"instance":entry,"reason":"retained_identity_requires_explicit_recovery",
                "message":"Previous identity lacks ownership evidence or retained export configuration: automatic deletion refused"}));
        }
    }
    report["candidates"] = json!(candidates);
    report["blocked"] = json!(blocked);
    if !blocked.is_empty() {
        report["complete"] = false.into();
    }
    // Parse and validate every candidate before the first external effect. No
    // fallible conversion may abort a batch after earlier deletions succeeded.
    let mut plan = Vec::new();
    for entry in candidates {
        match expected(&entry) {
            Ok(expected) => plan.push((entry, expected)),
            Err(error) => {
                report["complete"] = false.into();
                report["inventory_complete"] = false.into();
                if let Some(diagnostics) = report["diagnostics"].as_array_mut() {
                    diagnostics.push(json!({"code":"invalid_deletion_candidate","instance":entry,"message":error.to_string()}));
                }
            }
        }
    }
    // Partial discovery cannot authorize deleting an apparently complete set.
    if args.dry_run || report["inventory_complete"] != true {
        return Ok(report);
    }
    let mut results = Vec::new();
    let mut deleted = 0;
    for (entry, expected) in plan {
        let request = Destroy {
            state: expected.directory.clone(),
            discard_work: args.discard_work,
        };
        match super::run_expected(&request, &expected) {
            Ok(receipt) => {
                deleted += 1;
                results.push(json!({"instance":entry,"outcome":"deleted","receipt":receipt}));
            }
            Err(error) => {
                report["complete"] = false.into();
                results
                    .push(json!({"instance":entry,"outcome":"failed","error":error.to_string()}));
            }
        }
    }
    report["results"] = json!(results);
    report["deleted"] = json!(deleted);
    Ok(report)
}
fn expected(entry: &Value) -> Result<Association> {
    let expected = Association {
        schema_version: 1,
        project: state::text(entry, "project")?.into(),
        directory: state::text(entry, "directory")?.into(),
        name: state::text(entry, "sandbox_name")?.into(),
        sandbox_id: state::text(entry, "sandbox_id")?.into(),
        gateway: state::text(entry, "gateway")?.into(),
        workspace: state::text(entry, "workspace")?.into(),
    };
    for identifier in [&expected.name, &expected.gateway, &expected.workspace] {
        crate::config::identifier(identifier)?;
    }
    Ok(expected)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
