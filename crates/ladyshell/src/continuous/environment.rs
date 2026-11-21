//! Compatibility projection of host-resolved construction inputs.
use super::invalid;
use crate::error::{ensure, Result};
use serde_json::{json, Value};

/// Consume the native resolver's result, never a sandbox's compatibility claim.
/// Preparation currently binds all its source inputs; preserve that restriction.
pub fn identity(desired: &Value) -> Result<String> {
    ensure!(
        desired["schema_version"] == 2,
        "Unsupported resolved environment"
    );
    ensure!(
        desired["dependency_scan"]["complete"] == true
            && desired["dependency_scan"]["missing"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && desired["dependency_inventory"]["complete"] == true,
        "Environment compatibility is unknown: dependency evidence is incomplete"
    );
    for name in [
        "context",
        "evaluated",
        "environment_lock",
        "artifacts",
        "dependency_inventory",
    ] {
        ensure!(
            desired[name].is_object(),
            "Missing resolved environment input: {name}"
        );
    }
    ensure!(
        desired["environment_lock"]["schema_version"] == 1,
        "Unsupported environment lock"
    );
    let mut artifacts = serde_json::Map::new();
    for name in ["ladyshell", "codex", "codex-code-mode-host"] {
        let hash = desired["artifacts"][name]["sha256"]
            .as_str()
            .ok_or_else(|| super::invalid("Resolved runtime artifact is missing"))?;
        ensure!(
            super::model::digest(hash),
            "Resolved runtime digest is invalid"
        );
        artifacts.insert(name.into(), json!(hash));
    }
    crate::plan::digest(&json!({"schema_version":1,"context":desired["context"],
        "evaluated":desired["evaluated"],"lock":desired["environment_lock"],
        "artifacts":artifacts,"dependencies":desired["dependency_inventory"],
        "preparation":desired["dependency_preparation"]}))
}
