//! Pure reconciliation: never executes tools or grants permissions from scan results.
use crate::{
    config::Permissions,
    error::{ensure, Error, Result},
    files, policy,
};
use serde::Serialize;
use serde_json::{json, Value};
pub fn digest(value: &impl Serialize) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(value)?))
}
pub fn plan(desired: &Value, state: Option<&Value>, observed: &Value) -> Result<Value> {
    let desired_hash = digest(desired)?;
    let mut actions = Vec::new();
    let sandbox = observed.get("sandbox").filter(|s| !s.is_null());
    if let Some(state) = state {
        ensure!(
            state["context"] == desired["context"],
            "Gateway/workspace mismatch: separate state is required"
        );
        if let Some(sandbox) = sandbox {
            ensure!(
                sandbox["id"].is_string() && sandbox["id"] == state["sandbox_id"],
                "Sandbox identity mismatch: adoption refused"
            );
        }
        if state["desired_hash"] != desired_hash {
            actions.push("build_image");
            if sandbox.is_some() {
                actions.extend(["retain_old_sandbox", "replace_sandbox"]);
            } else {
                actions.push("create_sandbox");
            }
        } else if observed["image_exists"] != true {
            actions.push("restore_image");
        }
        if let Some(sandbox) = sandbox {
            if sandbox["policy_hash"] != state["policy_hash"] {
                actions.push("policy_drift_review");
            }
            if sandbox["phase"] != "Ready" {
                actions.push("sandbox_not_ready");
            }
        } else if !actions.contains(&"create_sandbox") {
            actions.push("create_sandbox");
        }
    } else {
        ensure!(
            sandbox.is_none(),
            "Resource exists without recorded ownership"
        );
        actions.extend(["build_image", "create_sandbox"]);
    }
    let requests: Permissions = match desired.pointer("/evaluated/config/permissions") {
        Some(v) => serde_json::from_value(v.clone())?,
        None => Permissions::default(),
    };
    let permissions = policy::review(&requests);
    if permissions.iter().any(|r| r["authorized"] != true) {
        actions.push("permission_denied");
    }
    let scan = &desired["dependency_scan"];
    if scan["missing"].as_array().is_some_and(|a| !a.is_empty()) {
        actions.push("declare_missing_tools");
    }
    if scan["complete"] != true {
        actions.push("incomplete_dependency_scan");
    }
    let blocked = actions.iter().any(|a| {
        [
            "policy_drift_review",
            "sandbox_not_ready",
            "permission_denied",
            "declare_missing_tools",
            "incomplete_dependency_scan",
        ]
        .contains(a)
    });
    let changed: Vec<_> = desired
        .as_object()
        .ok_or_else(|| invalid("Plan inputs must be an object".into()))?
        .iter()
        .filter(|(key, value)| {
            state.is_none_or(|s| s.get("desired_inputs").and_then(|v| v.get(*key)) != Some(*value))
        })
        .map(|(key, _)| key.clone())
        .collect();
    Ok(
        json!({"schema_version":2,"desired":desired,"permissions":permissions,"dependency_scan":scan,"desired_hash":desired_hash,"state_hash":digest(&state)?,"observed":observed,"actions":actions,"blocked":blocked,"changed_inputs":changed,"preconditions_hash":digest(&json!({"state":state,"observed":observed}))?}),
    )
}
pub fn verify(
    saved: &Value,
    desired: &Value,
    state: Option<&Value>,
    observed: &Value,
) -> Result<()> {
    let current = plan(desired, state, observed)?;
    ensure!(*saved == current, "Stale plan: run plan again before apply");
    ensure!(
        current["blocked"] == false,
        "Plan blocked: inspect actions and dependency_scan"
    );
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
