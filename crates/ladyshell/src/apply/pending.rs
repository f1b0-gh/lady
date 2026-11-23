use super::{invalid, Operation, Phase};
use crate::{
    error::{ensure, Result},
    plan, state,
};
use serde_json::Value;
use std::path::Path;

pub(crate) fn broker(directory: &Path) -> Result<Value> {
    let original = state::read(&directory.join("operation.json"))?
        .ok_or_else(|| invalid("Original provisioning operation missing".into()))?;
    let op: Operation = serde_json::from_value(original.clone())?;
    let desired = op.desired_inputs.as_ref().ok_or_else(|| {
        invalid(
            "Original broker inputs missing; resume the original apply before cancellation".into(),
        )
    })?;
    ensure!(
        op.schema_version == 2
            && op.phase != Phase::Complete
            && !op.restore_only
            && desired["evaluated"]["config"]["image"]["profile"] == "openshell-worker-v1"
            && plan::digest(desired)? == op.desired_hash,
        "Cancellation requires an original incomplete broker provisioning operation"
    );
    let profile: crate::storage::Profile =
        serde_json::from_value(desired["evaluated"]["config"]["storage"].clone())?;
    profile.intents(&op.owner, state::text(&desired["context"], "workspace")?)?;
    ensure!(
        op.sandbox_name == format!("er-{}", &op.owner[..12]),
        "Provisioning resource name differs from original owner"
    );
    let current = state::load(directory)?;
    ensure!(
        current == op.state_before || (op.phase == Phase::Publishing && current == op.result),
        "State changed since original provisioning attempt"
    );
    ensure!(
        match op.phase {
            Phase::Planned => op.build.is_none() && op.result.is_none(),
            Phase::Built | Phase::Validating => op.build.is_some() && op.result.is_none(),
            Phase::Publishing => op.build.is_some() && op.result.is_some(),
            Phase::Complete => false,
        },
        "Invalid provisioning phase evidence"
    );
    if let Some(build) = &op.build {
        ensure!(
            build["image_profile"] == "openshell-worker-v1",
            "Original build is not a broker profile"
        );
    }
    if let Some(result) = &op.result {
        ensure!(
            result["sandbox_name"] == op.sandbox_name
                && result["owner"] == op.owner
                && result["desired_hash"] == op.desired_hash
                && result.get("desired_inputs") == Some(desired)
                && result.get("storage") == op.build.as_ref().and_then(|b| b.get("storage")),
            "Publication result differs from original broker attempt"
        );
    }
    Ok(original)
}

#[cfg(test)]
mod tests {
    use crate::{environment_lock::atomic_json, error::Result, plan, state};
    use serde_json::{json, Value};
    fn operation() -> Result<Value> {
        let desired = json!({"context":{"gateway":"test","workspace":"default"},"evaluated":{"config":{"image":{"profile":"openshell-worker-v1"},"storage":{"control":{"bytes":65536,"inodes":32},"artifacts":{"bytes":65536,"inodes":32},"incoming":{"bytes":65536,"inodes":32}}}}});
        Ok(
            json!({"schema_version":2,"desired_hash":plan::digest(&desired)?,"desired_inputs":desired,
            "state_before":null,"observed_before":{},"phase":"planned","owner":"a".repeat(32),"sandbox_name":"er-aaaaaaaaaaaa",
            "restore_only":false,"build":null,"result":null}),
        )
    }
    #[test]
    fn cancellation_selects_only_the_original_incomplete_operation() -> Result<()> {
        let root = tempfile::tempdir()?;
        let lock = state::StateLock::acquire(&root.path().join("state"))?;
        let original = operation()?;
        atomic_json(&lock.directory.join("operation.json"), &original)?;
        assert_eq!(super::broker(&lock.directory)?, original);
        for (field, value) in [
            ("desired_hash", json!("changed")),
            ("phase", json!("complete")),
            ("desired_inputs", Value::Null),
            ("owner", json!("changed")),
            ("sandbox_name", json!("someone-else")),
            ("restore_only", json!(true)),
            ("state_before", json!({"other":"state"})),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            atomic_json(&lock.directory.join("operation.json"), &changed)?;
            assert!(super::broker(&lock.directory).is_err(), "accepted {field}");
        }
        Ok(())
    }
}
