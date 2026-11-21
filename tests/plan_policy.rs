use ladyshell::{
    plan::{plan, verify},
    policy::{native_policy, validate_effective},
};
use serde_json::json;
#[test]
fn blocks_missing_tools_and_policy_drift_and_rejects_stale_plan(
) -> Result<(), Box<dyn std::error::Error>> {
    let desired = json!({"context":{"gateway":"g","workspace":"w"},"dependency_scan":{"complete":true,"missing":[]}});
    let observed = json!({"sandbox":null,"image_exists":false});
    let p = plan(&desired, None, &observed)?;
    assert_eq!(p["actions"], json!(["build_image", "create_sandbox"]));
    assert_eq!(p["blocked"], false);
    verify(&p, &desired, None, &observed)?;
    let mut missing = desired.clone();
    missing["dependency_scan"]["missing"] = json!([{"tool":"node"}]);
    assert_eq!(plan(&missing, None, &observed)?["blocked"], true);
    assert!(verify(&p, &missing, None, &observed).is_err());
    let state = json!({"context":desired["context"],"desired_hash":p["desired_hash"],"sandbox_id":"ours","policy_hash":"original"});
    let drift = json!({"image_exists":true,"sandbox":{"id":"ours","phase":"Ready","policy_hash":"changed"}});
    assert_eq!(plan(&desired, Some(&state), &drift)?["blocked"], true);
    let mut wrong = drift.clone();
    wrong["sandbox"]["id"] = json!("other");
    assert!(plan(&desired, Some(&state), &wrong).is_err());
    Ok(())
}
#[test]
fn native_policy_rejects_network_and_filesystem_widening() -> Result<(), Box<dyn std::error::Error>>
{
    let binary = format!("/nix/store/{}-ladyshell-codex/bin/codex", "a".repeat(32));
    let policy = native_policy(&binary)?;
    validate_effective(&policy, &binary)?;
    let mut altered = policy.clone();
    altered["network_policies"]["openai_codex"]["binaries"] = json!([{"path":"/bin/curl"}]);
    assert!(validate_effective(&altered, &binary).is_err());
    let mut altered = policy.clone();
    altered["filesystem_policy"]["read_write"] = json!(["/"]);
    assert!(validate_effective(&altered, &binary).is_err());
    let mut altered = policy;
    altered["landlock"]["compatibility"] = json!("best_effort");
    assert!(validate_effective(&altered, &binary).is_err());
    Ok(())
}
