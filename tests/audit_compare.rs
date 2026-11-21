mod audit_support;
use audit_support::*;
use serde_json::{json, Value};
use std::{error::Error, process::Command};
#[test]
fn comparison_is_deterministic_and_conditions_require_revalidation() -> Result<(), Box<dyn Error>> {
    let old = fixture(true)?;
    let new = fixture(true)?;
    edit_metadata(
        new.path(),
        "/config_sha256",
        json!(hash(b"different config")),
    )?;
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(["audit", "compare"])
            .arg(old.path())
            .arg(new.path())
            .output()
    };
    let output = run()?;
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, run()?.stdout);
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["conditions_changed"], true);
    assert_eq!(
        value["requires_revalidation"],
        json!(["src-handler-missing-check"])
    );
    assert_eq!(value["confirmed_transferred"], false);
    Ok(())
}

#[test]
fn comparison_keeps_unresolved_candidates_from_archived_attempts() -> Result<(), Box<dyn Error>> {
    let dir = fixture(true)?;
    let root = dir.path();
    let mut coverage: Value =
        serde_json::from_slice(&std::fs::read(root.join("coverage-ledger.json"))?)?;
    let unit = &mut coverage[0];
    let attempt = json!({"wave":1,"status":"candidate","agent_id":"old-hunter","reviewed_paths":["src/handler.c"],"local_checks":[{"agent_id":"old-hunter","reviewed_paths":["src/handler.c"],"invariant":"ownership","method":"source","result":"candidate","artifact":null}],"result_fingerprints":["pending-candidate"],"unresolved":["verification budget exhausted"],"reassignment_reason":"new review"});
    unit["attempts"] = json!([attempt]);
    unit["wave"] = json!(2);
    unit["status"] = json!("covered");
    unit["result_fingerprints"] = json!([]);
    replace_document(root, "coverage-ledger.json", &coverage)?;
    replace_document(root, "findings.json", &json!([]))?;
    edit_metadata(root, "/links", json!([]))?;
    edit_metadata(
        root,
        "/invocations",
        json!([{"id":"hunter","role":"hunter","status":"finished"},{"id":"old-hunter","role":"hunter","status":"finished"},{"id":"verifier","role":"verifier","status":"finished"}]),
    )?;
    let result = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "compare"])
        .arg(root)
        .arg(root)
        .output()?;
    assert!(result.status.success(), "{:?}", result);
    let value: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(value["prior_gaps"], json!([coverage[0]["coverage_id"]]));
    assert_eq!(value["requires_revalidation"], json!(["pending-candidate"]));
    Ok(())
}
