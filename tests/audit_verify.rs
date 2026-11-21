mod audit_support;
use audit_support::*;
use serde_json::json;
use std::{error::Error, fs};

#[test]
fn verifies_partial_and_confirmed_runs_without_claiming_authenticity() -> Result<(), Box<dyn Error>>
{
    let dir = fixture(false)?;
    let result = command(&["verify"], dir.path())?;
    assert!(result.status.success(), "{:?}", result);
    let value: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(value["run_status"], "partial");
    assert_eq!(value["coverage_complete"], false);
    assert_eq!(value["authenticity_verified"], false);
    let dir = fixture(true)?;
    let result = command(&["verify"], dir.path())?;
    assert!(result.status.success(), "{:?}", result);
    let value: serde_json::Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(value["counts"]["confirmed"], 1);
    Ok(())
}

#[test]
fn refuses_orphans_shared_identity_tampering_and_false_completion() -> Result<(), Box<dyn Error>> {
    for (pointer, value) in [
        ("/schema_version", json!(99)),
        ("/links/0/coverage_ids", json!(["absent"])),
        ("/links/0/verifier_id", json!("hunter")),
        ("/links/0/artifact_ids", json!(["absent"])),
        ("/links/0/fingerprint", json!("absent")),
        ("/budget/invocations", json!(1)),
    ] {
        let dir = fixture(true)?;
        edit_metadata(dir.path(), pointer, value)?;
        assert!(
            !command(&["verify"], dir.path())?.status.success(),
            "{pointer}"
        );
    }
    let dir = fixture(false)?;
    edit_metadata(dir.path(), "/status", json!("complete"))?;
    assert!(!command(&["verify"], dir.path())?.status.success());
    let dir = fixture(true)?;
    fs::write(
        dir.path().join("agents/verifier/artifacts/proof.txt"),
        "tampered",
    )?;
    assert!(!command(&["verify"], dir.path())?.status.success());
    Ok(())
}

#[test]
fn refuses_ambiguous_json_links_and_unsafe_proofs() -> Result<(), Box<dyn Error>> {
    let dir = fixture(false)?;
    let meta = dir.path().join("run-metadata.json");
    let text = fs::read_to_string(&meta)?;
    fs::write(&meta, text.replacen('{', "{\"schema_version\":1,", 1))?;
    assert!(!command(&["verify"], dir.path())?.status.success());
    for hard in [false, true] {
        let dir = fixture(true)?;
        let proof = dir.path().join("agents/verifier/artifacts/proof.txt");
        let outside = dir.path().join("outside");
        fs::rename(&proof, &outside)?;
        if hard {
            fs::hard_link(outside, proof)?;
        } else {
            std::os::unix::fs::symlink(outside, proof)?;
        }
        assert!(!command(&["verify"], dir.path())?.status.success());
    }
    Ok(())
}

#[test]
fn archived_candidates_cannot_disappear_when_coverage_is_reassigned() -> Result<(), Box<dyn Error>>
{
    let dir = fixture(true)?;
    let root = dir.path();
    let mut coverage: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("coverage-ledger.json"))?)?;
    let unit = &mut coverage[0];
    let attempt = json!({"wave":1,"status":"candidate","agent_id":"old-hunter","reviewed_paths":["src/handler.c"],"local_checks":[{"agent_id":"old-hunter","reviewed_paths":["src/handler.c"],"invariant":"ownership","method":"source","result":"candidate","artifact":null}],"result_fingerprints":["orphan-candidate"],"unresolved":[],"reassignment_reason":"new review"});
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
    close_run(root)?;
    let result = command(&["verify"], root)?;
    assert!(!result.status.success(), "orphan accepted: {:?}", result);
    assert!(String::from_utf8(result.stderr)?.contains("Candidat sans disposition"));
    Ok(())
}

#[test]
fn terminal_scope_dispositions_do_not_prevent_completion() -> Result<(), Box<dyn Error>> {
    for status in ["not_applicable", "out_of_scope"] {
        let dir = fixture(false)?;
        let root = dir.path();
        let mut coverage: serde_json::Value =
            serde_json::from_str(include_str!("fixtures/audit/coverage.json"))?;
        coverage[0]["status"] = json!(status);
        coverage[0]["unresolved"] = json!(["Explicit scope disposition"]);
        replace_document(root, "coverage-ledger.json", &coverage)?;
        close_run(root)?;
        let result = command(&["verify"], root)?;
        assert!(result.status.success(), "{:?}", result);
        let output: serde_json::Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(output["coverage_complete"], false);
    }
    Ok(())
}

#[test]
fn retains_elapsed_time_for_partial_deadline_overrun_without_allowing_complete(
) -> Result<(), Box<dyn Error>> {
    let dir = fixture(false)?;
    edit_metadata(dir.path(), "/elapsed_seconds", json!(100000))?;
    assert!(command(&["verify"], dir.path())?.status.success());
    let complete = fixture(true)?;
    close_run(complete.path())?;
    assert!(command(&["verify"], complete.path())?.status.success());
    edit_metadata(complete.path(), "/elapsed_seconds", json!(100000))?;
    assert!(!command(&["verify"], complete.path())?.status.success());
    Ok(())
}
