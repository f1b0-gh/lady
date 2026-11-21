use ladybom::{
    vuln::{self, vxdf, Snapshot},
    Report,
};
use serde_json::{json, Value};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const NOW: &str = "2026-11-04T12:00:00Z";

fn inputs() -> std::result::Result<(Report, Snapshot), serde_json::Error> {
    let mut report: Report = serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    let mut project = report.projects.remove(1);
    project
        .components
        .retain(|component| component.purl.is_some());
    report.projects = vec![project];
    let snapshot = Snapshot {
        schema_version: 1,
        source: "fixture".into(),
        fetched_at: "2026-11-04T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["crates.io".into()],
        advisories: vec![json!({
            "id":"TEST-1", "modified":"2026-11-03T00:00:00Z", "affected":[{
                "package":{"ecosystem":"crates.io","name":"itoa"}, "versions":["1.0.15"]
            }]
        })],
    };
    Ok((report, snapshot))
}
fn scope() -> vxdf::Scope {
    vxdf::Scope {
        revision: "fixture-commit".into(),
        target_profile: "fixture-linux".into(),
        as_of: NOW.into(),
        snapshot_max_age_seconds: 86400,
        evidence_max_age_seconds: 86400,
    }
}
fn document() -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let (report, snapshot) = inputs()?;
    let assessment = vuln::assess(&report, &snapshot, NOW, 86400)?;
    let finding = &assessment.findings[0];
    Ok(
        json!({"vxdfVersion":"0.0.1", "id":"10000000-0000-4000-8000-000000000001",
        "generatedAt":NOW,"exploitFlows":[{
            "id":"20000000-0000-4000-8000-000000000001", "title":"Synthetic assertion",
            "category":"VULNERABLE_COMPONENTS", "severity":{"level":"HIGH"},
            "validatedAt":"2026-11-04T11:00:00Z", "affectedComponents":[{
                "name":"itoa","version":"1.0.15","purl":"pkg:cargo/itoa@1.0.15",
                "componentType":"SOFTWARE_LIBRARY","evidenceRefs":["30000000-0000-4000-8000-000000000001"]}],
            "evidence":[{"id":"30000000-0000-4000-8000-000000000001",
                "evidenceType":"TOOL_SPECIFIC_OUTPUT_LOG", "description":"Untrusted receipt",
                "timestamp":"2026-11-04T10:00:00Z", "data":{"toolName":"fake-receipt",
                    "relevantLogSectionOrOutput":"success", "commandLineExecuted":"touch /tmp/ladybom-vxdf-must-not-execute"}}],
            "x-ladybom":{"report_digest":assessment.report_digest,"snapshot_digest":assessment.snapshot_digest,
                "finding_id":finding.id,"component_ref":finding.component_ref,"purl":finding.purl,
                "source":report.projects[0].components[0].source,"manifest":finding.manifest,
                "lockfile":finding.lockfile,"context":finding.context,"revision":"fixture-commit",
                "target_profile":"fixture-linux"}
        }]}),
    )
}

#[test]
fn import_preserves_exact_original_and_never_trusts_fake_receipts() -> Result {
    let original = serde_json::to_vec_pretty(&document()?)?;
    let imported = vxdf::import(&original)?;
    let result = serde_json::to_value(&imported)?;
    assert_eq!(result["original"], String::from_utf8(original.clone())?);
    assert_eq!(result["document_digest"], ladybom::files::hash(&original));
    assert_eq!(result["trust"], "untrusted");
    assert_eq!(result["schema_validation"], "valid_pinned_0.0.1");
    assert_eq!(result["qualified"], false);
    Ok(())
}
#[test]
fn exact_correlation_does_not_qualify_an_assertion() -> Result {
    let (report, snapshot) = inputs()?;
    let imported = vxdf::import(&serde_json::to_vec(&document()?)?)?;
    let correlation = vxdf::correlate(&imported, &report, &snapshot, &scope())?;
    let value = serde_json::to_value(&correlation)?;
    assert_eq!(value["matches"].as_array().ok_or("matches")?.len(), 1);
    assert_eq!(value["qualified"], false);
    Ok(())
}
#[test]
fn same_purl_cannot_transfer_between_sources_locks_revisions_or_targets() -> Result {
    let (report, snapshot) = inputs()?;
    for key in [
        "report_digest",
        "snapshot_digest",
        "finding_id",
        "component_ref",
        "purl",
        "source",
        "manifest",
        "lockfile",
        "context",
        "revision",
        "target_profile",
    ] {
        let mut doc = document()?;
        doc["exploitFlows"][0]["x-ladybom"][key] = json!("wrong-context");
        let imported = vxdf::import(&serde_json::to_vec(&doc)?)?;
        assert!(
            vxdf::correlate(&imported, &report, &snapshot, &scope()).is_err(),
            "{key}"
        );
    }
    Ok(())
}
#[test]
fn stale_future_unknown_and_suspected_findings_cannot_correlate() -> Result {
    let (report, snapshot) = inputs()?;
    for (key, value) in [
        ("validatedAt", "2026-10-01T00:00:00Z"),
        ("validatedAt", "2026-11-05T00:00:00Z"),
        ("status", "UNDER_INVESTIGATION"),
    ] {
        let mut doc = document()?;
        doc["exploitFlows"][0][key] = json!(value);
        let imported = vxdf::import(&serde_json::to_vec(&doc)?)?;
        assert!(vxdf::correlate(&imported, &report, &snapshot, &scope()).is_err());
    }
    let mut incomplete = snapshot.clone();
    incomplete.complete = false;
    let imported = vxdf::import(&serde_json::to_vec(&document()?)?)?;
    assert!(vxdf::correlate(&imported, &report, &incomplete, &scope()).is_err());
    Ok(())
}
#[test]
fn rejects_duplicate_keys_dangling_references_dates_and_oversized_deep_input() -> Result {
    assert!(vxdf::import(br#"{"vxdfVersion":"0.0.1","vxdfVersion":"0.0.1"}"#).is_err());
    for mutation in 0..5 {
        let mut doc = document()?;
        match mutation {
            0 => {
                doc["exploitFlows"][0]["affectedComponents"][0]["evidenceRefs"] =
                    json!(["40000000-0000-4000-8000-000000000001"])
            }
            1 => doc["generatedAt"] = json!("not-a-date"),
            2 => doc["exploitFlows"][0]["evidence"] = json!([]),
            3 => doc["exploitFlows"][0]["id"] = json!("bad-id"),
            _ => doc["exploitFlows"][0]["evidence"][0]["timestamp"] = json!("bad-date"),
        }
        assert!(
            vxdf::import(&serde_json::to_vec(&doc)?).is_err(),
            "{mutation}"
        );
    }
    assert!(vxdf::import(&vec![b' '; vxdf::MAX_DOCUMENT_BYTES + 1]).is_err());
    let deep = format!("{}0{}", "[".repeat(150), "]".repeat(150));
    assert!(vxdf::import(deep.as_bytes()).is_err());
    Ok(())
}
#[test]
fn embedded_paths_and_urls_are_opaque_and_never_followed() -> Result {
    let directory = tempfile::tempdir()?;
    let sentinel = directory.path().join("EXECUTED");
    let mut doc = document()?;
    doc["exploitFlows"][0]["evidence"][0]["data"] = json!({
        "toolName":"fixture", "relevantLogSectionOrOutput":"file:///definitely/missing",
        "commandLineExecuted":format!("touch {}", sentinel.display()),
        "x-url":"https://127.0.0.1:1/never-fetch"});
    assert!(vxdf::import(&serde_json::to_vec(&doc)?).is_ok());
    assert!(!sentinel.exists());
    Ok(())
}

#[test]
fn subsecond_expiry_is_not_rounded_into_freshness() -> Result {
    let (report, snapshot) = inputs()?;
    let imported = vxdf::import(&serde_json::to_vec(&document()?)?)?;
    let mut current_scope = scope();
    current_scope.as_of = "2026-11-04T12:00:00.000000001Z".into();
    current_scope.evidence_max_age_seconds = 7200;
    assert!(vxdf::correlate(&imported, &report, &snapshot, &current_scope).is_err());
    Ok(())
}

#[test]
fn full_pinned_schema_rejects_variants_formats_and_unknown_properties() -> Result {
    for mutation in 0..7 {
        let mut doc = document()?;
        match mutation {
            0 => doc["exploitFlows"][0]["severity"]["level"] = json!("INVALID"),
            1 => doc["exploitFlows"][0]["evidence"][0]["data"] = json!({"unrecognized":"payload"}),
            2 => doc["exploitFlows"][0]["evidence"][0]["evidenceType"] = json!("FAKE_RECEIPT"),
            3 => doc["applicationInfo"] = json!({"name":"fixture","repositoryUrl":"not a uri"}),
            4 => {
                doc["exploitFlows"][0]["affectedComponents"][0]["componentType"] =
                    json!("NOT_A_TYPE")
            }
            5 => doc["unexpectedRootProperty"] = json!("not allowed"),
            _ => doc["exploitFlows"][0]["evidence"][0]["unexpectedProperty"] = json!(false),
        }
        assert!(
            vxdf::import(&serde_json::to_vec(&doc)?).is_err(),
            "mutation {mutation}"
        );
    }
    Ok(())
}

// Deliberately vulnerable synthetic endpoint, confined to files created by this test.
// This reproduces a prefix-check/path-normalization bug; it asserts nothing about itoa.
fn synthetic_endpoint(root: &std::path::Path, request: &str) -> std::io::Result<Option<String>> {
    if !request.starts_with("/public/") {
        return Ok(None);
    }
    std::fs::read_to_string(root.join(request.trim_start_matches('/'))).map(Some)
}
fn synthetic_observation() -> std::result::Result<String, Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    std::fs::create_dir(fixture.path().join("public"))?;
    std::fs::write(fixture.path().join("public/welcome"), "public fixture")?;
    std::fs::write(
        fixture.path().join("protected"),
        "SYNTHETIC_PROTECTED_MARKER",
    )?;
    let control = synthetic_endpoint(fixture.path(), "/protected")?;
    let public = synthetic_endpoint(fixture.path(), "/public/welcome")?;
    let observed = synthetic_endpoint(fixture.path(), "/public/../protected")?;
    assert!(control.is_none());
    assert_eq!(public.as_deref(), Some("public fixture"));
    assert_eq!(observed.as_deref(), Some("SYNTHETIC_PROTECTED_MARKER"));
    Ok(format!("Control /protected denied; /public/welcome returned public fixture; /public/../protected returned {}", observed.ok_or("missing observation")?))
}

fn reviewed(
    doc: &vxdf::ImportedDocument,
    report: &Report,
    snapshot: &Snapshot,
) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    let mut review = vxdf::review_template(doc, report, snapshot, &scope())?;
    review["reviewer"] = json!("independent-fixture-reviewer");
    review["reviewed_at"] = json!(NOW);
    review["expires_at"] = json!("2026-11-05T12:00:00Z");
    review["public_content_approved"] = json!(true);
    review["flows"][0]["decision"] = json!("validated_exploitable");
    review["flows"][0]["public"] = json!({"title":"Synthetic reviewed issue", "summary":"Manually reproduced synthetic issue",
        "severity":"HIGH", "scenario":"Create synthetic public/welcome and protected files; compare /protected, /public/welcome and /public/../protected through synthetic_endpoint in vuln_vxdf.rs",
        "observed_result":synthetic_observation()?, "tool_name":"cargo test synthetic Rust fixture", "tool_version":env!("CARGO_PKG_VERSION"),
        "environment":"Isolated synthetic fixture", "limitations":"Only the exact synthetic build was examined"});
    Ok(review)
}
#[test]
fn reviewed_export_requires_separate_operator_accepted_review_and_redacts_native_payloads() -> Result
{
    let (report, snapshot) = inputs()?;
    let mut original = document()?;
    original["exploitFlows"][0]["evidence"][0]["data"]["toolName"] =
        json!("cargo test synthetic_endpoint fixture");
    original["exploitFlows"][0]["evidence"][0]["data"]["relevantLogSectionOrOutput"] =
        json!(synthetic_observation()?);
    original["x-native-secret"] = json!("PRIVATE-NATIVE-SENTINEL");
    original["exploitFlows"][0]["title"] = json!("PRIVATE-NATIVE-SENTINEL");
    original["exploitFlows"][0]["evidence"][0]["data"]["commandLineExecuted"] =
        json!("PRIVATE-NATIVE-SENTINEL");
    let imported = vxdf::import(&serde_json::to_vec(&original)?)?;
    let review = serde_json::to_vec(&reviewed(&imported, &report, &snapshot)?)?;
    let acceptance = vxdf::ReviewAcceptance {
        review_digest: ladybom::files::hash(&review),
        reviewer: "independent-fixture-reviewer".into(),
    };
    let exported = vxdf::export_reviewed(
        &imported,
        &report,
        &snapshot,
        &scope(),
        &review,
        &acceptance,
    )?;
    assert_eq!(
        exported["x-ladybom-review"]["trust"],
        "human_review_assertion"
    );
    assert_eq!(
        exported["x-ladybom-review"]["cryptographically_verified"],
        false
    );
    assert_eq!(
        exported["exploitFlows"][0]["evidence"][0]["evidenceType"],
        "MANUAL_VERIFICATION_NOTES"
    );
    assert!(!exported.to_string().contains("PRIVATE-NATIVE-SENTINEL"));
    assert!(!exported.to_string().contains("registry+"));
    assert!(!exported.to_string().contains("fixture-commit"));
    let reimported = vxdf::import(&serde_json::to_vec(&exported)?)?;
    assert_eq!(serde_json::to_value(reimported)?["qualified"], false);
    assert_eq!(
        exported,
        vxdf::export_reviewed(
            &imported,
            &report,
            &snapshot,
            &scope(),
            &review,
            &acceptance
        )?
    );
    Ok(())
}
#[test]
fn self_claims_fake_receipts_stale_reviews_and_mismatched_evidence_never_export() -> Result {
    let (report, snapshot) = inputs()?;
    let imported = vxdf::import(&serde_json::to_vec(&document()?)?)?;
    let no_review = b"{}";
    let no_review_acceptance = vxdf::ReviewAcceptance {
        review_digest: ladybom::files::hash(no_review),
        reviewer: "independent-fixture-reviewer".into(),
    };
    assert!(vxdf::export_reviewed(
        &imported,
        &report,
        &snapshot,
        &scope(),
        no_review,
        &no_review_acceptance
    )
    .is_err());
    let template = serde_json::to_vec(&vxdf::review_template(
        &imported,
        &report,
        &snapshot,
        &scope(),
    )?)?;
    let template_acceptance = vxdf::ReviewAcceptance {
        review_digest: ladybom::files::hash(&template),
        reviewer: "independent-fixture-reviewer".into(),
    };
    assert!(vxdf::export_reviewed(
        &imported,
        &report,
        &snapshot,
        &scope(),
        &template,
        &template_acceptance
    )
    .is_err());
    for mutation in 0..10 {
        let mut review = reviewed(&imported, &report, &snapshot)?;
        match mutation {
            0 => review["document_digest"] = json!("wrong"),
            1 => review["flows"][0]["binding_digest"] = json!("wrong"),
            2 => review["flows"][0]["evidence"][0]["digest"] = json!("wrong"),
            3 => review["expires_at"] = json!(NOW),
            4 => review["reviewed_at"] = json!("2026-11-05T00:00:00Z"),
            5 => review["flows"][0]["decision"] = json!("execution_succeeded"),
            6 => review["public_content_approved"] = json!(false),
            7 => review["flows"][0]["public"]["observed_result"] = json!(""),
            8 => review["flows"] = json!([]),
            _ => review["cryptographically_verified"] = json!(true),
        }
        let bytes = serde_json::to_vec(&review)?;
        let acceptance = vxdf::ReviewAcceptance {
            review_digest: ladybom::files::hash(&bytes),
            reviewer: "independent-fixture-reviewer".into(),
        };
        assert!(
            vxdf::export_reviewed(&imported, &report, &snapshot, &scope(), &bytes, &acceptance)
                .is_err(),
            "mutation {mutation}"
        );
    }
    let review = serde_json::to_vec(&reviewed(&imported, &report, &snapshot)?)?;
    for acceptance in [
        vxdf::ReviewAcceptance {
            review_digest: "wrong".into(),
            reviewer: "independent-fixture-reviewer".into(),
        },
        vxdf::ReviewAcceptance {
            review_digest: ladybom::files::hash(&review),
            reviewer: "unexpected-reviewer".into(),
        },
    ] {
        assert!(vxdf::export_reviewed(
            &imported,
            &report,
            &snapshot,
            &scope(),
            &review,
            &acceptance
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn imported_documents_cannot_select_schemas_or_resolve_embedded_extensions() -> Result {
    let mut doc = document()?;
    doc["$schema"] = json!("file:///definitely/missing/alternate-schema.json");
    assert!(vxdf::import(&serde_json::to_vec(&doc)?).is_err());
    doc.as_object_mut().ok_or("object")?.remove("$schema");
    doc["x-schema"] =
        json!({"$ref":"http://127.0.0.1:1/never-fetch", "$schema":"file:///definitely/missing"});
    let imported = vxdf::import(&serde_json::to_vec(&doc)?)?;
    assert_eq!(serde_json::to_value(imported)?["qualified"], false);
    Ok(())
}
