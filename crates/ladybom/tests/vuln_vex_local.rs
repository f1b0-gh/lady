use cyclonedx_bom::{models::bom::Bom, prelude::Validate};
use ladybom::{
    cyclonedx,
    vuln::{self, vex, *},
    Report,
};
use serde_json::{json, Value};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const NOW: &str = "2026-11-04T12:00:00Z";
fn inventory() -> std::result::Result<Report, serde_json::Error> {
    let mut report: Report = serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    let project = report.projects.remove(1);
    report.projects = vec![project];
    Ok(report)
}
fn assess(report: &Report) -> ladybom::error::Result<Assessment> {
    vuln::assess(
        report,
        &Snapshot {
            schema_version: 1,
            source: "synthetic".into(),
            fetched_at: NOW.into(),
            complete: true,
            ecosystems: vec!["crates.io".into()],
            advisories: vec![
                json!({"id":"RUSTSEC-2026-TEST","modified":NOW,"aliases":["CVE-2026-TEST","GHSA-test-test-test"],"affected":[{"package":{"ecosystem":"crates.io","name":"itoa"},"versions":["1.0.15","1.0.14"]}]}),
            ],
        },
        NOW,
        86400,
    )
}
fn decisions(a: &Assessment, state: DecisionState) -> Decisions {
    Decisions {
        schema_version: 1,
        report_digest: a.report_digest.clone(),
        snapshot_digest: a.snapshot_digest.clone(),
        decisions: vec![Decision {
            finding_id: a.findings[0].id.clone(),
            state,
            justification: Some("code_not_reachable".into()),
            detail: "Synthetic reviewed scope".into(),
            author: "Reviewer".into(),
            evidence: vec!["review://synthetic/123".into()],
            issued_at: "2026-11-04T10:00:00Z".into(),
            expires_at: "2026-11-05T10:00:00Z".into(),
        }],
    }
}
fn value(bom: Bom) -> std::result::Result<Value, Box<dyn std::error::Error>> {
    assert!(bom.validate().passed());
    let mut bytes = Vec::new();
    bom.output_as_json_v1_5(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn local(report: &Report, a: &Assessment, d: Option<&Decisions>) -> ladybom::error::Result<Bom> {
    vex::from_report(report, a, d, vex::Profile::LocalComponents)
}
#[test]
fn local_targets_are_embedded_and_alias_sources_are_standard() -> Result {
    let report = inventory()?;
    let a = assess(&report)?;
    let first = value(local(&report, &a, None)?)?;
    assert_eq!(first, value(local(&report, &a, None)?)?);
    assert_eq!(first["components"].as_array().ok_or("components")?.len(), 1);
    assert_eq!(first["components"][0]["purl"], "pkg:cargo/itoa@1.0.15");
    let component_properties = first["components"][0]["properties"]
        .as_array()
        .ok_or("component properties")?;
    let sbom_coverage = component_properties
        .iter()
        .find(|p| p["name"] == "ladybom:coverage")
        .and_then(|p| p["value"].as_str())
        .ok_or("SBOM coverage")?;
    assert_eq!(
        serde_json::from_str::<Value>(sbom_coverage)?["composition"],
        "unknown"
    );
    assert!(component_properties
        .iter()
        .any(|p| p["name"] == "ladybom:vulnerability_coverage"));
    assert_eq!(
        first["components"][0]["bom-ref"],
        first["vulnerabilities"][0]["affects"][0]["ref"]
    );
    assert_eq!(first["vulnerabilities"][0]["source"]["name"], "RUSTSEC");
    let references = first["vulnerabilities"][0]["references"]
        .as_array()
        .ok_or("references")?;
    assert!(references
        .iter()
        .any(|r| r["id"] == "CVE-2026-TEST" && r["source"]["name"] == "CVE"));
    assert!(references
        .iter()
        .any(|r| r["id"] == "GHSA-test-test-test" && r["source"]["name"] == "GITHUB"));
    assert_ne!(
        first["serialNumber"],
        value(vex::from_assessment(&a, None)?)?["serialNumber"]
    );
    Ok(())
}
#[test]
fn local_refuses_wrong_report_serial_and_finding_context() -> Result {
    let report = inventory()?;
    for mutation in 0..7 {
        let mut a = assess(&report)?;
        match mutation {
            0 => a.report_digest = "0".repeat(64),
            1 => a.sbom_serial = "urn:uuid:12345678-1234-8123-8123-123456789abc".into(),
            2 => a.findings[0].component_ref = "unknown".into(),
            3 => a.findings[0].context = "another-context".into(),
            4 => a.findings[0].version = "1.0.14".into(),
            5 => a.findings[0].purl = Some("pkg:cargo/itoa@1.0.14".into()),
            _ => a.findings[0].ecosystem = "npm".into(),
        }
        assert!(local(&report, &a, None).is_err(), "mutation {mutation}");
    }
    Ok(())
}
#[test]
fn local_refuses_same_purl_in_distinct_contexts_even_if_only_one_finding_remains() -> Result {
    for fork in [false, true] {
        let mut report = inventory()?;
        let mut duplicate = report.projects[0].clone();
        duplicate.root = "other".into();
        duplicate.manifest = "other/Cargo.toml".into();
        duplicate.lockfile = Some("other/Cargo.lock".into());
        if fork {
            duplicate.components[1].source = json!("git+https://example.invalid/fork#123");
        }
        report
            .inputs
            .insert("other/Cargo.toml".into(), "1".repeat(64));
        report
            .inputs
            .insert("other/Cargo.lock".into(), "2".repeat(64));
        report.projects.push(duplicate);
        let mut a = assess(&report)?;
        a.findings.truncate(1);
        assert!(local(&report, &a, None).is_err());
        assert!(vex::from_assessment(&a, None).is_ok());
    }
    Ok(())
}
#[test]
fn local_refuses_unverified_source_even_with_rebound_assessment() -> Result {
    let mut report = inventory()?;
    let mut a = assess(&report)?;
    report.projects[0].components[1].source = json!("git+https://example.invalid/fork#123");
    a.report_digest = vuln::digest(&report)?;
    a.sbom_serial = cyclonedx::document_serial(&report)?;
    a.findings[0].component_ref =
        cyclonedx::component_reference(&report.projects[0], &report.projects[0].components[1])?;
    assert!(local(&report, &a, None).is_err());
    Ok(())
}
#[test]
fn local_handles_all_five_states_without_applying_expired_or_contradictory_decisions() -> Result {
    let report = inventory()?;
    let a = assess(&report)?;
    for (state, expected) in [
        (DecisionState::InTriage, "in_triage"),
        (DecisionState::Exploitable, "exploitable"),
        (DecisionState::NotAffected, "not_affected"),
        (DecisionState::FalsePositive, "false_positive"),
    ] {
        let mut d = decisions(&a, state);
        let current = value(local(&report, &a, Some(&d))?)?;
        assert_eq!(current["vulnerabilities"][0]["analysis"]["state"], expected);
        d.decisions[0].expires_at = NOW.into();
        let expired = value(local(&report, &a, Some(&d))?)?;
        assert_eq!(
            expired["vulnerabilities"][0]["analysis"]["state"],
            "in_triage"
        );
        assert_ne!(current["serialNumber"], expired["serialNumber"]);
    }
    assert!(local(&report, &a, Some(&decisions(&a, DecisionState::Resolved))).is_err());
    let mut d = decisions(&a, DecisionState::NotAffected);
    let mut conflicting = d.decisions[0].clone();
    conflicting.state = DecisionState::Exploitable;
    d.decisions.push(conflicting);
    assert!(local(&report, &a, Some(&d)).is_err());
    Ok(())
}
#[test]
fn same_advisory_on_two_versions_keeps_each_decision_local() -> Result {
    let mut report = inventory()?;
    let mut second = report.projects[0].components[1].clone();
    second.version = "1.0.14".into();
    second.purl = Some("pkg:cargo/itoa@1.0.14".into());
    report.projects[0].components.push(second);
    let a = assess(&report)?;
    assert_eq!(a.findings.len(), 2);
    let json = value(local(
        &report,
        &a,
        Some(&decisions(&a, DecisionState::NotAffected)),
    )?)?;
    let findings = json["vulnerabilities"].as_array().ok_or("findings")?;
    assert_eq!(findings[0]["analysis"]["state"], "not_affected");
    assert_eq!(findings[1]["analysis"]["state"], "in_triage");
    assert_ne!(
        findings[0]["affects"][0]["ref"],
        findings[1]["affects"][0]["ref"]
    );
    Ok(())
}

#[test]
fn local_refuses_source_collisions_without_a_purl() -> Result {
    let mut report = inventory()?;
    let mut fork = report.projects[0].components[1].clone();
    fork.purl = None;
    fork.context = "git+https://example.invalid/fork#123".into();
    fork.source = json!("git+https://example.invalid/fork#123");
    report.projects[0].components.push(fork);
    let a = assess(&report)?;
    assert_eq!(a.findings.len(), 1);
    assert!(local(&report, &a, None).is_err());
    Ok(())
}

#[test]
fn local_refuses_alias_overlap_between_distinct_finding_ids() -> Result {
    let report = inventory()?;
    let mut a = assess(&report)?;
    let mut duplicate = a.findings[0].clone();
    duplicate.id = "findings/conflicting-alias".into();
    duplicate.advisory_ids = vec!["GHSA-test-test-test".into()];
    a.findings.push(duplicate);
    assert!(local(&report, &a, None).is_err());
    Ok(())
}

#[test]
fn local_refuses_same_purl_in_nested_npm_installations() -> Result {
    let mut report: Report = serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    let mut project = report.projects.remove(2);
    let mut duplicate = project.components[0].clone();
    duplicate.context = "node_modules/parent/node_modules/is-number".into();
    project.components.push(duplicate);
    report.projects = vec![project];
    let a = vuln::assess(
        &report,
        &Snapshot {
            schema_version: 1,
            source: "synthetic".into(),
            fetched_at: NOW.into(),
            complete: true,
            ecosystems: vec!["npm".into()],
            advisories: vec![
                json!({"id":"GHSA-test-test-test","modified":NOW,"affected":[{"package":{"ecosystem":"npm","name":"is-number"},"versions":["7.0.0"]}]}),
            ],
        },
        NOW,
        86400,
    )?;
    assert_eq!(a.findings.len(), 2);
    assert!(local(&report, &a, None).is_err());
    Ok(())
}

#[test]
fn public_vex_omits_private_reviews_and_keeps_scope_and_expiry() -> Result {
    let mut report = inventory()?;
    report.projects[0].components[1].metadata["secret"] = json!("SECRET_NATIVE");
    let mut a = assess(&report)?;
    a.snapshot_source = "SECRET_SNAPSHOT".into();
    a.coverage.limitations.push("SECRET_COVERAGE".into());
    let mut d = decisions(&a, DecisionState::NotAffected);
    d.decisions[0].author = "SECRET_AUTHOR".into();
    d.decisions[0].detail = "SECRET_DETAIL".into();
    d.decisions[0].evidence = vec!["https://internal.test/SECRET_EVIDENCE".into()];
    for bom in [
        local(&report, &a, Some(&d))?,
        vex::from_assessment(&a, Some(&d))?,
    ] {
        let document = value(bom)?;
        assert!(!serde_json::to_string(&document)?.contains("SECRET_"));
        assert_eq!(
            document["vulnerabilities"][0]["analysis"]["state"],
            "not_affected"
        );
        assert!(document["vulnerabilities"][0]["analysis"]
            .get("detail")
            .is_none());
        let props = document["vulnerabilities"][0]["properties"]
            .as_array()
            .ok_or("properties")?;
        assert!(props
            .iter()
            .any(|p| p["name"] == "ladybom:decision_expires_at"
                && p["value"] == "2026-11-05T10:00:00Z"));
        assert!(props.iter().any(|p| p["name"] == "ladybom:decision_sha256"
            && p["value"].as_str().is_some_and(|v| v.len() == 64)));
    }
    Ok(())
}

#[test]
fn explicit_private_vex_targets_exact_private_sbom_without_rebinding_assessment() -> Result {
    let report = inventory()?;
    let a = assess(&report)?;
    let d = decisions(&a, DecisionState::NotAffected);
    let public = value(vex::from_report(
        &report,
        &a,
        Some(&d),
        vex::Profile::BomLink,
    )?)?;
    let private = value(vex::from_report_with_export_profile(
        &report,
        &a,
        Some(&d),
        vex::Profile::BomLink,
        cyclonedx::ExportProfile::PrivateDetailed,
    )?)?;
    let private_serial = cyclonedx::document_serial_with_profile(
        &report,
        cyclonedx::ExportProfile::PrivateDetailed,
    )?;
    let uuid = private_serial.strip_prefix("urn:uuid:").ok_or("uuid")?;
    assert_eq!(
        private["vulnerabilities"][0]["affects"][0]["ref"],
        format!("urn:cdx:{uuid}/1#{}", a.findings[0].component_ref)
    );
    assert_eq!(a.sbom_serial, cyclonedx::document_serial(&report)?);
    assert_ne!(public["serialNumber"], private["serialNumber"]);
    assert!(serde_json::to_string(&private)?.contains("Synthetic reviewed scope"));
    assert!(!serde_json::to_string(&public)?.contains("Synthetic reviewed scope"));
    Ok(())
}

#[test]
fn public_vex_rejects_url_identifiers_without_rewriting_them() -> Result {
    let report = inventory()?;
    let mut a = assess(&report)?;
    a.findings[0]
        .aliases
        .push("https://internal.test/SECRET_TOKEN".into());
    assert!(vex::from_assessment(&a, None).is_err());
    assert!(local(&report, &a, None).is_err());
    Ok(())
}

#[test]
fn public_local_vex_preserves_allowlisted_internal_authority() -> Result {
    let report = inventory()?;
    let mut a = assess(&report)?;
    a.snapshot_source = "INTERNAL".into();
    a.findings[0].advisory_ids = vec!["LADYBOM-SYNTHETIC".into()];
    a.findings[0].aliases.clear();
    let doc = value(local(&report, &a, None)?)?;
    assert_eq!(doc["vulnerabilities"][0]["source"]["name"], "INTERNAL");
    a.snapshot_source = "SECRET_UNKNOWN_SOURCE".into();
    assert!(local(&report, &a, None).is_err());
    Ok(())
}
