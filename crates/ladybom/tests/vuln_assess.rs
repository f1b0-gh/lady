use ladybom::{
    cyclonedx,
    vuln::{self, MatchStatus, Snapshot},
    Report,
};
use serde_json::{json, Value};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
const NOW: &str = "2026-11-04T12:00:00Z";

fn inventory() -> std::result::Result<Report, serde_json::Error> {
    let mut report: Report = serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    let mut project = report.projects.remove(1);
    project.components.retain(|c| c.purl.is_some());
    report.projects = vec![project];
    Ok(report)
}

fn snapshot() -> Snapshot {
    Snapshot {
        schema_version: 1,
        source: "https://osv.dev/test-fixture".into(),
        fetched_at: "2026-11-04T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["crates.io".into()],
        advisories: vec![json!({
            "schema_version":"1.6.0", "id":"RUSTSEC-2026-TEST",
            "modified":"2026-11-03T00:00:00Z", "aliases":["CVE-2026-TEST"],
            "summary":"Synthetic issue", "affected":[{
                "package":{"ecosystem":"crates.io","name":"itoa"},
                "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.16"}]}]
            }]
        })],
    }
}

#[test]
fn findings_are_reproducible_bound_to_sources_and_retain_original_evidence() -> Result {
    let report = inventory()?;
    let snapshot = snapshot();
    let first = vuln::assess(&report, &snapshot, NOW, 86400)?;
    assert!(first.complete);
    assert_eq!(first.coverage.assessed_components, 1);
    assert_eq!(first.findings.len(), 1);
    assert_eq!(first.findings[0].status, MatchStatus::Matched);
    assert_eq!(first.findings[0].fixed_versions, ["1.0.16"]);
    assert_eq!(first.findings[0].evidence, snapshot.advisories);
    assert_eq!(first.report_digest, vuln::digest(&report)?);
    assert_eq!(first.snapshot_digest, vuln::digest(&snapshot)?);
    let bom = cyclonedx::from_report(&report)?;
    assert_eq!(
        bom.serial_number.ok_or("serial")?.to_string(),
        first.sbom_serial
    );
    assert_eq!(
        serde_json::to_vec(&first)?,
        serde_json::to_vec(&vuln::assess(&report, &snapshot, NOW, 86400)?)?
    );
    Ok(())
}

#[test]
fn publication_time_is_independent_from_last_edit_time() -> Result {
    let mut snapshot = snapshot();
    // OSV defines publication's effective time separately from the last edit.
    // RustSec's export can declare publication at noon after an earlier edit.
    snapshot.advisories[0]["published"] = json!("2026-11-03T12:00:00Z");
    let assessment = vuln::assess(&inventory()?, &snapshot, NOW, 86400)?;
    assert!(assessment.complete);
    assert_eq!(assessment.findings.len(), 1);
    assert_eq!(assessment.findings[0].evidence, snapshot.advisories);

    // All effective dates must still fall within the fetched snapshot.
    snapshot.advisories[0]["published"] = json!("2026-11-05T00:00:00Z");
    assert!(vuln::assess(&inventory()?, &snapshot, NOW, 86400).is_err());
    Ok(())
}

#[test]
fn withdrawal_time_is_independent_from_last_edit_time() -> Result {
    let mut snapshot = snapshot();
    snapshot.advisories[0]["withdrawn"] = json!("2026-11-03T12:00:00Z");
    let assessment = vuln::assess(&inventory()?, &snapshot, NOW, 86400)?;
    assert!(assessment.complete);
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.coverage.withdrawn_advisories, 1);
    snapshot.advisories[0]["withdrawn"] = json!("2026-11-05T00:00:00Z");
    assert!(vuln::assess(&inventory()?, &snapshot, NOW, 86400).is_err());
    Ok(())
}

#[test]
fn alias_groups_are_transitive_but_related_records_are_distinct() -> Result {
    let mut snapshot = snapshot();
    let mut alias = snapshot.advisories[0].clone();
    alias["id"] = json!("GHSA-synthetic-alias");
    alias["aliases"] = json!(["CVE-2026-TEST", "PYSEC-TEST"]);
    snapshot.advisories.push(alias);
    let mut related = snapshot.advisories[0].clone();
    related["id"] = json!("GHSA-related");
    related["aliases"] = json!([]);
    related["related"] = json!(["CVE-2026-TEST"]);
    snapshot.advisories.push(related);
    let assessment = vuln::assess(&inventory()?, &snapshot, NOW, 86400)?;
    assert_eq!(assessment.findings.len(), 2);
    assert!(assessment
        .findings
        .iter()
        .any(|f| f.advisory_ids.len() == 2 && f.aliases.contains(&"PYSEC-TEST".into())));
    Ok(())
}

#[test]
fn incomplete_stale_empty_and_unsupported_coverage_cannot_look_clean() -> Result {
    let mut report = inventory()?;
    let mut snapshot = snapshot();
    let stale = vuln::assess(&report, &snapshot, NOW, 1)?;
    assert!(!stale.complete);
    assert!(!stale.coverage.fresh);
    assert_eq!(stale.findings.len(), 1);
    snapshot.complete = false;
    assert!(!vuln::assess(&report, &snapshot, NOW, 86400)?.complete);
    snapshot.complete = true;
    snapshot.ecosystems = vec!["npm".into()];
    snapshot.advisories.clear();
    assert!(!vuln::assess(&report, &snapshot, NOW, 86400)?.complete);
    report.projects.clear();
    assert!(!vuln::assess(&report, &snapshot, NOW, 86400)?.complete);
    Ok(())
}

#[test]
fn private_registries_and_forged_purls_are_not_public_package_matches() -> Result {
    let original = inventory()?;
    for mutation in 0..4 {
        let mut report = original.clone();
        let component = &mut report.projects[0].components[0];
        match mutation {
            0 => component.source = json!("registry+https://private.example/index"),
            1 => component.purl = Some("pkg:cargo/other@1.0.15".into()),
            2 => component.purl = Some("pkg:cargo/itoa@9.0.0".into()),
            _ => component.purl = None,
        }
        let assessment = vuln::assess(&report, &snapshot(), NOW, 86400)?;
        assert!(!assessment.complete, "mutation {mutation}");
        assert!(assessment.findings.is_empty(), "mutation {mutation}");
        assert!(!assessment.coverage.identities_complete);
    }
    Ok(())
}

#[test]
fn shared_locks_keep_one_finding_and_invalid_dates_are_refused() -> Result {
    let mut report = inventory()?;
    let mut member = report.projects[0].clone();
    member.manifest = "rust/member/Cargo.toml".into();
    member.components.clear();
    member.components_from = Some(report.projects[0].manifest.clone());
    report.projects.push(member);
    assert_eq!(
        vuln::assess(&report, &snapshot(), NOW, 86400)?
            .findings
            .len(),
        1
    );
    assert!(vuln::assess(&report, &snapshot(), "bad-date", 86400).is_err());
    assert!(vuln::assess(&report, &snapshot(), "2026-11-01T00:00:00Z", 86400).is_err());
    assert!(vuln::assess(&report, &snapshot(), NOW, 0).is_err());
    Ok(())
}

#[test]
fn withdrawn_advisories_are_preserved_but_never_reported_as_active_findings() -> Result {
    let mut snapshot = snapshot();
    snapshot.advisories[0]["withdrawn"] = json!("2026-11-03T12:00:00Z");
    snapshot.advisories[0]["modified"] = json!("2026-11-03T12:00:00Z");
    let assessment = vuln::assess(&inventory()?, &snapshot, NOW, 86400)?;
    assert!(assessment.complete);
    assert!(assessment.findings.is_empty());
    assert_eq!(assessment.coverage.withdrawn_advisories, 1);
    assert_eq!(
        snapshot.advisories[0]["withdrawn"],
        Value::String("2026-11-03T12:00:00Z".into())
    );
    Ok(())
}

#[test]
fn unsupported_installed_versions_are_unknown_even_without_advisories() -> Result {
    let mut snapshot = snapshot();
    snapshot.advisories.clear();
    for (ecosystem, osv_ecosystem, purl_type, source) in [
        (
            "rust",
            "crates.io",
            "cargo",
            json!("registry+https://github.com/rust-lang/crates.io-index"),
        ),
        (
            "npm",
            "npm",
            "npm",
            json!("https://registry.npmjs.org/itoa/-/itoa-1.0.15.tgz"),
        ),
        (
            "python",
            "PyPI",
            "pypi",
            json!({"registry":"https://pypi.org/simple"}),
        ),
    ] {
        let mut report = inventory()?;
        report.projects[0].ecosystem = ecosystem.into();
        let component = &mut report.projects[0].components[0];
        component.source = source;
        component.purl = Some(format!("pkg:{purl_type}/itoa@1.0.15"));
        snapshot.ecosystems = vec![osv_ecosystem.into()];
        assert!(vuln::assess(&report, &snapshot, NOW, 86400)?.complete);
        report.projects[0].components[0].version = "not-a-version".into();
        report.projects[0].components[0].purl = Some(format!("pkg:{purl_type}/itoa@not-a-version"));
        let result = vuln::assess(&report, &snapshot, NOW, 86400)?;
        assert!(!result.complete, "{ecosystem}");
        assert!(!result.coverage.identities_complete, "{ecosystem}");
    }
    Ok(())
}

#[test]
fn contradictory_python_sources_cannot_be_treated_as_public_packages() -> Result {
    let mut snapshot = snapshot();
    snapshot.ecosystems = vec!["PyPI".into()];
    snapshot.advisories.clear();
    for source in [
        json!({"registry":"https://pypi.org/simple", "git":"https://private.invalid/demo"}),
        json!({"registry":"https://pypi.org/simple", "editable":"."}),
        json!({"registry":"https://pypi.org/simple", "url":"https://private.invalid/demo.whl"}),
    ] {
        let mut report = inventory()?;
        report.projects[0].ecosystem = "python".into();
        let component = &mut report.projects[0].components[0];
        component.source = source;
        component.purl = Some("pkg:pypi/itoa@1.0.15".into());
        let result = vuln::assess(&report, &snapshot, NOW, 86400)?;
        assert!(!result.complete);
        assert!(!result.coverage.identities_complete);
        assert!(result.findings.is_empty());
    }
    Ok(())
}

#[test]
fn active_advisories_without_package_metadata_leave_coverage_unknown() -> Result {
    let mut snapshot = snapshot();
    snapshot.advisories = vec![json!({"id":"OSV-RESERVED", "modified":"2026-11-03T00:00:00Z"})];
    for affected in [None, Some(json!([]))] {
        if let Some(affected) = affected {
            snapshot.advisories[0]["affected"] = affected;
        }
        vuln::osv::validate_snapshot(&snapshot)?;
        let result = vuln::assess(&inventory()?, &snapshot, NOW, 86400)?;
        assert!(!result.complete);
        assert!(!result.coverage.matching_complete);
        assert!(result.findings.is_empty());
        assert!(result
            .coverage
            .limitations
            .iter()
            .any(|l| l.contains("OSV-RESERVED")));
        assert!(!vuln::policy::evaluate(&result, None, &Default::default(), None)?.allowed);
    }
    snapshot.advisories[0]["withdrawn"] = json!("2026-11-03T00:00:00Z");
    assert!(vuln::assess(&inventory()?, &snapshot, NOW, 86400)?.complete);
    Ok(())
}
