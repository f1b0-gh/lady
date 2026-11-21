use cyclonedx_bom::{
    models::bom::{Bom, SpecVersion},
    prelude::Validate,
};
use ladybom::deps::vuln::{self, *};

fn assessment() -> Assessment {
    Assessment {
        schema_version: 1,
        report_digest: "a".repeat(64),
        snapshot_digest: "b".repeat(64),
        sbom_serial: "urn:uuid:12345678-1234-8123-8123-123456789abc".into(),
        as_of: "2026-11-04T12:00:00Z".into(),
        snapshot_fetched_at: "2026-11-04T11:00:00Z".into(),
        snapshot_source: "synthetic OSV".into(),
        max_age_seconds: 604800,
        complete: true,
        coverage: Coverage {
            inventory_complete: true,
            advisories_complete: true,
            identities_complete: true,
            matching_complete: true,
            fresh: true,
            components: 1,
            assessed_components: 1,
            withdrawn_advisories: 0,
            limitations: vec![],
        },
        findings: vec![Finding {
            id: "finding-1".into(),
            component_ref: "ladybom:component-1".into(),
            purl: Some("pkg:cargo/demo@1.0.0".into()),
            ecosystem: "crates.io".into(),
            name: "demo".into(),
            version: "1.0.0".into(),
            manifest: "Cargo.toml".into(),
            lockfile: None,
            context: "runtime".into(),
            status: MatchStatus::Matched,
            advisory_ids: vec!["OSV-TEST-1".into()],
            aliases: vec!["CVE-2099-0001".into()],
            fixed_versions: vec!["1.0.1".into()],
            evidence: vec![],
            limitations: vec![],
        }],
    }
}
fn decisions(a: &Assessment) -> Decisions {
    Decisions {
        schema_version: 1,
        report_digest: a.report_digest.clone(),
        snapshot_digest: a.snapshot_digest.clone(),
        decisions: vec![Decision {
            finding_id: "finding-1".into(),
            state: DecisionState::NotAffected,
            justification: Some("code_not_reachable".into()),
            detail: "Reviewed call graph excludes affected function".into(),
            author: "Security reviewer".into(),
            evidence: vec!["review://synthetic/callgraph-proof-123".into()],
            issued_at: "2026-11-04T10:00:00Z".into(),
            expires_at: "2026-11-05T10:00:00Z".into(),
        }],
    }
}
fn exception(a: &Assessment) -> Exception {
    Exception {
        finding_id: "finding-1".into(),
        report_digest: a.report_digest.clone(),
        snapshot_digest: a.snapshot_digest.clone(),
        author: "Risk owner".into(),
        reason: "Temporary acceptance pending verified upgrade".into(),
        evidence: vec!["review://synthetic/risk-acceptance-123".into()],
        issued_at: "2026-11-04T10:00:00Z".into(),
        expires_at: "2026-11-05T10:00:00Z".into(),
    }
}
fn evaluate(
    a: &Assessment,
    d: Option<&Decisions>,
    p: &Policy,
) -> ladybom::error::Result<PolicyResult> {
    vuln::policy::evaluate(a, d, p, None)
}
fn vex_json(a: &Assessment, d: Option<&Decisions>) -> ladybom::error::Result<serde_json::Value> {
    let mut output = Vec::new();
    vuln::vex::write_json(a, d, &mut output)?;
    Ok(serde_json::from_slice(&output)?)
}
#[test]
fn default_denies_and_reviewed_exemption_allows() -> ladybom::error::Result<()> {
    let a = assessment();
    let p = Policy::default();
    let denied = evaluate(&a, None, &p)?;
    assert!(!denied.allowed);
    assert_eq!(denied.findings[0].state, DecisionState::InTriage);
    let allowed = evaluate(&a, Some(&decisions(&a)), &p)?;
    assert!(allowed.allowed);
    assert!(!allowed.findings[0].blocking);
    Ok(())
}
#[test]
fn expired_decision_returns_to_triage_at_exact_boundary() -> ladybom::error::Result<()> {
    let a = assessment();
    let mut d = decisions(&a);
    d.decisions[0].expires_at = a.as_of.clone();
    let result = evaluate(&a, Some(&d), &Policy::default())?;
    assert!(!result.allowed);
    assert_eq!(result.findings[0].state, DecisionState::InTriage);
    assert!(result.findings[0]
        .reasons
        .iter()
        .any(|r| r.contains("expir")));
    assert_eq!(
        vex_json(&a, Some(&d))?["vulnerabilities"][0]["analysis"]["state"],
        "in_triage"
    );
    Ok(())
}
#[test]
fn rejects_unknown_duplicate_and_wrong_scope_decisions() {
    let a = assessment();
    for mutation in 0..4 {
        let mut d = decisions(&a);
        match mutation {
            0 => d.decisions[0].finding_id = "*".into(),
            1 => d.decisions.push(d.decisions[0].clone()),
            2 => d.report_digest = "c".repeat(64),
            _ => d.snapshot_digest = "c".repeat(64),
        }
        assert!(evaluate(&a, Some(&d), &Policy::default()).is_err());
        assert!(vuln::vex::from_assessment(&a, Some(&d)).is_err());
    }
}
#[test]
fn rejects_future_unjustified_unproven_and_resolved_assertions() {
    let a = assessment();
    for mutation in 0..8 {
        let mut d = decisions(&a);
        match mutation {
            0 => d.decisions[0].issued_at = "2026-11-05T00:00:00Z".into(),
            1 => d.decisions[0].justification = None,
            2 => d.decisions[0].justification = Some("trust_me".into()),
            3 => d.decisions[0].evidence = vec![],
            4 => d.decisions[0].evidence = vec![" ".into()],
            5 => d.decisions[0].author = "\t".into(),
            6 => d.decisions[0].state = DecisionState::Resolved,
            _ => d.decisions[0].finding_id = "finding-1\n".into(),
        }
        assert!(
            evaluate(&a, Some(&d), &Policy::default()).is_err(),
            "mutation {mutation}"
        );
    }
}
#[test]
fn incomplete_unknown_and_stale_assessments_never_green() -> ladybom::error::Result<()> {
    for mutation in 0..5 {
        let mut a = assessment();
        match mutation {
            0 => a.coverage.inventory_complete = false,
            1 => a.findings[0].status = MatchStatus::Unknown,
            2 => a.snapshot_fetched_at = "2026-09-01T00:00:00Z".into(),
            3 => a.coverage.fresh = false,
            _ => a.complete = false,
        }
        let p = Policy {
            max_age_seconds: 31536000,
            ..Policy::default()
        };
        assert!(
            !evaluate(&a, Some(&decisions(&a)), &p)?.allowed,
            "mutation {mutation}"
        );
    }
    Ok(())
}
#[test]
fn stricter_freshness_and_empty_inventory_fail_closed() -> ladybom::error::Result<()> {
    let mut a = assessment();
    a.findings.clear();
    let p = Policy {
        max_age_seconds: 3599,
        ..Policy::default()
    };
    assert!(!evaluate(&a, None, &p)?.allowed);
    a.coverage.matching_complete = false;
    assert!(!evaluate(&a, None, &Policy::default())?.allowed);
    Ok(())
}
#[test]
fn risk_acceptance_is_bound_expiring_and_does_not_change_vex_state() -> ladybom::error::Result<()> {
    let a = assessment();
    let mut p = Policy {
        exceptions: vec![exception(&a)],
        ..Policy::default()
    };
    let r = evaluate(&a, None, &p)?;
    assert!(r.allowed);
    assert!(r.findings[0].accepted_risk);
    assert_eq!(r.findings[0].state, DecisionState::InTriage);
    p.exceptions[0].expires_at = a.as_of.clone();
    assert!(!evaluate(&a, None, &p)?.allowed);
    for mutation in 0..4 {
        let mut p = Policy {
            exceptions: vec![exception(&a)],
            ..Policy::default()
        };
        match mutation {
            0 => p.exceptions[0].finding_id = "*".into(),
            1 => p.exceptions[0].report_digest = "c".repeat(64),
            2 => p.exceptions[0].snapshot_digest = "c".repeat(64),
            _ => p.exceptions.push(p.exceptions[0].clone()),
        }
        assert!(evaluate(&a, None, &p).is_err());
    }
    let mut unknown = a.clone();
    unknown.findings[0].status = MatchStatus::Unknown;
    assert!(
        !evaluate(
            &unknown,
            None,
            &Policy {
                exceptions: vec![exception(&a)],
                ..Policy::default()
            }
        )?
        .allowed
    );
    Ok(())
}
#[test]
fn signals_only_raise_priority_and_stale_signals_block() -> ladybom::error::Result<()> {
    let a = assessment();
    let mut s = Signals {
        schema_version: 1,
        source: "Synthetic KEV EPSS".into(),
        fetched_at: a.as_of.clone(),
        entries: vec![Signal {
            id: "CVE-2099-0001".into(),
            known_exploited: false,
            epss: Some(0.01),
        }],
    };
    let p = Policy::default();
    let r = vuln::policy::evaluate(&a, None, &p, Some(&s))?;
    assert!(!r.allowed);
    assert_eq!(r.findings[0].priority, "review");
    s.entries[0].epss = Some(0.1);
    assert_eq!(
        vuln::policy::evaluate(&a, None, &p, Some(&s))?.findings[0].priority,
        "high_epss"
    );
    s.entries[0].known_exploited = true;
    assert_eq!(
        vuln::policy::evaluate(&a, None, &p, Some(&s))?.findings[0].priority,
        "known_exploited"
    );
    s.fetched_at = "2026-11-03T11:59:59Z".into();
    assert!(!vuln::policy::evaluate(&a, Some(&decisions(&a)), &p, Some(&s))?.allowed);
    for value in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
        s.entries[0].epss = Some(value);
        assert!(vuln::policy::evaluate(&a, None, &p, Some(&s)).is_err());
    }
    s.entries[0].epss = None;
    s.entries.push(s.entries[0].clone());
    assert!(vuln::policy::evaluate(&a, None, &p, Some(&s)).is_err());
    Ok(())
}
#[test]
fn policy_schema_and_age_are_validated() {
    let a = assessment();
    for (schema_version, max_age_seconds) in [(2, 604800), (1, 0), (1, 31536001)] {
        assert!(evaluate(
            &a,
            None,
            &Policy {
                schema_version,
                max_age_seconds,
                exceptions: vec![]
            }
        )
        .is_err());
    }
}
#[test]
fn vex_links_exact_sbom_and_preserves_review_provenance_reproducibly() -> ladybom::error::Result<()>
{
    let a = assessment();
    let d = decisions(&a);
    let mut first = Vec::new();
    let mut second = Vec::new();
    vuln::vex::write_json(&a, Some(&d), &mut first)?;
    vuln::vex::write_json(&a, Some(&d), &mut second)?;
    assert_eq!(first, second);
    let parsed = Bom::parse_from_json_v1_5(first.as_slice())
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    assert!(parsed.validate_version(SpecVersion::V1_5).passed());
    let json: serde_json::Value = serde_json::from_slice(&first)?;
    assert_eq!(
        json["vulnerabilities"][0]["affects"][0]["ref"],
        "urn:cdx:12345678-1234-8123-8123-123456789abc/1#ladybom:component-1"
    );
    assert_eq!(
        json["vulnerabilities"][0]["analysis"]["state"],
        "not_affected"
    );
    let text = String::from_utf8_lossy(&first);
    assert!(!text.contains("Security reviewer"));
    assert!(!text.contains("review://synthetic/callgraph-proof-123"));
    assert!(text.contains("ladybom:decision_sha256"));
    assert!(text.contains("2026-11-05T10:00:00Z"));
    assert!(text.contains(&a.report_digest));
    assert!(text.contains(&a.snapshot_digest));
    Ok(())
}
#[test]
fn unknown_findings_remain_triage_in_vex() -> ladybom::error::Result<()> {
    let mut a = assessment();
    a.findings[0].status = MatchStatus::Unknown;
    assert_eq!(
        vex_json(&a, Some(&decisions(&a)))?["vulnerabilities"][0]["analysis"]["state"],
        "in_triage"
    );
    Ok(())
}
#[test]
fn vex_writer_failures_remain_operational_errors() -> ladybom::error::Result<()> {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("synthetic failure"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = vuln::vex::write_json(&assessment(), None, Broken)
        .err()
        .ok_or_else(|| std::io::Error::other("missing expected writer failure"))?;
    assert_eq!(ladybom::error::exit_code(&error), 1);
    Ok(())
}

#[test]
fn rejects_future_signals_and_inconsistent_decision_dates() {
    let a = assessment();
    let future = Signals {
        schema_version: 1,
        source: "synthetic".into(),
        fetched_at: "2026-11-04T12:00:01Z".into(),
        entries: vec![],
    };
    assert!(vuln::policy::evaluate(&a, None, &Policy::default(), Some(&future)).is_err());
    for mutation in 0..5 {
        let mut d = decisions(&a);
        match mutation {
            0 => d.decisions[0].expires_at = d.decisions[0].issued_at.clone(),
            1 => d.decisions[0].author = "x".repeat(8193),
            2 => d.decisions[0].detail.clear(),
            3 => d.schema_version = 2,
            _ => d.decisions[0].expires_at = "not-a-date".into(),
        }
        assert!(
            evaluate(&a, Some(&d), &Policy::default()).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn risk_exceptions_never_waive_incomplete_or_stale_inventory() -> ladybom::error::Result<()> {
    for mutation in 0..3 {
        let mut a = assessment();
        match mutation {
            0 => a.coverage.advisories_complete = false,
            1 => a.snapshot_fetched_at = "2026-10-01T00:00:00Z".into(),
            _ => a.coverage.assessed_components = 0,
        }
        let p = Policy {
            exceptions: vec![exception(&a)],
            ..Policy::default()
        };
        assert!(!evaluate(&a, None, &p)?.allowed);
    }
    Ok(())
}

#[test]
fn valid_false_positive_is_reviewed_and_exploitable_precedes_epss() -> ladybom::error::Result<()> {
    let a = assessment();
    let mut d = decisions(&a);
    d.decisions[0].state = DecisionState::FalsePositive;
    d.decisions[0].justification = None;
    d.decisions[0].evidence = vec!["src/a.rs:10".into()];
    assert!(evaluate(&a, Some(&d), &Policy::default())?.allowed);
    d.decisions[0].state = DecisionState::Exploitable;
    let signals = Signals {
        schema_version: 1,
        source: "synthetic".into(),
        fetched_at: a.as_of.clone(),
        entries: vec![Signal {
            id: "OSV-TEST-1".into(),
            known_exploited: false,
            epss: Some(1.0),
        }],
    };
    let result = vuln::policy::evaluate(&a, Some(&d), &Policy::default(), Some(&signals))?;
    assert!(!result.allowed);
    assert_eq!(result.findings[0].priority, "exploitable");
    Ok(())
}

#[test]
fn changing_decision_changes_vex_identity() -> ladybom::error::Result<()> {
    let a = assessment();
    let mut d = decisions(&a);
    let first = vex_json(&a, Some(&d))?;
    d.decisions[0].author = "Another security reviewer".into();
    let second = vex_json(&a, Some(&d))?;
    assert_ne!(first["serialNumber"], second["serialNumber"]);
    Ok(())
}

#[test]
fn vex_refuses_identity_normalization() {
    for mutation in 0..3 {
        let mut a = assessment();
        match mutation {
            0 => a.findings[0].advisory_ids[0].push('\t'),
            1 => a.findings[0].component_ref.push('\n'),
            _ => a.sbom_serial = "urn:uuid:invalid".into(),
        }
        assert!(vuln::vex::from_assessment(&a, None).is_err());
    }
}

#[test]
fn fractional_seconds_do_not_admit_future_decisions_or_stale_data() -> ladybom::error::Result<()> {
    let mut a = assessment();
    a.as_of = "2026-11-04T12:00:00.1Z".into();
    let mut d = decisions(&a);
    d.decisions[0].issued_at = "2026-11-04T12:00:00.9Z".into();
    assert!(evaluate(&a, Some(&d), &Policy::default()).is_err());
    let p = Policy {
        max_age_seconds: 3600,
        ..Policy::default()
    };
    assert!(!evaluate(&a, Some(&decisions(&a)), &p)?.allowed);
    Ok(())
}
