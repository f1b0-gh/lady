use ladybom::deps::{Component, Project, Report};
use ladybom_graph::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: &str = "2026-11-05T12:00:00Z";

fn fixture(
    ecosystem: &str,
    name: &str,
    versions: &[&str],
) -> Result<Graph, Box<dyn std::error::Error>> {
    let (kind, manifest, lock) = match ecosystem {
        "rust" => ("cargo", "Cargo.toml", "Cargo.lock"),
        "python" => ("pypi", "pyproject.toml", "uv.lock"),
        _ => ("npm", "package.json", "package-lock.json"),
    };
    let components = versions
        .iter()
        .enumerate()
        .map(|(i, version)| Component {
            name: name.into(),
            version: (*version).into(),
            purl: Some(format!("pkg:{kind}/{name}@{version}")),
            context: format!("node_modules/{i}/{name}"),
            source: Value::Null,
            artifacts: vec![],
            metadata: json!({}),
        })
        .collect();
    Ok(project(Report {
        schema_version: 2,
        complete: true,
        inputs: BTreeMap::new(),
        diagnostics: vec![],
        projects: vec![Project {
            manifest_package: None,
            ecosystem: ecosystem.into(),
            root: ".".into(),
            manifest: manifest.into(),
            lockfile: Some(lock.into()),
            locked: true,
            manager: ecosystem.into(),
            tools: vec![],
            requirements: vec![],
            components,
            components_from: None,
            workspace: Value::Null,
        }],
    })?)
}
fn policy(baseline: &Graph) -> Result<AlignmentPolicy, Box<dyn std::error::Error>> {
    Ok(AlignmentPolicy {
        schema_version: 1,
        baseline_graph_digest: graph_digest(baseline)?,
        exceptions: vec![],
    })
}
fn exception(id: &str, versions: &[&str]) -> AlignmentException {
    AlignmentException {
        finding_id: id.into(),
        versions: versions.iter().map(|s| (*s).into()).collect(),
        owner: "dependency-team".into(),
        reason: "Parent migration requires a reviewed API change".into(),
        issued_at: "2026-11-01T00:00:00Z".into(),
        expires_at: "2026-12-01T00:00:00Z".into(),
    }
}

// A baseline must never silently approve debt, even when the gate permits no-change.
#[test]
fn unchanged_debt_passes_only_the_non_regression_gate_in_each_ecosystem() -> TestResult {
    for ecosystem in ["npm", "rust", "python"] {
        let baseline = fixture(ecosystem, "shared", &["1.0.0", "2.0.0"])?;
        let result = check_alignment_policy(&baseline, &baseline, &policy(&baseline)?, NOW)?;
        assert!(
            result.non_regression_pass,
            "{ecosystem}: {:?}",
            result.problems
        );
        assert!(!result.reviewed_alignment_pass);
        assert_eq!(result.summary.unreviewed, 1);
        assert_eq!(result.findings[0].change, AlignmentChange::Unchanged);
        assert_eq!(result.findings[0].review, AlignmentReview::Backlog);
    }
    Ok(())
}

#[test]
fn new_duplicates_and_equal_count_replacements_require_review() -> TestResult {
    for (before, after, expected) in [
        (vec!["1.0.0"], vec!["1.0.0", "2.0.0"], AlignmentChange::New),
        (
            vec!["1.0.0", "2.0.0"],
            vec!["1.0.0", "3.0.0"],
            AlignmentChange::Changed,
        ),
        (
            vec!["1.0.0", "2.0.0"],
            vec!["1.0.0", "2.0.0", "3.0.0"],
            AlignmentChange::Changed,
        ),
    ] {
        let baseline = fixture("npm", "shared", &before)?;
        let current = fixture("npm", "shared", &after)?;
        let result = check_alignment_policy(&current, &baseline, &policy(&baseline)?, NOW)?;
        assert!(!result.non_regression_pass);
        assert_eq!(result.summary.regressions, 1);
        assert_eq!(result.findings[0].change, expected);
        assert_eq!(result.findings[0].review, AlignmentReview::Required);
    }
    Ok(())
}

#[test]
fn subset_reduction_is_progress_and_single_version_resolves_debt() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0", "3.0.0"])?;
    let current = fixture("npm", "shared", &["1.0.0", "3.0.0"])?;
    let result = check_alignment_policy(&current, &baseline, &policy(&baseline)?, NOW)?;
    assert!(result.non_regression_pass);
    assert!(!result.reviewed_alignment_pass);
    assert_eq!(result.findings[0].change, AlignmentChange::Reduced);
    let current = fixture("npm", "shared", &["4.0.0"])?;
    let result = check_alignment_policy(&current, &baseline, &policy(&baseline)?, NOW)?;
    assert!(result.reviewed_alignment_pass);
    assert_eq!(result.summary.resolved, 1);
    assert_eq!(result.findings[0].change, AlignmentChange::Resolved);
    Ok(())
}

#[test]
fn incomplete_inventory_and_scope_shrink_cannot_be_grandfathered() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut incomplete = baseline.clone();
    incomplete.inventory.complete = false;
    for (current, reference) in [
        (&incomplete, &baseline),
        (&incomplete, &incomplete),
        (&baseline, &incomplete),
    ] {
        let result = check_alignment_policy(current, reference, &policy(reference)?, NOW)?;
        assert!(!result.non_regression_pass);
        assert!(!result.complete);
    }
    let mut expanded = baseline.inventory.clone();
    let mut other = expanded.projects[0].clone();
    other.manifest = "other/package.json".into();
    other.lockfile = Some("other/package-lock.json".into());
    expanded.projects.push(other);
    let expanded = project(expanded)?;
    let result = check_alignment_policy(&baseline, &expanded, &policy(&expanded)?, NOW)?;
    assert!(!result.non_regression_pass);
    assert!(result.problems.iter().any(|s| s.contains("scope")));
    Ok(())
}

#[test]
fn reviewed_exception_is_exact_scoped_and_expires_at_the_boundary() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0"])?;
    let current = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut config = policy(&baseline)?;
    let initial = check_alignment_policy(&current, &baseline, &config, NOW)?;
    config
        .exceptions
        .push(exception(&initial.findings[0].id, &["2.0.0", "1.0.0"]));
    let approved = check_alignment_policy(&current, &baseline, &config, NOW)?;
    assert!(approved.reviewed_alignment_pass);
    assert_eq!(approved.findings[0].review, AlignmentReview::Accepted);
    assert_eq!(approved.summary.exceptions_active, 1);
    let expired = check_alignment_policy(&current, &baseline, &config, "2026-12-01T00:00:00Z")?;
    assert!(!expired.non_regression_pass);
    assert_eq!(expired.findings[0].review, AlignmentReview::Expired);
    assert!(check_alignment_policy(&current, &baseline, &config, "2026-10-01T00:00:00Z").is_err());
    let changed = fixture("npm", "shared", &["1.0.0", "3.0.0"])?;
    assert!(check_alignment_policy(&changed, &baseline, &config, NOW).is_err());
    config.exceptions.push(config.exceptions[0].clone());
    assert!(check_alignment_policy(&current, &baseline, &config, NOW).is_err());
    Ok(())
}

#[test]
fn source_change_cannot_inherit_old_debt_allowance() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut inventory = baseline.inventory.clone();
    for component in &mut inventory.projects[0].components {
        component.source = json!({"registry":"https://other.invalid"});
    }
    let current = project(inventory)?;
    let result = check_alignment_policy(&current, &baseline, &policy(&baseline)?, NOW)?;
    assert!(!result.non_regression_pass);
    assert_eq!(result.summary.regressions, 1);
    assert_eq!(result.findings.len(), 2);
    Ok(())
}

#[test]
fn foreign_reference_digest_and_malformed_exceptions_are_rejected() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut config = policy(&baseline)?;
    config.baseline_graph_digest = "0".repeat(64);
    assert!(check_alignment_policy(&baseline, &baseline, &config, NOW).is_err());
    config = policy(&baseline)?;
    let result = check_alignment_policy(&baseline, &baseline, &config, NOW)?;
    let good = exception(&result.findings[0].id, &["1.0.0", "2.0.0"]);
    for broken in [
        AlignmentException {
            owner: " ".into(),
            ..good.clone()
        },
        AlignmentException {
            finding_id: "unknown".into(),
            ..good.clone()
        },
        AlignmentException {
            expires_at: "2028-01-01T00:00:00Z".into(),
            ..good.clone()
        },
        AlignmentException {
            versions: vec!["1.0.0".into(), "1.0.0".into()],
            ..good.clone()
        },
    ] {
        config.exceptions = vec![broken];
        assert!(check_alignment_policy(&baseline, &baseline, &config, NOW).is_err());
    }
    Ok(())
}

#[test]
fn replacing_one_version_with_another_source_cannot_masquerade_as_resolution() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut inventory = baseline.inventory.clone();
    inventory.projects[0].components[1].source = json!({"git":"https://fork.invalid/repo"});
    let current = project(inventory)?;
    let result = check_alignment_policy(&current, &baseline, &policy(&baseline)?, NOW)?;
    assert!(!result.non_regression_pass);
    assert!(result.problems.iter().any(|s| s.contains("source_changed")));
    Ok(())
}

#[test]
fn independent_locks_and_same_version_installations_are_not_duplicates() -> TestResult {
    let first = fixture("npm", "shared", &["1.0.0", "1.0.0"])?;
    let mut inventory = first.inventory.clone();
    let other = fixture("npm", "shared", &["2.0.0"])?;
    let mut other = other.inventory.projects[0].clone();
    other.manifest = "other/package.json".into();
    other.lockfile = Some("other/package-lock.json".into());
    inventory.projects.push(other);
    let graph = project(inventory)?;
    let result = check_alignment_policy(&graph, &graph, &policy(&graph)?, NOW)?;
    assert!(result.reviewed_alignment_pass);
    assert_eq!(result.summary.current_duplicates, 0);
    assert!(result.findings.is_empty());
    Ok(())
}

#[test]
fn an_exception_does_not_override_incomplete_evidence_or_survive_resolution() -> TestResult {
    let baseline = fixture("npm", "shared", &["1.0.0", "2.0.0"])?;
    let mut config = policy(&baseline)?;
    let initial = check_alignment_policy(&baseline, &baseline, &config, NOW)?;
    config.exceptions = vec![exception(&initial.findings[0].id, &["1.0.0", "2.0.0"])];
    let mut incomplete = baseline.clone();
    incomplete.inventory.complete = false;
    let result = check_alignment_policy(&incomplete, &baseline, &config, NOW)?;
    assert!(!result.non_regression_pass);
    assert!(!result.reviewed_alignment_pass);
    let resolved = fixture("npm", "shared", &["1.0.0"])?;
    assert!(check_alignment_policy(&resolved, &baseline, &config, NOW).is_err());
    Ok(())
}
