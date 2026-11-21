use ladybom::{deps, error::Result};
use std::fs;

fn fixture_project() -> Result<tempfile::TempDir> {
    // Cargo excludes nested packages. Restore Cargo's input filenames in the scan tree.
    let project = tempfile::tempdir()?;
    let files: &[(&str, &[u8])] = &[
        (
            "rust/Cargo.toml",
            include_bytes!("fixtures/project/rust/Cargo.toml.fixture"),
        ),
        (
            "rust/Cargo.lock",
            include_bytes!("fixtures/project/rust/Cargo.lock.fixture"),
        ),
        (
            "rust/src/main.rs",
            include_bytes!("fixtures/project/rust/src/main.rs"),
        ),
        (
            "python/pyproject.toml",
            include_bytes!("fixtures/project/python/pyproject.toml"),
        ),
        (
            "python/uv.lock",
            include_bytes!("fixtures/project/python/uv.lock"),
        ),
        (
            "python/check.py",
            include_bytes!("fixtures/project/python/check.py"),
        ),
        (
            "web/package.json",
            include_bytes!("fixtures/project/web/package.json"),
        ),
        (
            "web/package-lock.json",
            include_bytes!("fixtures/project/web/package-lock.json"),
        ),
        (
            "web/check.ts",
            include_bytes!("fixtures/project/web/check.ts"),
        ),
    ];
    for directory in ["rust/src", "python", "web"] {
        fs::create_dir_all(project.path().join(directory))?;
    }
    for (path, bytes) in files {
        fs::write(project.path().join(path), bytes)?;
    }
    Ok(project)
}

#[test]
fn validation_plan_verification_preserves_schema_one_without_graph() -> Result<()> {
    use ladybom::deps::prune_validation::{verify_inventory, ValidationPlan};
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/validation-plan-v1.json"))?;
    let plan: ValidationPlan = serde_json::from_value(expected.clone())?;
    plan.validate()?;
    verify_inventory(&plan, &plan.expected)?;
    assert_eq!(serde_json::to_value(&plan)?, expected);

    let mut stale = plan.expected.clone();
    stale.remove("package.json");
    assert!(verify_inventory(&plan, &stale).is_err());

    let mut altered = plan.clone();
    altered.removed_declarations[0].root.kind = "development".into();
    assert!(altered.validate().is_err());
    let mut duplicate = plan.clone();
    duplicate
        .removed_declarations
        .push(plan.removed_declarations[0].clone());
    assert!(duplicate.validate().is_err());
    Ok(())
}

#[test]
fn report_schema_two_preserves_the_compact_scanner_contract() -> Result<()> {
    let project = fixture_project()?;
    let report = deps::scan_project(project.path())?;
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    assert_eq!(report.schema_version, 2);
    assert_eq!(serde_json::to_value(report)?, expected);
    Ok(())
}

#[test]
fn older_report_v2_without_manifest_package_remains_readable() -> Result<()> {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/report-v2-legacy.json"))?;
    let report: deps::Report = serde_json::from_value(expected.clone())?;
    report.validate()?;
    assert!(report.projects.iter().all(|p| p.manifest_package.is_none()));
    assert_eq!(serde_json::to_value(report)?, expected);
    Ok(())
}

#[test]
fn graph_schema_and_digest_bind_the_compact_inventory() -> Result<()> {
    let project = fixture_project()?;
    let graph = deps::graph::project(deps::scan_project(project.path())?)?;
    let expected: serde_json::Value = serde_json::from_str(include_str!("fixtures/graph-v2.json"))?;
    let historical: deps::graph::Graph = serde_json::from_value(expected.clone())?;
    historical.validate()?;
    assert_eq!(serde_json::to_value(&historical)?, expected);
    let historical_digest = deps::graph::graph_digest(&historical)?;
    assert_eq!(
        historical_digest,
        include_str!("fixtures/graph-v2.sha256").trim()
    );

    // Translation changes human explanations, not inventory or graph structure.
    // Keep the historical artifact and its original digest independently verifiable.
    graph.validate()?;
    assert_eq!(historical.limitations.len(), 5);
    assert_eq!(graph.limitations.len(), historical.limitations.len());
    assert!(graph.limitations.iter().all(|text| !text.trim().is_empty()));
    assert!(historical
        .limitations
        .iter()
        .all(|text| !text.trim().is_empty()));
    assert!(graph.inventory.complete);
    assert!(historical.inventory.complete);
    assert!(!graph.complete());
    assert!(!historical.complete());
    assert_ne!(graph.limitations, historical.limitations);
    assert_ne!(deps::graph::graph_digest(&graph)?, historical_digest);

    // Restoring only the historical prose must restore every serialized field
    // and the original digest; all identities, evidence and conditions remain bound.
    let mut with_historical_wording = graph.clone();
    with_historical_wording.limitations = historical.limitations;
    assert_eq!(serde_json::to_value(&with_historical_wording)?, expected);
    assert_eq!(
        deps::graph::graph_digest(&with_historical_wording)?,
        historical_digest
    );
    Ok(())
}
