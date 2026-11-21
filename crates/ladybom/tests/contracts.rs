use ladybom::{deps, error::Result};
use std::path::Path;

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
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project");
    let report = deps::scan_project(&project)?;
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

#[cfg(feature = "graph")]
#[test]
fn graph_schema_and_digest_bind_the_compact_inventory() -> Result<()> {
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project");
    let graph = deps::graph::project(deps::scan_project(&project)?)?;
    let expected: serde_json::Value = serde_json::from_str(include_str!("fixtures/graph-v2.json"))?;
    assert_eq!(serde_json::to_value(&graph)?, expected);
    assert_eq!(
        deps::graph::graph_digest(&graph)?,
        include_str!("fixtures/graph-v2.sha256").trim()
    );
    Ok(())
}
