#![cfg(feature = "graph")]

use ladybom::deps::{
    self,
    graph::{self, AlignmentExplanationOptions, Ladybug},
};
use serde_json::json;
use std::{fs, time::Duration};

fn fixture() -> Result<(tempfile::TempDir, graph::Graph), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("package.json"),
        json!({"name":"test","dependencies":{"a":"1.0.0"}}).to_string(),
    )?;
    fs::write(root.path().join("package-lock.json"), json!({"lockfileVersion":3,"packages":{"":{"name":"test"},"node_modules/a":{"version":"1.0.0"}}}).to_string())?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    Ok((root, graph))
}

#[test]
fn explanation_options_refuse_invalid_bounds_and_versioned_identity_before_execution(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_root, graph) = fixture()?;
    let engine = Ladybug::new(std::env::current_exe()?)?;
    let cases = [
        AlignmentExplanationOptions {
            max_queries: 0,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            max_queries: 17,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            max_results: 0,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            max_results: 4097,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            max_depth: 0,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            max_depth: 65,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            timeout: Duration::ZERO,
            ..Default::default()
        },
        AlignmentExplanationOptions {
            timeout: Duration::from_secs(301),
            ..Default::default()
        },
        AlignmentExplanationOptions {
            package: Some("pkg:npm/a@1.0.0".into()),
            ..Default::default()
        },
        AlignmentExplanationOptions {
            package: Some("pkg:npm/absent".into()),
            ..Default::default()
        },
        AlignmentExplanationOptions {
            package: Some("'; CREATE NODE TABLE x(id STRING, PRIMARY KEY(id));".into()),
            ..Default::default()
        },
    ];
    for options in cases {
        assert!(
            engine.explain_alignment(&graph, &options).is_err(),
            "{options:?}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_explanation_preserves_paths_across_npm_scopes_and_marks_output_truncation(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("package.json"),
        json!({"name":"test","dependencies":{"a":"1.0.0"}}).to_string(),
    )?;
    fs::write(
        root.path().join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":{
            "":{"name":"test"},
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1.0.0"}},
            "node_modules/a/node_modules/b":{"version":"1.0.0"}
        }})
        .to_string(),
    )?;
    let mut graph = graph::project(deps::scan_project(root.path())?)?;
    let engine = Ladybug::new(
        std::env::var_os("LADYBOM_LADYBUG_BIN")
            .ok_or("engine")?
            .into(),
    )?;
    let mut options = AlignmentExplanationOptions {
        package: Some("pkg:npm/b".into()),
        ..Default::default()
    };
    let report = engine.explain_alignment(&graph, &options)?;
    assert!(report.complete());
    let explanations = report.explanations.ok_or("explanations")?;
    assert_eq!(explanations.results[0].nodes.len(), 1);
    assert_eq!(explanations.results[0].roots.len(), 1);
    assert_eq!(explanations.results[0].nodes[0].path.len(), 2);
    options.max_results = 1;
    let bounded = engine.explain_alignment(&graph, &options)?;
    assert!(!bounded.complete());
    assert!(bounded.explanations.ok_or("bounded")?.truncated);
    graph.dependencies[0].condition = json!({"optional":true});
    options.max_results = 4096;
    let conditional = engine.explain_alignment(&graph, &options)?;
    assert!(!conditional.complete());
    assert!(conditional.alignment.coverage.versions_complete);
    assert!(conditional.explanations.ok_or("conditional")?.results[0].potential);
    Ok(())
}
