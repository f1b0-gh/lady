use ladybom::deps;
use ladybom_graph as graph;
use serde_json::json;
use std::fs;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const COMMIT: &str = "0123456789012345678901234567890123456789";
const OTHER: &str = "abcdef0123456789012345678901234567890123";
const REPO: &str = "https://example.invalid/repo";

fn scan(dependency: &str, packages: &str) -> Result<deps::Report> {
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join("Cargo.toml"),
        format!("[package]\nname='app'\nversion='1.0.0'\n[dependencies]\n{dependency}\n"),
    )?;
    fs::write(
        dir.path().join("Cargo.lock"),
        format!("version=4\n{packages}"),
    )?;
    Ok(deps::scan_project(dir.path())?)
}

fn package(source: &str) -> String {
    format!("[[package]]\nname='actual'\nversion='1.2.3'\nsource='{source}'\n")
}

#[test]
fn locked_git_identity_keeps_version_repository_and_commit() -> Result {
    let source = format!("git+{REPO}?branch=stable#{COMMIT}");
    let report = scan(
        &format!("alias={{package='actual',git='{REPO}',branch='stable',version='1'}}"),
        &package(&source),
    )?;
    let graph = graph::project(report)?;
    assert!(graph::alignment(&graph)?.coverage.versions_complete);
    Ok(())
}

#[test]
fn unresolved_or_unsupported_git_locations_remain_unidentified() -> Result {
    for source in [
        format!("git+{REPO}"),
        format!("git+{REPO}#0123456"),
        format!("git+{REPO}#{}", "z".repeat(40)),
        format!("git+ssh://git@example.invalid/repo#{COMMIT}"),
        format!("git+file:///tmp/repo#{COMMIT}"),
    ] {
        let report = scan(&format!("actual={{git='{REPO}'}}"), &package(&source))?;
        let graph = graph::project(report)?;
        assert!(!graph::alignment(&graph)?.coverage.versions_complete);
    }
    Ok(())
}

#[test]
fn snapshot_validation_rechecks_git_provenance_after_public_graph_mutation() -> Result {
    let original = graph::project(scan("", &package(&format!("git+{REPO}#{COMMIT}")))?)?;
    for inventory in [true, false] {
        let mut graph = original.clone();
        let component = if inventory {
            &mut graph.inventory.projects[0].components[0]
        } else {
            &mut graph.components[0].component
        };
        component.metadata["source"] = json!(format!("git+{REPO}#{OTHER}"));
        let dir = tempfile::tempdir()?;
        assert!(graph::write_snapshot(&graph, &dir.path().join("forged")).is_err());
    }
    Ok(())
}

#[test]
fn git_source_substitution_stays_a_policy_regression_after_snapshot_roundtrip() -> Result {
    let baseline = graph::project(scan(
        "",
        &package("registry+https://github.com/rust-lang/crates.io-index"),
    )?)?;
    let current = graph::project(scan("", &package(&format!("git+{REPO}#{COMMIT}")))?)?;
    let dir = tempfile::tempdir()?;
    graph::write_snapshot(&current, &dir.path().join("snapshot"))?;
    let current = graph::read_snapshot(&dir.path().join("snapshot"))?;
    let policy = graph::AlignmentPolicy {
        schema_version: 1,
        baseline_graph_digest: graph::graph_digest(&baseline)?,
        exceptions: vec![],
    };
    let result =
        graph::check_alignment_policy(&current, &baseline, &policy, "2026-11-05T12:00:00Z")?;
    assert!(result.complete);
    assert!(!result.non_regression_pass);
    assert!(result.problems.iter().any(|s| s.contains("source_changed")));
    Ok(())
}
