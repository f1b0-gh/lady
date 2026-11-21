use ladybom::deps::{self, graph};
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

fn snapshot(
    root: &Path,
    name: &str,
    versions: &[&str],
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let project = root.join(name);
    fs::create_dir(&project)?;
    fs::write(
        project.join("package.json"),
        json!({"name":"demo","version":"1.0.0","scripts":{"postinstall":"touch EXECUTED"}})
            .to_string(),
    )?;
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name":"demo","version":"1.0.0"}));
    for (i, version) in versions.iter().enumerate() {
        packages.insert(
            format!("node_modules/parent{i}/node_modules/shared"),
            json!({"name":"shared","version":version}),
        );
    }
    fs::write(
        project.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":packages}).to_string(),
    )?;
    let graph = graph::project(deps::scan_project(&project)?)?;
    let output = root.join(format!("{name}-snapshot"));
    graph::write_snapshot(&graph, &output)?;
    Ok(output)
}
fn run(
    root: &Path,
    current: &Path,
    baseline: &Path,
    strict: bool,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
    command
        .args(["graph", "alignment-policy", "--snapshot"])
        .arg(current)
        .arg("--baseline")
        .arg(baseline)
        .arg("--policy")
        .arg(root.join("policy.json"))
        .args(["--as-of", "2026-11-05T12:00:00Z"]);
    if strict {
        command.arg("--require-reviewed");
    }
    Ok(command.output()?)
}
fn policy(root: &Path, baseline: &Path) -> TestResult {
    fs::write(root.join("policy.json"), json!({
        "schema_version":1, "baseline_graph_digest":graph::graph_digest(&graph::read_snapshot(baseline)?)?, "exceptions":[]
    }).to_string())?;
    Ok(())
}

#[test]
fn cli_keeps_backlog_visible_and_rejects_new_versions() -> TestResult {
    let temp = tempfile::tempdir()?;
    let baseline = snapshot(temp.path(), "base", &["1.0.0", "2.0.0"])?;
    policy(temp.path(), &baseline)?;
    let unchanged = run(temp.path(), &baseline, &baseline, false)?;
    assert!(
        unchanged.status.success(),
        "{}",
        String::from_utf8_lossy(&unchanged.stderr)
    );
    let report: Value = serde_json::from_slice(&unchanged.stdout)?;
    assert_eq!(report["summary"]["unreviewed"], 1);
    assert_eq!(report["non_regression_pass"], true);
    assert_eq!(report["reviewed_alignment_pass"], false);
    assert_eq!(
        run(temp.path(), &baseline, &baseline, true)?.status.code(),
        Some(2)
    );
    let changed = snapshot(temp.path(), "changed", &["1.0.0", "3.0.0"])?;
    let result = run(temp.path(), &changed, &baseline, false)?;
    assert_eq!(result.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(report["summary"]["regressions"], 1);
    assert!(!temp.path().join("base/EXECUTED").exists());
    assert!(!temp.path().join("changed/EXECUTED").exists());
    Ok(())
}

#[test]
fn cli_rejects_unknown_duplicate_oversized_and_foreign_policy_inputs() -> TestResult {
    let temp = tempfile::tempdir()?;
    let baseline = snapshot(temp.path(), "base", &["1.0.0", "2.0.0"])?;
    policy(temp.path(), &baseline)?;
    let original = fs::read_to_string(temp.path().join("policy.json"))?;
    let unknown = original.replacen('{', "{\"allow_unknown\":true,", 1);
    let duplicate = original.replacen('{', "{\"schema_version\":1,", 1);
    let foreign = original.replace(
        &graph::graph_digest(&graph::read_snapshot(&baseline)?)?,
        &"0".repeat(64),
    );
    for invalid in [unknown, duplicate, foreign, " ".repeat(4 * 1024 * 1024 + 1)] {
        fs::write(temp.path().join("policy.json"), invalid)?;
        let output = run(temp.path(), &baseline, &baseline, false)?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    Ok(())
}
