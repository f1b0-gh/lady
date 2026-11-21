use ladybom::deps::graph;
use serde_json::Value;
use std::{fs, path::Path, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
    command.env("PATH", "/no-project-executables");
    command
}

fn scan(root: &Path, sources: &Path) -> std::io::Result<std::process::Output> {
    command()
        .args(["scan", "--project"])
        .arg(root)
        .arg("--sources")
        .arg(sources)
        .arg("--json")
        .output()
}

#[test]
fn go_only_scan_fails_deterministically_without_executing_a_tool() -> TestResult {
    let root = tempfile::tempdir()?;
    let external = tempfile::tempdir()?;
    let sources = external.path().join("sources.json");
    fs::write(
        &sources,
        r#"{"include":["go.mod","go.sum","go.work","go.work.sum"],"exclude":[]}"#,
    )?;
    fs::write(
        root.path().join("go.mod"),
        "module example.org/demo\nrequire example.org/x v1.0.0\n",
    )?;
    fs::write(
        root.path().join("go.sum"),
        "example.org/x v1.0.0 h1:synthetic\n",
    )?;
    fs::write(root.path().join("go.work"), "go 1.26.0\nuse ../outside\n")?;
    fs::write(root.path().join("go.work.sum"), "")?;
    let first = scan(root.path(), &sources)?;
    assert_eq!(
        first.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["inputs"].as_object().ok_or("inputs")?.len(), 4);
    assert!(report["projects"]
        .as_array()
        .ok_or("projects")?
        .iter()
        .any(|p| p["manifest"] == "go.mod"));
    let diagnostics = report["diagnostics"].as_array().ok_or("diagnostics")?;
    assert!(!diagnostics.is_empty());
    assert!(diagnostics.iter().all(|d| d["blocking"] == true));
    let second = scan(root.path(), &sources)?;
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn mixed_project_export_alignment_and_plan_retain_go_coverage_gap() -> TestResult {
    let root = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fs::write(
        root.path().join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","dependencies":{"dep":"1.0.0"},"scripts":{"postinstall":"touch EXECUTED"}}"#,
    )?;
    fs::write(
        root.path().join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"},"node_modules/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz"}}}"#,
    )?;
    let baseline = graph::project(ladybom::scan_project(root.path())?)?;
    assert!(graph::plan_alignment(&baseline)?.analysis_complete);
    fs::write(
        root.path().join("go.mod"),
        "module example.org/demo\nrequire example.org/x v1.0.0\n",
    )?;
    let snapshot = output.path().join("graph");
    let exported = command()
        .args(["graph", "export", "--project"])
        .arg(root.path())
        .arg("--output")
        .arg(&snapshot)
        .output()?;
    assert_eq!(
        exported.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let restored = graph::read_snapshot(&snapshot)?;
    assert_eq!(
        serde_json::to_value(&restored.components)?,
        serde_json::to_value(&baseline.components)?
    );
    assert_eq!(
        serde_json::to_value(&restored.dependencies)?,
        serde_json::to_value(&baseline.dependencies)?
    );
    assert!(!restored.inventory.complete);
    assert_eq!(
        restored.inventory.diagnostics[0].code,
        "go_resolution_unknown"
    );
    for operation in ["alignment", "alignment-plan"] {
        let mut cmd = command();
        cmd.args(["graph", operation, "--snapshot"]).arg(&snapshot);
        if operation == "alignment" {
            cmd.arg("--check");
        }
        let checked = cmd.output()?;
        assert_eq!(
            checked.status.code(),
            Some(2),
            "{operation}: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        let report: Value = serde_json::from_slice(&checked.stdout)?;
        assert_eq!(report["alignment"]["coverage"]["inventory_complete"], false);
        if operation == "alignment-plan" {
            assert_eq!(report["analysis_complete"], false);
            assert_eq!(report["actions"][0]["kind"], "complete_coverage");
        }
    }
    assert!(!root.path().join("EXECUTED").exists());
    Ok(())
}
