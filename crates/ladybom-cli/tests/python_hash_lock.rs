use ladybom::deps::graph;
use serde_json::Value;
use std::{fs, path::Path, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(root: &Path) -> std::io::Result<()> {
    fs::write(root.join("requirements.in"), "idna>=3\n")?;
    fs::write(
        root.join("requirements.lock"),
        format!(
            "idna==3.10 ; sys_platform == 'linux' --hash=sha256:{}\n# via invented-parent\n",
            "a".repeat(64)
        ),
    )
}

#[test]
fn hashed_pins_are_visible_in_deterministic_incomplete_reports() -> TestResult {
    let root = tempfile::tempdir()?;
    fixture(root.path())?;
    let scan = || {
        Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .args(["scan", "--project"])
            .arg(root.path())
            .arg("--json")
            .env("PATH", "/no-project-executables")
            .output()
    };
    let first = scan()?;
    assert_eq!(first.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(report["complete"], false);
    let projects = report["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0]["manifest"], "requirements.in");
    assert_eq!(projects[0]["requirements"][0]["constraint"], ">=3");
    assert_eq!(projects[1]["manifest"], "requirements.lock");
    assert_eq!(projects[1]["requirements"], serde_json::json!([]));
    let component = &projects[1]["components"][0];
    assert_eq!(component["purl"], "pkg:pypi/idna@3.10");
    assert_eq!(component["source"]["pip-index"], "unverified");
    assert_eq!(component["artifacts"], serde_json::json!([]));
    assert_eq!(
        component["metadata"]["pip"]["records"][0]["hashes"][0],
        format!("sha256:{}", "a".repeat(64))
    );
    let second = scan()?;
    assert_eq!(second.status.code(), Some(2));
    assert_eq!(first.stdout, second.stdout);
    Ok(())
}

#[test]
fn graph_and_alignment_plan_retain_flat_inventory_limits() -> TestResult {
    let root = tempfile::tempdir()?;
    let exported = tempfile::tempdir()?;
    fixture(root.path())?;
    // A separate declaration must not become a root of the unassociated lock.
    let snapshot = exported.path().join("snapshot");
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "export", "--project"])
        .arg(root.path())
        .arg("--output")
        .arg(&snapshot)
        .env("PATH", "/no-project-executables")
        .output()?;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let restored = graph::read_snapshot(&snapshot)?;
    assert_eq!(restored.components.len(), 1);
    assert!(restored.dependencies.is_empty());
    assert!(restored.roots.is_empty());
    assert!(!restored.complete());
    assert_eq!(restored.inventory.projects.len(), 2);
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment-plan", "--snapshot"])
        .arg(&snapshot)
        .env("PATH", "/no-project-executables")
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let plan: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(plan["analysis_complete"], false);
    assert_eq!(plan["remediation_approved"], false);
    assert!(plan["actions"]
        .as_array()
        .ok_or("actions missing")?
        .iter()
        .any(|a| a["kind"] == "complete_coverage"));
    Ok(())
}
