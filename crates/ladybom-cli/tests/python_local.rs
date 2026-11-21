#[cfg(feature = "graph")]
use ladybom_graph as graph;
use serde_json::Value;
use std::{fs, path::Path, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(root: &Path) -> TestResult {
    fs::write(
        root.join("pyproject.toml"),
        "[project]\nname='Local_Project'\nversion='1.0.0'\ndependencies=['idna==3.10']\n",
    )?;
    fs::write(
        root.join("uv.lock"),
        "version=1\n\
        [[package]]\nname='local-project'\nversion='1.0.0'\nsource={editable='.'}\n\
        resolution-markers=[\"sys_platform == 'win32'\"]\ndependencies=[{name='idna'}]\n\
        [[package]]\nname='idna'\nversion='3.10'\nsource={registry='https://pypi.org/simple'}\n",
    )?;
    fs::write(
        root.join("setup.py"),
        "from pathlib import Path\nPath('executed').write_text('not allowed')\n",
    )?;
    Ok(())
}

#[test]
fn local_manifest_evidence_is_deterministic_without_project_execution() -> TestResult {
    let root = tempfile::tempdir()?;
    fixture(root.path())?;
    let scan = || {
        Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .args(["scan", "--project"])
            .arg(root.path())
            .arg("--json")
            .current_dir(root.path())
            .env("PATH", "/no-project-executables")
            .output()
    };
    let first = scan()?;
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let report: Value = serde_json::from_slice(&first.stdout)?;
    assert_eq!(
        report["projects"][0]["manifest_package"]["name"],
        "local-project"
    );
    assert_eq!(
        report["projects"][0]["manifest_package"]["version"],
        "1.0.0"
    );
    let local = report["projects"][0]["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .find(|c| c["name"] == "local-project")
        .ok_or("local")?;
    assert!(local["purl"].is_null());
    assert_eq!(local["source"]["editable"], ".");
    let second = scan()?;
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(!root.path().join("executed").exists());
    Ok(())
}

#[cfg(feature = "graph")]
#[test]
fn exported_local_identity_keeps_unknown_activation_and_plan_limits() -> TestResult {
    let root = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    fixture(root.path())?;
    let snapshot = output.path().join("graph");
    let exported = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "export", "--project"])
        .arg(root.path())
        .arg("--output")
        .arg(&snapshot)
        .env("PATH", "/no-project-executables")
        .output()?;
    assert_eq!(
        exported.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let restored = graph::read_snapshot(&snapshot)?;
    assert!(restored
        .components
        .iter()
        .any(|n| n.key.purl == "pkg:generic/python-local/local-project@1.0.0"));
    assert_eq!(restored.dependencies.len(), 1);
    let planned = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment-plan", "--snapshot"])
        .arg(&snapshot)
        .env("PATH", "/no-project-executables")
        .output()?;
    // All locked versions can be analyzed while target activation remains unknown.
    assert_eq!(planned.status.code(), Some(0));
    let plan: Value = serde_json::from_slice(&planned.stdout)?;
    assert_eq!(plan["alignment"]["coverage"]["unidentified_components"], 0);
    assert_eq!(plan["alignment"]["coverage"]["unprojected_components"], 0);
    assert_eq!(plan["alignment"]["coverage"]["unmapped_nodes"], 0);
    assert_eq!(plan["alignment"]["coverage"]["activation_known"], false);
    assert_eq!(plan["analysis_complete"], true);
    assert_eq!(plan["remediation_approved"], false);
    assert!(!root.path().join("executed").exists());
    Ok(())
}
