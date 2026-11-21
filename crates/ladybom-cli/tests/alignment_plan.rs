use ladybom::deps::{self, graph};
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn snapshot(root: &Path, empty: bool) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    if !empty {
        fs::write(root.join("package.json"), json!({"name":"fixture","version":"1.0.0","dependencies":{"shared":"1.2.3"},"scripts":{"postinstall":"touch EXECUTED"}}).to_string())?;
        fs::write(
            root.join("package-lock.json"),
            json!({"lockfileVersion":3,"packages":{
                "":{"name":"fixture","version":"1.0.0"},
                "node_modules/shared":{"version":"1.2.3"},
                "node_modules/parent/node_modules/shared":{"version":"2.0.0"}
            }})
            .to_string(),
        )?;
    }
    let snapshot = root.join("snapshot");
    graph::write_snapshot(&graph::project(deps::scan_project(root)?)?, &snapshot)?;
    Ok(snapshot)
}

// A plan reads the verified snapshot even after its source project disappears.
#[test]
fn json_and_markdown_are_offline_snapshot_only_and_keep_digest() -> TestResult {
    let temp = tempfile::tempdir()?;
    let snapshot = snapshot(temp.path(), false)?;
    let manifest = fs::read(snapshot.join("manifest.json"))?;
    let expected: Value = serde_json::from_slice(&manifest)?;
    fs::remove_file(temp.path().join("package.json"))?;
    fs::remove_file(temp.path().join("package-lock.json"))?;
    for markdown in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
        command
            .args(["graph", "alignment-plan", "--snapshot"])
            .arg(&snapshot);
        if markdown {
            command.arg("--markdown");
        }
        let output = command.env("PATH", "/no-executables").output()?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if markdown {
            let text = String::from_utf8(output.stdout)?;
            assert!(text.starts_with("# Duplicate reduction plan"));
            assert!(text.contains("pkg&#58;npm/shared"));
        } else {
            let value: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["graph_digest"], expected["logical_sha256"]);
            assert_eq!(value["remediation_approved"], false);
            assert_eq!(value["actions"][0]["kind"], "review_lock_resolution");
            assert_eq!(
                value["alignment"]["pins"][0]["requirement"]["constraint"],
                "1.2.3"
            );
        }
    }
    assert_eq!(fs::read(snapshot.join("manifest.json"))?, manifest);
    assert!(!temp.path().join("EXECUTED").exists());
    Ok(())
}

// Empty coverage still emits its diagnosis but cannot return successful analysis.
#[test]
fn incomplete_plan_exits_two_in_both_formats() -> TestResult {
    let temp = tempfile::tempdir()?;
    let snapshot = snapshot(temp.path(), true)?;
    for markdown in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
        command
            .args(["graph", "alignment-plan", "--snapshot"])
            .arg(&snapshot);
        if markdown {
            command.arg("--markdown");
        }
        let output = command.output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(!output.stdout.is_empty());
        if !markdown {
            let value: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(value["analysis_complete"], false);
            assert_eq!(value["actions"][0]["kind"], "complete_coverage");
        }
    }
    Ok(())
}

// Tampering must not bypass the snapshot integrity boundary through the new command.
#[test]
fn tampered_snapshot_is_rejected_without_a_plan() -> TestResult {
    let temp = tempfile::tempdir()?;
    let snapshot = snapshot(temp.path(), false)?;
    fs::write(snapshot.join("inventory.json"), b"{}")?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment-plan", "--snapshot"])
        .arg(snapshot)
        .output()?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Digest mismatch"));
    Ok(())
}
