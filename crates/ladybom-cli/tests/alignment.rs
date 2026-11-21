#![cfg(feature = "graph")]

use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn fixture(root: &Path, versions: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(root.join("package.json"), json!({"name":"demo","version":"1.0.0","dependencies":{"a":"1.0.0"},"scripts":{"postinstall":"touch EXECUTED"}}).to_string())?;
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name":"demo","version":"1.0.0"}));
    for (index, version) in versions.iter().enumerate() {
        let path = if index == 0 {
            "node_modules/a".to_owned()
        } else {
            format!("node_modules/parent{index}/node_modules/a")
        };
        packages.insert(path, json!({"name":"a","version":version}));
    }
    fs::write(
        root.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":packages}).to_string(),
    )?;
    Ok(())
}

fn export(root: &Path, snapshot: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "export", "--project"])
        .arg(root)
        .arg("--output")
        .arg(snapshot)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn audit_reports_conflicts_and_check_rejects_them_without_running_project_code(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fixture(temp.path(), &["1.0.0", "2.0.0"])?;
    let snapshot = temp.path().join("snapshot");
    export(temp.path(), &snapshot)?;
    for check in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
        command
            .args(["graph", "alignment", "--snapshot"])
            .arg(&snapshot);
        if check {
            command.arg("--check");
        }
        let output = command.output()?;
        assert_eq!(
            output.status.code(),
            Some(if check { 2 } else { 0 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(value["alignment"]["aligned"], false);
        assert_eq!(value["alignment"]["pins_compliant"], true);
        assert!(value["alignment"]["groups"]
            .as_array()
            .ok_or("groups")?
            .iter()
            .any(|g| g["identity"] == "pkg:npm/a" && g["duplicate"] == true));
        assert!(value["explanations"].is_null());
    }
    assert!(!temp.path().join("EXECUTED").exists());
    Ok(())
}

#[test]
fn export_honors_sources_and_check_requires_pins_and_coverage(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fixture(temp.path(), &["1.0.0"])?;
    fs::create_dir(temp.path().join("excluded"))?;
    fs::write(temp.path().join("excluded/Cargo.toml"), "invalid TOML [")?;
    let sources = temp.path().join("sources.json");
    fs::write(
        &sources,
        json!({"include":["package.json","package-lock.json"],"exclude":[]}).to_string(),
    )?;
    let snapshot = temp.path().join("snapshot");
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "export", "--project"])
        .arg(temp.path())
        .arg("--sources")
        .arg(&sources)
        .arg("--output")
        .arg(&snapshot)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let checked = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment", "--check", "--snapshot"])
        .arg(&snapshot)
        .output()?;
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let value: Value = serde_json::from_slice(&checked.stdout)?;
    assert_eq!(value["alignment"]["aligned"], true);
    assert_eq!(value["alignment"]["coverage"]["versions_complete"], true);
    Ok(())
}

#[test]
fn empty_snapshot_cannot_pass_alignment_check() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let snapshot = temp.path().join("snapshot");
    export(temp.path(), &snapshot)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment", "--check", "--snapshot"])
        .arg(&snapshot)
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert!(value["alignment"]["aligned"].is_null());
    Ok(())
}

#[test]
fn exact_manifest_pin_with_a_different_locked_version_cannot_pass_check(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fixture(temp.path(), &["2.0.0"])?;
    let snapshot = temp.path().join("snapshot");
    let graph = ladybom::deps::graph::project(ladybom::deps::scan_project(temp.path())?)?;
    ladybom_graph::write_snapshot(&graph, &snapshot)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment", "--check", "--snapshot"])
        .arg(&snapshot)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["alignment"]["aligned"], true);
    assert_eq!(value["alignment"]["pins_compliant"], true);
    assert_ne!(value["alignment"]["pin_lock_consistent"], true);
    Ok(())
}

#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_alignment_explains_nested_contexts_and_query_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fixture(temp.path(), &["1.0.0", "2.0.0"])?;
    let snapshot = temp.path().join("snapshot");
    export(temp.path(), &snapshot)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "alignment", "--snapshot"])
        .arg(&snapshot)
        .arg("--engine")
        .arg(std::env::var_os("LADYBOM_LADYBUG_BIN").ok_or("engine")?)
        .args(["--package", "pkg:npm/a", "--max-queries", "1"])
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["explanations"]["selected_occurrences"], 2);
    assert_eq!(value["explanations"]["queries_run"], 1);
    assert_eq!(value["explanations"]["truncated"], true);
    assert_eq!(
        value["explanations"]["results"][0]["roots"][0]["manifest"],
        "package.json"
    );
    Ok(())
}
