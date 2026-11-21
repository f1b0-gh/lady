use std::process::Command;

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn scan_does_not_need_nickel_openshell_or_ladybug() -> Result {
    let project = tempfile::tempdir()?;
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"independent","version":"1.0.0","scripts":{"postinstall":"exit 99"}}"#,
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .env_clear()
        .env("PATH", project.path())
        .args(["scan", "--json", "--project"])
        .arg(project.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["projects"][0]["ecosystem"], "npm");
    Ok(())
}

#[test]
fn runtime_validation_is_not_an_analysis_command() -> Result {
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["prune", "validate", "--help"])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    Ok(())
}
