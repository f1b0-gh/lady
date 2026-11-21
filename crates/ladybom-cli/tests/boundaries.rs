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

#[test]
fn graph_and_prune_are_available_only_in_full_builds() -> Result {
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for name in ["graph", "prune"] {
        assert_eq!(
            help.lines()
                .any(|l| l.split_whitespace().next() == Some(name)),
            cfg!(feature = "graph")
        );
        let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .args([name, "--help"])
            .output()?;
        assert_eq!(output.status.success(), cfg!(feature = "graph"));
    }
    for name in ["scan", "artifact", "interop", "vuln", "vxdf"] {
        assert!(help
            .lines()
            .any(|l| l.split_whitespace().next() == Some(name)));
    }
    Ok(())
}
