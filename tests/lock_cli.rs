use std::{fs, path::Path, process::Command};
#[test]
fn lock_cli_hashes_artifacts_without_running_project_checks(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let entry = dir.path().join("sandbox.ncl");
    let text = fs::read_to_string(root.join("tests/fixtures/nickel/sandbox.ncl"))?.replace(
        "[\"bash\", \"scripts/check.sh\", \"--container\"]",
        "[\"touch\", \"DO_NOT_EXECUTE\"]",
    );
    fs::write(&entry, text)?;
    let artifact = dir.path().join("codex");
    fs::write(&artifact, b"\x7fELFsynthetic-artifact")?;
    let lock = dir.path().join("test.lock.json");
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("lock")
        .arg("--config")
        .arg(&entry)
        .arg("--project")
        .arg(dir.path())
        .arg("--state")
        .arg(
            dir.path()
                .parent()
                .ok_or("Fixture invalide : valeur absente")?
                .join("unused-state"),
        )
        .arg("--resources")
        .arg(root)
        .arg("--codex")
        .arg(&artifact)
        .arg("--codex-code-mode-host")
        .arg(&artifact)
        .arg("--lock")
        .arg(&lock)
        .current_dir(dir.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dir.path().join("DO_NOT_EXECUTE").exists());
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(lock)?)?;
    assert_eq!(receipt["configuration"]["config"]["mission"], "dev");
    assert_eq!(
        receipt["artifacts_sha256"]["codex"]
            .as_str()
            .ok_or("Fixture invalide : valeur absente")?
            .len(),
        64
    );
    Ok(())
}
#[test]
fn distinguishes_validation_errors_from_missing_host_tools(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let invalid = dir.path().join("invalid.txt");
    fs::write(&invalid, "{}")?;
    let valid = dir.path().join("sandbox.ncl");
    fs::copy(root.join("tests/fixtures/nickel/sandbox.ncl"), &valid)?;
    for (entry, expected) in [(&invalid, 2), (&valid, 1)] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg("lock")
            .arg("--config")
            .arg(entry)
            .args(["--project", "/tmp", "--state", "/state"])
            .arg("--resources")
            .arg(root)
            .args(["--codex", "/absent", "--codex-code-mode-host", "/absent"])
            .env("PATH", "")
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn external_report_is_checked_before_lock_and_plan_and_bound_in_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let project = dir.path().join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::write(project.join("src/lib.rs"), "// data only\n")?;
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )?;
    let entry = dir.path().join("sandbox.ncl");
    fs::write(
        &entry,
        fs::read_to_string(root.join("tests/fixtures/nickel/sandbox.ncl"))?
            .replace("[\"README.md\", \"src\"]", "[\"Cargo.toml\", \"src\"]"),
    )?;
    let artifact = dir.path().join("codex");
    fs::write(&artifact, b"\x7fELFsynthetic-artifact")?;
    let lock = dir.path().join("environment.lock.json");
    let report_path = dir.path().join("ladybom.json");
    let report = ladyshell::deps::scan_project(&project)?;
    fs::write(&report_path, serde_json::to_vec(&report)?)?;
    let run = |operation: &str| -> std::io::Result<std::process::Output> {
        Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg(operation)
            .arg("--config")
            .arg(&entry)
            .arg("--project")
            .arg(&project)
            .arg("--state")
            .arg(dir.path().join("state"))
            .arg("--resources")
            .arg(root)
            .arg("--codex")
            .arg(&artifact)
            .arg("--codex-code-mode-host")
            .arg(&artifact)
            .arg("--lock")
            .arg(&lock)
            .arg("--ladybom")
            .arg(&report_path)
            .output()
    };
    let locked = run("lock")?;
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(&lock)?)?;
    assert_eq!(
        receipt["ladybom_sha256"],
        ladyshell::files::hash(&serde_json::to_vec(&report)?)
    );
    let before = fs::read(&lock)?;
    let mut fake = serde_json::to_value(report)?;
    fake["projects"] = serde_json::json!([]);
    fs::write(&report_path, serde_json::to_vec(&fake)?)?;
    for operation in ["lock", "plan", "apply"] {
        let rejected = run(operation)?;
        assert!(!rejected.status.success());
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("Rapport Ladybom divergent"),
            "{}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
    assert_eq!(before, fs::read(&lock)?);
    assert!(!dir.path().join("state").exists());
    Ok(())
}
