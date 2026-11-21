use std::{error::Error, fs, process::Command};

#[test]
fn validates_documents_offline_and_returns_stable_codes() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("rapport avec espaces.json");
    fs::write(&file, "[]")?;
    for mode in ["findings", "coverage"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .env_clear()
            .args(["audit", "validate", mode])
            .arg(&file)
            .output()?;
        assert_eq!(output.status.code(), Some(0), "{:?}", output);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["records"], 0);
        assert_eq!(value["document_valid"], true);
        assert!(value.get("secure").is_none());
    }
    fs::write(&file, "[{}]")?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "validate", "findings"])
        .arg(&file)
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8(output.stderr)?.contains("$[0]"));
    fs::remove_file(&file)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "validate", "findings"])
        .arg(&file)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    Ok(())
}

#[test]
fn refuses_links_limits_and_output_failure() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("input.json");
    fs::write(&file, "[]")?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&file, &link)?;
    let run = |path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(["audit", "validate", "findings"])
            .arg(path)
            .output()
    };
    assert!(!run(&link)?.status.success());
    let hard = dir.path().join("hard");
    fs::hard_link(&file, &hard)?;
    assert!(!run(&hard)?.status.success());
    fs::remove_file(hard)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "validate", "findings"])
        .arg(&file)
        .stdout(fs::OpenOptions::new().write(true).open("/dev/full")?)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    fs::write(&file, vec![b' '; 5 * 1024 * 1024 + 1])?;
    assert_eq!(run(&file)?.status.code(), Some(2));
    Ok(())
}
