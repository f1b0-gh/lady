use std::{
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    process::Command,
};

fn tool(directory: &std::path::Path, body: &str) -> std::io::Result<std::path::PathBuf> {
    let path = directory.join("bootc tool");
    fs::write(&path, format!("#!/usr/bin/python3\n{body}\n"))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[test]
fn compatibility_forwards_arguments_bytes_output_and_exit_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let child = tool(temp.path(), "import os,sys,json\nprint(json.dumps([os.fsencode(a).hex() for a in sys.argv[1:]]))\nprint('child diagnostic',file=sys.stderr)\nsys.exit(37)")?;
    let arguments = vec![
        "inspect".into(),
        "--receipt".into(),
        std::ffi::OsString::from_vec(b"a path with spaces-\xff.json".to_vec()),
        "--unknown-option".into(),
    ];
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("artifact")
        .args(&arguments)
        .env("LADYSHELL_BOOTC_BIN", child)
        .output()?;
    assert_eq!(output.status.code(), Some(37));
    let expected: Vec<String> = arguments
        .into_iter()
        .map(|a| a.into_vec().iter().map(|b| format!("{b:02x}")).collect())
        .collect();
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(&output.stdout)?,
        expected
    );
    assert_eq!(output.stderr, b"child diagnostic\n");
    Ok(())
}

#[test]
fn compatibility_forwards_help_and_reports_a_missing_installation(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let child = tool(
        temp.path(),
        "import sys\nassert sys.argv[1:] == ['--help']\nprint('independent bootc help')",
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["artifact", "--help"])
        .env("LADYSHELL_BOOTC_BIN", child)
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"independent bootc help\n");
    let missing = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["artifact", "check"])
        .env("LADYSHELL_BOOTC_BIN", temp.path().join("missing"))
        .output()?;
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8(missing.stderr)?.contains("LADYSHELL_BOOTC_BIN"));
    assert!(missing.stdout.is_empty());
    Ok(())
}

#[test]
fn compatibility_preserves_option_terminator() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let child = tool(
        temp.path(),
        "import json,sys\nprint(json.dumps(sys.argv[1:]))",
    )?;
    for arguments in [
        vec!["--"],
        vec!["--", "--help"],
        vec!["--", "check", "--config", "a path"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg("artifact")
            .args(&arguments)
            .env("LADYSHELL_BOOTC_BIN", &child)
            .output()?;
        assert!(output.status.success());
        assert_eq!(
            serde_json::from_slice::<Vec<String>>(&output.stdout)?,
            arguments
        );
    }
    Ok(())
}

#[test]
fn compatibility_finds_the_independent_ladyboot_installation(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let child = tool(
        temp.path(),
        "import sys\nassert sys.argv[1:] == ['--help']\nprint('ladyboot installed')",
    )?;
    fs::rename(child, temp.path().join("ladyboot"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["artifact", "--help"])
        .env_remove("LADYSHELL_BOOTC_BIN")
        .env("PATH", temp.path())
        .output()?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"ladyboot installed\n");
    Ok(())
}
