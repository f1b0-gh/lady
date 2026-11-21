// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
use std::{error::Error, fs, process::Command};
#[test]
fn safe_input_and_generic_diagnostics() -> Result<(), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!("audit-validator-test-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let file = dir.join("input.json");
    fs::write(&file, b"[]")?;
    let run = |path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_audit-validator"))
            .arg("findings")
            .arg(path)
            .output()
    };
    assert!(run(&file)?.status.success());
    assert!(!run(&dir)?.status.success());
    #[cfg(unix)]
    {
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link)?;
        assert!(!run(&link)?.status.success());
    }
    let missing = dir.join("\u{1b}[31msecret");
    let output = run(&missing)?;
    assert!(!output.status.success());
    assert!(!output.stderr.contains(&27));
    fs::remove_dir_all(dir)?;
    Ok(())
}
#[test]
fn reports_version_for_packaging() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_audit-validator"))
        .arg("--version")
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!("audit-validator {}\n", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn output_failures_return_failure_without_panicking() -> Result<(), Box<dyn Error>> {
    let full = fs::OpenOptions::new().write(true).open("/dev/full")?;
    let output = Command::new(env!("CARGO_BIN_EXE_audit-validator"))
        .arg("--version")
        .stdout(full)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!String::from_utf8(output.stderr)?.contains("panicked"));
    let full = fs::OpenOptions::new().write(true).open("/dev/full")?;
    let output = Command::new(env!("CARGO_BIN_EXE_audit-validator"))
        .arg("invalid-command")
        .stderr(full)
        .output()?;
    assert_eq!(output.status.code(), Some(1));
    Ok(())
}
