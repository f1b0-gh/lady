use ladyshell::audit::{
    journal::RunJournal,
    model::{Budget, Role},
};
use ladyshell_cli::cli::validate_args;
use serde_json::json;
use std::{
    fs,
    io::Write,
    process::{Command, Output, Stdio},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn worker(input: &[u8]) -> Result<Output, Box<dyn std::error::Error>> {
    let mut data = tempfile::tempfile()?;
    data.write_all(input)?;
    use std::io::{Seek, SeekFrom};
    data.seek(SeekFrom::Start(0))?;
    Ok(Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("audit-worker")
        .env_clear()
        .stdin(Stdio::from(data))
        .output()?)
}

#[test]
fn helper_commands_accept_only_their_declared_arguments_and_are_hidden() -> TestResult {
    validate_args(&["ladyshell", "audit-worker"])?;
    validate_args(&[
        "ladyshell",
        "audit-agent",
        "--codex",
        "/tool path/codex",
        "--cpu-seconds",
        "10",
        "--processes",
        "32",
        "--file-bytes",
        "1048576",
    ])?;
    validate_args(&["ladyshell", "audit", "recover", "/run with spaces"])?;
    for arguments in [
        vec!["ladyshell", "audit-worker", "--disable-guards"],
        vec!["ladyshell", "audit-agent"],
        vec![
            "ladyshell",
            "audit-agent",
            "--codex",
            "/bin/codex",
            "--shell",
        ],
        vec!["ladyshell", "audit", "recover"],
    ] {
        assert!(validate_args(&arguments).is_err());
    }
    let help = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("--help")
        .output()?;
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout)?;
    assert!(!help.contains("audit-worker"));
    assert!(!help.contains("audit-agent"));
    Ok(())
}

#[test]
fn worker_rejects_duplicate_keys_unknown_fields_trailing_json_and_oversize_input() -> TestResult {
    for (input, diagnostic) in [
        (
            br#"{"schema_version":1,"schema_version":1}"#.to_vec(),
            "duplicate JSON key",
        ),
        (br#"{} {}"#.to_vec(), "trailing characters"),
        (br#"{"disable_guards":true}"#.to_vec(), "unknown field"),
        (vec![b' '; 16 * 1024 * 1024 + 1], "16 Mio"),
    ] {
        let output = worker(&input)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[test]
fn worker_has_no_host_execution_fallback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("must-not-run");
    let request = json!({
        "schema_version":1,"invocation_id":"host-refusal",
        "command":["/bin/bash","-c","printf executed > \"$1\"","--",marker],
        "limits":{"cpu_seconds":5,"memory_bytes":268435456,"processes":32,"files":128,"disk_bytes":1048576},
        "timeout_seconds":1,"sources":[],"artifacts":[]
    });
    let output = worker(&serde_json::to_vec(&request)?)?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("UID"));
    assert!(!marker.exists());
    Ok(())
}

#[test]
fn agent_helper_refuses_the_host_before_executing_the_requested_binary() -> TestResult {
    let codex = format!("/nix/store/{}-ladyshell-codex/bin/codex", "a".repeat(32));
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args([
            "audit-agent",
            "--codex",
            &codex,
            "--cpu-seconds",
            "10",
            "--processes",
            "32",
            "--file-bytes",
            "1048576",
        ])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("réservé à l’image d’audit"));
    Ok(())
}

#[test]
fn agent_helper_validates_every_limit_before_environment_access() -> TestResult {
    let codex = format!("/nix/store/{}-ladyshell-codex/bin/codex", "a".repeat(32));
    for (cpu, processes, bytes) in [("0", "32", "1024"), ("10", "0", "1024"), ("10", "32", "0")] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args([
                "audit-agent",
                "--codex",
                &codex,
                "--cpu-seconds",
                cpu,
                "--processes",
                processes,
                "--file-bytes",
                bytes,
            ])
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Limites d’agent positives et finies")
        );
    }
    Ok(())
}

#[test]
fn recover_cli_marks_interrupted_work_without_replaying_an_invocation() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let mut journal = RunJournal::create(
        directory.path(),
        &"a".repeat(64),
        Budget {
            invocations: 2,
            seconds: 60,
        },
    )?;
    journal.start()?;
    journal.begin_invocation("synthetic", Role::Recon)?;
    let run = journal.directory().to_path_buf();
    drop(journal);
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["audit", "recover"])
        .arg(&run)
        .env_clear()
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(value["operation"], "recover");
    assert_eq!(value["status"], "interrupted");
    assert_eq!(value["target_executed"], false);
    assert_eq!(value["cleanup_verified"], true);
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("audit-journal.json"))?)?;
    assert_eq!(stored["invocations"].as_array().map(Vec::len), Some(1));
    assert_eq!(stored["invocations"][0]["status"], "interrupted");
    Ok(())
}
