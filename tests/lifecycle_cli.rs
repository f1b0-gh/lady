use std::{fs, process::Command};
#[test]
fn sessions_reach_state_validation_and_remote_auth_is_callable(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    for name in ["shell", "chat", "resume"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg(name)
            .arg("--state")
            .arg(root.path().join(name))
            .output()?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("State is missing"),
            "{output:?}"
        );
    }
    let home = root.path().join("codex");
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .arg("remote-auth")
        .env("CODEX_HOME", &home)
        .env("CODEX_ACCOUNT_ID", "12345678-1234-5678-9abc-123456789abc")
        .env(
            "CODEX_AUTH_ACCESS_TOKEN",
            "openshell:resolve:env:CODEX_AUTH_ACCESS_TOKEN",
        )
        .output()?;
    assert!(output.status.success(), "{output:?}");
    let auth: serde_json::Value = serde_json::from_slice(&fs::read(home.join("auth.json"))?)?;
    assert_eq!(
        auth["tokens"]["access_token"],
        "openshell:resolve:env:CODEX_AUTH_ACCESS_TOKEN"
    );
    Ok(())
}
#[test]
fn apply_reaches_input_validation() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args([
            "apply",
            "--config",
            "/missing.ncl",
            "--resources",
            "/missing",
            "--codex",
            "/missing",
            "--codex-code-mode-host",
            "/missing",
            "--project",
        ])
        .arg(root.path())
        .arg("--state")
        .arg(root.path().join("state"))
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside the project"),
        "{output:?}"
    );
    Ok(())
}
#[test]
fn session_cli_checks_policy_and_preserves_child_exit() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    let directory = root.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    let binary = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
    let state = serde_json::json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash","codex_binary":binary,"owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"test","workspace":"default"},"desired_inputs":{"evaluated":{"config":{"sandbox":{"provider":"test-provider"}}}}});
    fs::write(directory.join("state.json"), serde_json::to_vec(&state)?)?;
    fs::write(root.path().join("observed.json"), br#"{"id":"id","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}"#)?;
    fs::write(
        root.path().join("policy.json"),
        serde_json::to_vec(
            &serde_json::json!({"policy":ladyshell::policy::native_policy(binary)?}),
        )?,
    )?;
    let script = root.path().join("openshell");
    fs::write(
        &script,
        r#"#!/bin/bash
set -euo pipefail
shift 6
case "$1 $2" in
  'sandbox get') /bin/cat "$FIXTURE/observed.json" ;;
  'policy get') /bin/cat "$FIXTURE/policy.json" ;;
  'provider get') echo available ;;
  'sandbox exec') printf '%s\n' "$@" > "$FIXTURE/exec.args"; exit 37 ;;
  *) exit 99 ;;
esac
"#,
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let home = root.path().join("home");
    fs::create_dir(&home)?;
    fs::write(home.join("auth.json"), br#"{"tokens":{"account_id":"12345678-1234-5678-9abc-123456789abc","access_token":"HOST_SECRET_MARKER"}}"#)?;
    for command in ["shell", "chat", "resume"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .arg(command)
            .arg("--state")
            .arg(&directory)
            .env("PATH", root.path())
            .env("FIXTURE", root.path())
            .env("CODEX_HOME", &home)
            .output()?;
        assert_eq!(output.status.code(), Some(37), "{output:?}");
        let args = fs::read_to_string(root.path().join("exec.args"))?;
        assert!(args.contains("--tty\n--no-login-shell\n"));
        assert!(!args.contains("HOST_SECRET_MARKER"));
        if command != "shell" {
            assert!(args.contains("remote-auth"));
        }
        if command == "resume" {
            assert!(args.ends_with("resume\n--last\n"));
        }
    }
    fs::remove_file(root.path().join("exec.args"))?;
    fs::write(root.path().join("policy.json"), br#"{"policy":{}}"#)?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["shell", "--state"])
        .arg(&directory)
        .env("PATH", root.path())
        .env("FIXTURE", root.path())
        .output()?;
    assert!(!output.status.success());
    assert!(!root.path().join("exec.args").exists());
    Ok(())
}
