use serde_json::{Value, json};
use std::{fs, process::Command};
#[test]
fn cli_plan_requires_no_provider_credentials_and_has_no_filesystem_effects() {
    let root = std::env::temp_dir().join(format!("ladyhost-cli-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let spec = root.join("spec.json");
    let state = root.join("state");
    fs::write(&spec,serde_json::to_vec(&json!({"schema_version":1,"repository":"owner/project","workspace":root,"target":"main","app_name":"project-host","checks":[["true"]],"gh":"/not/installed/gh","jj":"/not/installed/jj"})).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ladyhost"))
        .args(["init", "--spec"])
        .arg(&spec)
        .arg("--state")
        .arg(&state)
        .arg("--json")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["repository"], "owner/project");
    assert!(!state.exists());
    let bad = Command::new(env!("CARGO_BIN_EXE_ladyhost"))
        .args(["doctor", "--state"])
        .arg(&state)
        .arg("--apply")
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(!state.exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn credential_helper_refusal_prevents_personal_fallback() {
    let out = Command::new(env!("CARGO_BIN_EXE_ladyhost"))
        .args(["credential", "/nonexistent/ladyhost.json", "get"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(out.stdout, b"quit=true\n\n");
}

#[test]
fn command_help_works_without_state_or_credentials() {
    for command in ["init", "doctor", "uninstall", "review-conflict"] {
        for args in [vec!["help", command], vec![command, "--help"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_ladyhost"))
                .args(&args)
                .env_clear()
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.contains("Usage:"), "{args:?}");
            assert!(text.contains("Example:"));
        }
    }
}
