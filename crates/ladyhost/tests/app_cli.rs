use serde_json::json;
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
fn setup(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("jjpr-helper-{}-{label}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let workspace = root.join("project");
    std::fs::create_dir(&workspace).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&workspace)
            .status()
            .unwrap()
            .success()
    );
    let config = root.join("host ' config.json");
    std::fs::write(&config,serde_json::to_vec(&json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"repo","workspace":workspace,"expected_actor":"publisher[bot]","expected_repository_id":42,"github_app":{"app_id":123,"installation_id":456,"slug":"publisher","private_key":root.join("key.pem"),"openssl":"/usr/bin/openssl"}})).unwrap()).unwrap();
    (root, workspace, config)
}
#[test]
fn helper_installer_resets_human_chain_quotes_paths_and_preserves_path_scope() {
    let (root, workspace, config) = setup("install");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "credential.helper", "human-helper"])
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_ladyhost-jjpr"))
        .arg("git-helper")
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = Command::new("git")
        .arg("-C")
        .arg(&workspace)
        .args(["config", "--get-all", "credential.helper"])
        .output()
        .unwrap();
    let values = String::from_utf8(values.stdout).unwrap();
    assert!(values.starts_with('\n'));
    assert!(!values.contains("human-helper"));
    let path = Command::new("git")
        .arg("-C")
        .arg(&workspace)
        .args(["config", "--get", "credential.useHttpPath"])
        .output()
        .unwrap();
    assert_eq!(path.stdout, b"true\n");
    let fallback = root.join("human-fallback-ran");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["config", "--add", "credential.helper"])
            .arg(format!("!touch {}", fallback.display()))
            .status()
            .unwrap()
            .success()
    );
    // Actual Git invocation proves the quoted path survives shell parsing. An
    // unrelated path is refused before the missing private key is inspected.
    let mut child = Command::new("git")
        .arg("-C")
        .arg(&workspace)
        .args(["credential", "fill"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=other/repo.git\n\n")
        .unwrap();
    let refused = child.wait_with_output().unwrap();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        !fallback.exists(),
        "helper refusal must stop later human helpers"
    );
    assert!(String::from_utf8_lossy(&refused.stderr).contains("credential destination"));
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
fn helper_never_loads_config_from_project_and_store_does_not_mint() {
    let (root, workspace, config) = setup("host");
    let inside = workspace.join("config.json");
    std::fs::copy(&config, &inside).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ladyhost-jjpr"))
        .arg("credential")
        .arg(&config)
        .arg("store")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"protocol=https\nhost=github.com\npath=owner/repo.git\nusername=x-access-token\npassword=secret\n\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let output = Command::new(env!("CARGO_BIN_EXE_ladyhost-jjpr"))
        .arg("git-helper")
        .arg(&inside)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside"));
    std::fs::remove_dir_all(root).unwrap();
}
