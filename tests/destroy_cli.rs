use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
#[test]
fn destroy_exports_first_and_preserves_state() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    let binary = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
    let current = json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash","codex_binary":binary,"owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":root.path(),"build_dir":"build","context":{"gateway":"test","workspace":"default"},"host_sources":{},"sync":{"destination":"exports"}});
    fs::write(directory.join("state.json"), serde_json::to_vec(&current)?)?;
    fs::write(
        root.path().join("policy.json"),
        serde_json::to_vec(&json!({"policy":ladyshell::policy::native_policy(binary)?}))?,
    )?;
    let script = root.path().join("openshell");
    fs::write(
        &script,
        r#"#!/bin/bash
set -euo pipefail
shift 6
case "$1 $2" in
 'sandbox get')
  if [[ -f "$FIXTURE/deleted" ]]; then echo 'sandbox not found' >&2; exit 1; fi
  printf '{"id":"%s","phase":"Ready","configuration_admission":{"policy_hash":"hash"},"labels":{"ladyshell.owner":"%s"}}' "${TEST_ID:-id}" "${TEST_OWNER:-owner}" ;;
 'policy get') /bin/cat "$FIXTURE/policy.json" ;;
 'sandbox exec') [[ ${FAIL_EXPORT:-0} == 0 ]] || exit 23; echo '{}' ;;
 'sandbox delete')
  [[ "$3" == test && $# == 3 ]]
  [[ -f "$FIXTURE/state/destroy.json" ]]
  [[ ${FAIL_DELETE:-0} == 0 ]] || exit 24
  /bin/touch "$FIXTURE/deleted"
  [[ ${FAIL_AFTER_DELETE:-0} == 0 ]] || exit 25 ;;
 *) exit 99 ;;
esac
"#,
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let invoke = |key: &str, value: &str| {
        Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .args(["destroy", "--state"])
            .arg(&directory)
            .env("PATH", root.path())
            .env("FIXTURE", root.path())
            .env(key, value)
            .output()
    };
    for (key, value) in [
        ("TEST_ID", "other"),
        ("TEST_OWNER", "other"),
        ("FAIL_EXPORT", "1"),
    ] {
        assert!(!invoke(key, value)?.status.success());
        assert!(!root.path().join("deleted").exists());
    }
    let lease = ladyshell::state::SessionLock::acquire(&directory, false)?;
    assert!(!invoke("unused", "")?.status.success());
    drop(lease);
    fs::write(directory.join("continuous-staging.json"), b"{}")?;
    let fenced = invoke("unused", "")?;
    assert!(!fenced.status.success());
    assert!(String::from_utf8_lossy(&fenced.stderr).contains("provisioning state"));
    assert!(!root.path().join("deleted").exists());
    fs::remove_file(directory.join("continuous-staging.json"))?;
    assert!(!invoke("FAIL_DELETE", "1")?.status.success());
    assert!(directory.join("destroy.json").exists());
    assert!(!root.path().join("deleted").exists());
    assert!(!invoke("FAIL_AFTER_DELETE", "1")?.status.success());
    assert!(root.path().join("deleted").exists());
    let output = invoke("unused", "")?;
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["deleted"], true);
    assert!(
        std::path::Path::new(result["export"].as_str().ok_or("Missing export")?)
            .join("manifest.json")
            .is_file()
    );
    assert!(directory.join("state.json").exists());
    assert!(invoke("unused", "")?.status.success());
    fs::remove_file(root.path().join("deleted"))?;
    assert!(!invoke("TEST_ID", "replacement")?.status.success());
    assert!(!root.path().join("deleted").exists());
    let discarded = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["delete", "--discard-work", "--state"])
        .arg(&directory)
        .env("PATH", root.path())
        .env("FIXTURE", root.path())
        .env("FAIL_EXPORT", "1")
        .output()?;
    assert!(discarded.status.success(), "{discarded:?}");
    let receipt: serde_json::Value = serde_json::from_slice(&discarded.stdout)?;
    assert_eq!(receipt["discard_work"], true);
    assert!(receipt["export"].is_null());
    Ok(())
}

#[test]
fn native_destroy_cannot_discard_broker_records_without_volume_lifecycle(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("state");
    ladyshell::state::create_directory(&directory)?;
    let current = json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash",
        "image_profile":"openshell-worker-v1","broker_binary":"/fixed/worker","storage":{},
        "owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":root.path(),
        "build_dir":"build","context":{"gateway":"test","workspace":"default"}});
    fs::write(directory.join("state.json"), serde_json::to_vec(&current)?)?;
    let script = root.path().join("openshell");
    fs::write(
        &script,
        "#!/bin/bash\n/bin/touch \"$FIXTURE/called\"\nexit 77\n",
    )?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladyshell"))
        .args(["destroy", "--discard-work", "--state"])
        .arg(&directory)
        .env("PATH", root.path())
        .env("FIXTURE", root.path())
        .output()?;
    assert!(!output.status.success());
    assert!(
        !root.path().join("called").exists(),
        "native deletion must not touch a broker deployment"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("broker lifecycle"),
        "{output:?}"
    );
    Ok(())
}
