use ladyshell::{associations, environment_lock::atomic_json};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn seed(root: &Path, name: &str) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let project = root.join("project");
    fs::create_dir_all(&project)?;
    let dir = root.join(name);
    ladyshell::state::create_directory(&dir)?;
    let binary = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
    atomic_json(
        &dir.join("state.json"),
        &json!({"schema_version":2,"sandbox_name":name,"sandbox_id":format!("id-{name}"),"policy_hash":"hash","codex_binary":binary,"owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":project,"desired_inputs":{"project":project},"build_dir":"build","context":{"gateway":"test","workspace":"default"},"host_sources":{},"sync":{"destination":"exports"}}),
    )?;
    associations::register_at(&root.join("xdg/ladyshell/associations"), &dir)?;
    atomic_json(
        &root.join("policy.json"),
        &json!({"policy":ladyshell::policy::native_policy(binary)?}),
    )?;
    let script = root.join("openshell");
    fs::write(
        &script,
        r#"#!/bin/bash
set -euo pipefail
shift 6
printf '%s\n' "$*" >> "$FIXTURE/calls"
if [[ "$1 $2" == 'sandbox get' && "$3" == "${REBIND_AFTER_FIRST:-}" && ! -f "$FIXTURE/rebound" ]]; then
 /usr/bin/python3 - "$FIXTURE/$REBIND_OTHER/state.json" <<'PYCODE'
import json,sys
p=sys.argv[1]
with open(p) as f: state=json.load(f)
state['sandbox_id']='replacement-after-preview'
with open(p,'w') as f: json.dump(state,f)
PYCODE
 /bin/touch "$FIXTURE/rebound"
fi
if [[ "$1 $2" == 'sandbox get' && "$3" == "${SWAP_DURING_GET:-}" && ! -f "$FIXTURE/swap-ready" ]]; then
 /bin/mv "$FIXTURE/$3" "$FIXTURE/preserved-$3"
 /bin/mkdir -m 700 "$FIXTURE/$3"
 /bin/cp "$FIXTURE/preserved-$3/state.json" "$FIXTURE/$3/state.json"
 /bin/touch "$FIXTURE/swap-ready"
 for ((i=0;i<500;i++)); do [[ -f "$FIXTURE/swap-resume" ]] && break; /bin/sleep .01; done
 [[ -f "$FIXTURE/swap-resume" ]]
fi
case "$1 $2" in
 'sandbox get')
  name="$3"
  if [[ -f "$FIXTURE/deleted-$name" ]]; then echo 'sandbox not found' >&2; exit 1; fi
  id="id-$name"; if [[ "${WRONG_ID:-}" == "$name" ]]; then id=wrong; fi
  printf '{"id":"%s","phase":"Ready","configuration_admission":{"policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}' "$id" ;;
 'policy get') /bin/cat "$FIXTURE/policy.json" ;;
 'sandbox exec') echo '{}' ;;
 'sandbox delete') [[ -f "$FIXTURE/$3/destroy.json" ]]; /bin/touch "$FIXTURE/deleted-$3" ;;
 *) exit 99 ;;
esac
"#,
    )?;
    fs::set_permissions(script, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
fn command(root: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
    c.arg("destroy")
        .args(args)
        .env("XDG_STATE_HOME", root.join("xdg"))
        .env("FIXTURE", root)
        .env("PATH", root);
    c
}
fn invoke(root: &Path, args: &[&str]) -> std::io::Result<Output> {
    command(root, args).output()
}
#[test]
fn bulk_preview_is_read_only_and_execution_exports_every_current_state() -> Result {
    let root = tempfile::tempdir()?;
    let one = seed(root.path(), "one")?;
    let two = seed(root.path(), "two")?;
    let before = fs::read(one.join("state.json"))?;
    let preview = invoke(root.path(), &["--all", "--dry-run"])?;
    assert!(preview.status.success(), "{preview:?}");
    let report: Value = serde_json::from_slice(&preview.stdout)?;
    assert_eq!(report["candidates"].as_array().map(Vec::len), Some(2));
    assert!(!root.path().join("calls").exists());
    assert_eq!(fs::read(one.join("state.json"))?, before);
    let output = invoke(root.path(), &["--all"])?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["deleted"], 2);
    for directory in [one, two] {
        assert!(directory.join("state.json").exists());
        let receipt: Value = serde_json::from_slice(&fs::read(directory.join("destroy.json"))?)?;
        assert_eq!(receipt["deleted"], true);
        assert_eq!(receipt["discard_work"], false);
        assert!(Path::new(receipt["export"].as_str().ok_or("no export")?)
            .join("manifest.json")
            .exists());
    }
    let again = invoke(root.path(), &["--all"])?;
    assert!(again.status.success());
    let report: Value = serde_json::from_slice(&again.stdout)?;
    assert_eq!(report["deleted"], 0);
    Ok(())
}
#[test]
fn individual_refusal_is_reported_while_other_states_are_handled() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "one")?;
    seed(root.path(), "two")?;
    let output = command(root.path(), &["--all"])
        .env("WRONG_ID", "one")
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], false);
    assert_eq!(report["deleted"], 1);
    assert!(!root.path().join("deleted-one").exists());
    assert!(root.path().join("deleted-two").exists());
    Ok(())
}
#[test]
fn incomplete_inventory_blocks_all_effects_and_retained_identities_are_explicit() -> Result {
    let root = tempfile::tempdir()?;
    let state = seed(root.path(), "one")?;
    let bad = root.path().join("xdg/ladyshell/associations/bad.json");
    fs::write(&bad, b"invalid")?;
    let output = invoke(root.path(), &["--all"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!root.path().join("calls").exists());
    fs::remove_file(bad)?;
    let mut current: Value = serde_json::from_slice(&fs::read(state.join("state.json"))?)?;
    current["retained"] = json!([{"sandbox_name":"old","sandbox_id":"old-id","context":{"gateway":"test","workspace":"default"}}]);
    atomic_json(&state.join("state.json"), &current)?;
    let output = invoke(root.path(), &["--all", "--dry-run"])?;
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["blocked"].as_array().map(Vec::len), Some(1));
    assert!(!root.path().join("calls").exists());
    Ok(())
}
#[test]
fn bulk_flags_are_explicit_and_busy_sessions_are_preserved() -> Result {
    let root = tempfile::tempdir()?;
    let dir = seed(root.path(), "one")?;
    assert!(!invoke(root.path(), &["--all", "--state", "anything"])?
        .status
        .success());
    assert!(!invoke(root.path(), &["--state", "anything", "--dry-run"])?
        .status
        .success());
    let lease = ladyshell::state::SessionLock::acquire(&dir, false)?;
    let output = invoke(root.path(), &["--all", "--discard-work"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(!root.path().join("calls").exists());
    drop(lease);
    let output = invoke(root.path(), &["--all", "--discard-work"])?;
    assert!(output.status.success(), "{output:?}");
    let receipt: Value = serde_json::from_slice(&fs::read(dir.join("destroy.json"))?)?;
    assert_eq!(receipt["export"], Value::Null);
    assert_eq!(receipt["discard_work"], true);
    Ok(())
}

#[test]
fn state_rebound_after_inventory_is_refused_before_provider_access() -> Result {
    let root = tempfile::tempdir()?;
    seed(root.path(), "one")?;
    seed(root.path(), "two")?;
    let preview = invoke(root.path(), &["--all", "--dry-run"])?;
    let report: Value = serde_json::from_slice(&preview.stdout)?;
    let first = report["candidates"][0]["sandbox_name"]
        .as_str()
        .ok_or("first missing")?;
    let second = report["candidates"][1]["sandbox_name"]
        .as_str()
        .ok_or("second missing")?;
    let output = command(root.path(), &["--all"])
        .env("REBIND_AFTER_FIRST", first)
        .env("REBIND_OTHER", second)
        .output()?;
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(root.path().join(format!("deleted-{first}")).exists());
    assert!(!root.path().join(format!("deleted-{second}")).exists());
    assert!(
        !fs::read_to_string(root.path().join("calls"))?.contains(&format!("sandbox get {second} "))
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert!(report["results"][1]["error"]
        .as_str()
        .is_some_and(|e| e.contains("Stale association")));
    Ok(())
}

#[test]
fn malformed_later_candidate_cannot_allow_earlier_deletion() -> Result {
    for bad_gateway in ["", "invalid gateway"] {
        let root = tempfile::tempdir()?;
        for name in ["one", "two", "three"] {
            seed(root.path(), name)?;
        }
        let preview = invoke(root.path(), &["--all", "--dry-run"])?;
        let report: Value = serde_json::from_slice(&preview.stdout)?;
        let directory = Path::new(
            report["candidates"][1]["directory"]
                .as_str()
                .ok_or("no directory")?,
        );
        let mut current: Value = serde_json::from_slice(&fs::read(directory.join("state.json"))?)?;
        current["context"]["gateway"] = json!(bad_gateway);
        atomic_json(&directory.join("state.json"), &current)?;
        for entry in fs::read_dir(root.path().join("xdg/ladyshell/associations"))? {
            let entry = entry?;
            if entry.file_name() == ".lock" {
                continue;
            }
            let mut association: Value = serde_json::from_slice(&fs::read(entry.path())?)?;
            if association["directory"] == directory.to_str().ok_or("non UTF8")? {
                association["gateway"] = json!(bad_gateway);
                atomic_json(&entry.path(), &association)?;
            }
        }
        let output = invoke(root.path(), &["--all", "--discard-work"])?;
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(!root.path().join("calls").exists());
        let report: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(report["deleted"], 0);
        assert_eq!(report["inventory_complete"], false);
        assert_eq!(
            invoke(root.path(), &["--all", "--dry-run"])?.status.code(),
            Some(1)
        );
    }
    Ok(())
}

#[test]
fn replaced_state_directory_is_refused_and_new_session_is_preserved() -> Result {
    let root = tempfile::tempdir()?;
    let dir = seed(root.path(), "one")?;
    let child = command(root.path(), &["--all", "--discard-work"])
        .env("SWAP_DURING_GET", "one")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let start = std::time::Instant::now();
    while !root.path().join("swap-ready").exists()
        && start.elapsed() < std::time::Duration::from_secs(5)
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(root.path().join("swap-ready").exists());
    let lease = ladyshell::state::SessionLock::acquire(&dir, false)?;
    fs::write(root.path().join("swap-resume"), b"ready")?;
    let output = child.wait_with_output()?;
    drop(lease);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(!root.path().join("deleted-one").exists());
    assert!(!dir.join("destroy.json").exists());
    assert!(!root.path().join("preserved-one/destroy.json").exists());
    Ok(())
}
