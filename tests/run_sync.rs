use ladyshell::{
    snapshot,
    sources::{FileRecord, Snapshot},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Fixture {
    root: tempfile::TempDir,
    state: Value,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        for name in ["host", "source", "remote", "state"] {
            fs::create_dir(root.path().join(name))?;
        }
        for name in ["host", "source"] {
            fs::write(root.path().join(name).join("calc.py"), b"print(1)\n")?;
            fs::write(root.path().join(name).join("removed.txt"), b"old\n")?;
        }
        fs::write(root.path().join("remote/calc.py"), b"print(2)\n")?;
        fs::write(root.path().join("remote/new.txt"), b"new\n")?;
        let records: Snapshot = snapshot::inventory(&root.path().join("source"))?
            .into_iter()
            .map(|(p, e)| {
                (
                    p,
                    FileRecord {
                        sha256: e.sha256,
                        executable: e.executable,
                    },
                )
            })
            .collect();
        fs::set_permissions(root.path().join("state"), fs::Permissions::from_mode(0o700))?;
        let binary = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
        let state = json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash","codex_binary":binary,"owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":root.path().join("source"),"build_dir":"build","context":{"gateway":"test","workspace":"default"},"host_sources":records,"sync":{"destination":"exports"},"desired_inputs":{"project":root.path().join("host"),"evaluated":{"config":{"sources":{"include":[],"exclude":[]},"sandbox":{"provider":"test-provider"}}}}});
        let f = Self { root, state };
        f.save()?;
        f.write("observed.json", &json!({"id":"id","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}))?;
        f.write(
            "policy.json",
            &json!({"policy":ladyshell::policy::native_policy(binary)?}),
        )?;
        f.write(
            "inventory.json",
            &serde_json::to_value(snapshot::inventory(&f.root.path().join("remote"))?)?,
        )?;
        for path in ["calc.py", "new.txt"] {
            f.write(
                &format!("file-{path}.json"),
                &serde_json::to_value(snapshot::read_file(&f.root.path().join("remote"), path)?)?,
            )?;
        }
        fs::write(f.root.path().join("provider"), b"available")?;
        fs::write(
            f.root.path().join("openshell"),
            r#"#!/bin/bash
set -euo pipefail
[[ -z ${OPENSHELL_GATEWAY+x} ]]
shift 6
case "$1 $2" in
 'sandbox get') /bin/cat "$FIXTURE/observed.json";;
 'policy get') /bin/cat "$FIXTURE/policy.json";;
 'provider get') /bin/cat "$FIXTURE/provider";;
 'sandbox exec')
  printf '%s\0' "$@" >> "$FIXTURE/args"
  while [[ "$1" != -- ]]; do shift; done; shift
  case "$1" in
   /usr/local/bin/ladyshell)
    case "$2" in
     snapshot-preview) [[ -f "$FIXTURE/preview.json" ]] || exit 64; /bin/cat "$FIXTURE/preview.json";;
     snapshot-list) : > "$FIXTURE/exported"; while [[ -f "$FIXTURE/pause-export" ]]; do /bin/sleep 0.02; done; /bin/cat "$FIXTURE/inventory.json";;
     snapshot-file) /bin/cat "$FIXTURE/file-${@: -1}.json";;
     *) exit 98;;
    esac;;
   fixture-change|/bin/bash)
    : > "$FIXTURE/executed"
    [[ ! -f "$FIXTURE/next-observed.json" ]] || /bin/cp "$FIXTURE/next-observed.json" "$FIXTURE/observed.json"
    [[ ! -f "$FIXTURE/pending-after" ]] || /bin/cp "$FIXTURE/pending-after" "$FIXTURE/state/checkout-pending.json"
    [[ ! -f "$FIXTURE/interrupt" ]] || kill -TERM $$
    exit "${EXPERIMENT_EXIT:-0}";;
   *) exit 97;;
  esac;;
 *) exit 99;;
esac
"#,
        )?;
        fs::set_permissions(
            f.root.path().join("openshell"),
            fs::Permissions::from_mode(0o700),
        )?;
        Ok(f)
    }
    fn write(&self, name: &str, v: &Value) -> Result {
        fs::write(self.root.path().join(name), serde_json::to_vec(v)?)?;
        Ok(())
    }
    fn save(&self) -> Result {
        self.write("state/state.json", &self.state)
    }
    fn command(&self, mode: &str, sync: bool) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
        c.env_clear()
            .env("PATH", self.root.path())
            .env("FIXTURE", self.root.path())
            .env("XDG_STATE_HOME", self.root.path().join("xdg"))
            .env("OPENSHELL_GATEWAY", "ignored")
            .arg(mode)
            .arg("--state")
            .arg(self.root.path().join("state"));
        if sync {
            c.arg("--sync");
        }
        c
    }
    fn run(&self, sync: bool) -> Result<Output> {
        Ok(self
            .command("run", sync)
            .args(["--", "fixture-change"])
            .output()?)
    }
    fn exported(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(
            self.root.path().join("state/state.json"),
        )?)?)
    }
}
#[test]
fn continuous_handoff_blocks_run_without_sync_shell_check_and_exports() -> Result {
    use ladyshell::continuous::model::Session;
    let mut f = Fixture::new()?;
    let mut session = Session::new(
        "task".into(),
        "id".into(),
        "owner".into(),
        "runtime".into(),
        "a".repeat(64),
        "b".repeat(64),
    )?;
    session.begin_checkpoint("checkpoint", 0)?;
    f.state["continuous"] = serde_json::to_value(session)?;
    f.save()?;
    for mode in ["run", "shell", "chat", "resume", "sync", "check"] {
        let mut command = f.command(mode, false);
        if mode == "run" {
            command.args(["--", "fixture-change"]);
        }
        let output = command.output()?;
        assert!(!output.status.success(), "{mode}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Continuous handoff"),
            "{mode}: {output:?}"
        );
        assert!(!f.root.path().join("executed").exists());
        assert!(!f.root.path().join("exported").exists());
    }
    Ok(())
}
#[test]
fn successful_run_syncs_add_modify_delete_and_preserves_arguments() -> Result {
    let f = Fixture::new()?;
    let output = f
        .command("run", true)
        .args([
            "--timeout",
            "600",
            "--",
            "fixture-change",
            "",
            "a b",
            "$(touch HOST_SENTINEL)",
            "a;b",
        ])
        .output()?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(f.root.path().join("host/calc.py"))?, b"print(2)\n");
    assert_eq!(fs::read(f.root.path().join("host/new.txt"))?, b"new\n");
    assert!(!f.root.path().join("host/removed.txt").exists());
    let args = fs::read(f.root.path().join("args"))?;
    assert!(args
        .windows(b"fixture-change\0\0a b\0$(touch HOST_SENTINEL)\0a;b\0".len())
        .any(|w| w == b"fixture-change\0\0a b\0$(touch HOST_SENTINEL)\0a;b\0"));
    assert!(!f.root.path().join("host/HOST_SENTINEL").exists());
    assert!(f.exported()?["last_checkout_export"].is_string());
    Ok(())
}
#[test]
fn failure_preserves_exit_and_export_without_applying() -> Result {
    let f = Fixture::new()?;
    let output = f
        .command("run", true)
        .args(["--", "fixture-change"])
        .env("EXPERIMENT_EXIT", "37")
        .output()?;
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(fs::read(f.root.path().join("host/calc.py"))?, b"print(1)\n");
    let saved = f.exported()?;
    let export = Path::new(saved["last_sync"].as_str().ok_or("missing export")?);
    assert_eq!(fs::read(export.join("project/calc.py"))?, b"print(2)\n");
    Ok(())
}
#[test]
fn opting_out_and_host_conflicts_do_not_apply() -> Result {
    let f = Fixture::new()?;
    assert!(f.run(false)?.status.success());
    assert!(!f.root.path().join("exported").exists());
    fs::write(f.root.path().join("host/calc.py"), b"print('local')\n")?;
    let out = f.run(true)?;
    assert!(!out.status.success(), "{out:?}");
    assert_eq!(
        fs::read(f.root.path().join("host/calc.py"))?,
        b"print('local')\n"
    );
    assert!(!f.root.path().join("host/new.txt").exists());
    assert!(f.exported()?["last_sync"].is_string());
    Ok(())
}
#[test]
fn pending_recovery_and_untrusted_sandbox_prevent_execution() -> Result {
    for kind in ["pending", "identity", "provider", "policy"] {
        let f = Fixture::new()?;
        match kind {
            "pending"=>f.write("state/checkout-pending.json",&json!({}))?,
            "identity"=>f.write("observed.json",&json!({"id":"other","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}))?,
            "provider"=>fs::write(f.root.path().join("provider"),"expired")?,
            _=>f.write("policy.json",&json!({"policy":{}}))?,
        }
        let out = f.run(true)?;
        assert!(!out.status.success(), "{kind}: {out:?}");
        assert!(!f.root.path().join("executed").exists(), "{kind}");
        assert!(!f.root.path().join("exported").exists(), "{kind}");
    }
    Ok(())
}
#[test]
fn automatic_sync_refuses_replacement_or_new_recovery_after_execution() -> Result {
    for name in ["next-observed.json", "pending-after"] {
        let f = Fixture::new()?;
        f.write(name,&json!({"id":"other","phase":"Ready","configuration_admission":{"state":"accepted","policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}))?;
        let out = f.run(true)?;
        assert!(!out.status.success(), "{out:?}");
        assert!(f.root.path().join("executed").exists());
        assert!(!f.root.path().join("exported").exists());
        assert_eq!(fs::read(f.root.path().join("host/calc.py"))?, b"print(1)\n");
    }
    Ok(())
}
#[test]
fn shell_sync_uses_the_same_verified_completion() -> Result {
    let f = Fixture::new()?;
    let out = f.command("shell", true).output()?;
    assert!(out.status.success(), "{out:?}");
    assert_eq!(fs::read(f.root.path().join("host/calc.py"))?, b"print(2)\n");
    for mode in ["shell", "chat", "resume"] {
        assert!(ladyshell_cli::cli::validate_args(&[
            "ladyshell",
            mode,
            "--state",
            "/state",
            "--sync"
        ])
        .is_ok());
    }
    Ok(())
}

#[test]
fn run_publishes_exact_export_and_failed_command_never_pushes() -> Result {
    let git = std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH is missing")?)
        .map(|directory| directory.join("git"))
        .find(|path| {
            path.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .ok_or("Git executable is missing from PATH")?
        .canonicalize()?;
    for exit in ["0", "37"] {
        let f = Fixture::new()?;
        std::os::unix::fs::symlink(&git, f.root.path().join("git"))?;
        let host = f.root.path().join("host");
        let remote = f.root.path().join("knot.git");
        for args in [
            vec!["init", "--initial-branch=agent/test"],
            vec!["config", "user.name", "Test"],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["add", "."],
            vec!["commit", "-m", "Baseline"],
        ] {
            assert!(Command::new("git")
                .arg("-C")
                .arg(&host)
                .args(args)
                .output()?
                .status
                .success());
        }
        assert!(Command::new("git")
            .args(["init", "--bare"])
            .arg(&remote)
            .output()?
            .status
            .success());
        assert!(Command::new("git")
            .arg("-C")
            .arg(&host)
            .args(["remote", "add", "knot"])
            .arg(&remote)
            .output()?
            .status
            .success());
        let out = f
            .command("run", true)
            .args([
                "--publish",
                "knot",
                "--branch",
                "agent/test",
                "--message",
                "Sandbox change",
                "--",
                "fixture-change",
            ])
            .env("EXPERIMENT_EXIT", exit)
            .output()?;
        assert_eq!(out.status.code(), Some(exit.parse()?), "{out:?}");
        let pushed = Command::new("git")
            .arg("-C")
            .arg(&remote)
            .args(["show", "refs/heads/agent/test:calc.py"])
            .output()?;
        if exit == "0" {
            assert!(pushed.status.success(), "{pushed:?}");
            assert_eq!(pushed.stdout, b"print(2)\n");
            assert!(f.root.path().join("state/publication.json").exists());
        } else {
            assert!(!pushed.status.success());
            assert!(!f.root.path().join("state/publication.json").exists());
        }
    }
    Ok(())
}

#[test]
fn publication_flags_and_timeout_require_complete_explicit_arguments() {
    for args in [
        vec!["--publish", "knot"],
        vec!["--sync", "--branch", "agent/test"],
        vec!["--timeout", "0"],
        vec!["--timeout", "86401"],
    ] {
        let mut full = vec!["ladyshell", "run", "--state", "/state"];
        full.extend(args);
        full.extend(["--", "true"]);
        assert!(ladyshell_cli::cli::validate_args(&full).is_err());
    }
}

#[test]
fn interrupted_run_exports_without_applying() -> Result {
    let f = Fixture::new()?;
    fs::write(f.root.path().join("interrupt"), b"")?;
    let out = f.run(true)?;
    assert_eq!(out.status.code(), Some(143), "{out:?}");
    assert!(f.exported()?["last_sync"].is_string());
    assert_eq!(fs::read(f.root.path().join("host/calc.py"))?, b"print(1)\n");
    Ok(())
}

#[test]
fn completion_retains_session_lease_and_state_lock_until_export_finishes() -> Result {
    let f = Fixture::new()?;
    fs::write(f.root.path().join("pause-export"), b"")?;
    let mut child = f
        .command("run", true)
        .args(["--", "fixture-change"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !f.root.path().join("exported").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let state = f.root.path().join("state");
    let reached_export = f.root.path().join("exported").exists();
    let state_locked = ladyshell::state::StateLock::acquire(&state).is_err();
    let lease_locked = ladyshell::state::SessionLock::acquire(&state, true).is_err();
    fs::remove_file(f.root.path().join("pause-export"))?;
    assert!(child.wait()?.success());
    assert!(reached_export && state_locked && lease_locked);
    assert!(ladyshell::state::SessionLock::acquire(&state, true).is_ok());
    Ok(())
}

#[test]
fn unconfirmed_publication_prevents_another_experiment() -> Result {
    let f = Fixture::new()?;
    f.write(
        "state/publication.json",
        &json!({"schema_version":1,"confirmed":false,"commit":"retained"}),
    )?;
    let out = f
        .command("run", true)
        .args([
            "--publish",
            "knot",
            "--branch",
            "agent/test",
            "--message",
            "Change",
            "--",
            "fixture-change",
        ])
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("publication"));
    assert!(!f.root.path().join("executed").exists());
    Ok(())
}

#[test]
fn live_preview_before_first_export_is_read_only_and_missing_capability_has_no_fallback() -> Result
{
    let f = Fixture::new()?;
    let invoke = || -> Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_ladyshell"))
            .env_clear()
            .env("PATH", f.root.path())
            .env("FIXTURE", f.root.path())
            .args(["task", "inspect", "--live", "--state"])
            .arg(f.root.path().join("state"))
            .output()?)
    };
    let before = fs::read(f.root.path().join("state/state.json"))?;
    let unsupported = invoke()?;
    assert!(!unsupported.status.success());
    assert!(String::from_utf8(unsupported.stderr)?
        .contains("optional snapshot-preview worker capability"));
    assert!(!f.root.path().join("exported").exists());
    let preview = ladyshell::snapshot::preview_filtered(&f.root.path().join("remote"), &[])?;
    f.write("preview.json", &serde_json::to_value(preview)?)?;
    let output = invoke()?;
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["scope"], "live_worker_metadata");
    assert_eq!(report["verified_source_bytes"], false);
    assert_eq!(report["preview"]["entries"]["calc.py"]["size"], 9);
    assert_eq!(before, fs::read(f.root.path().join("state/state.json"))?);
    assert!(!f.root.path().join("exported").exists());
    assert!(!f.root.path().join("state/exports").exists());
    f.write("preview.json", &json!({"schema_version":1,"entries":{".env":{"disposition":"included","kind":"file","size":1}}}))?;
    assert!(!invoke()?.status.success());
    fs::remove_file(f.root.path().join("args"))?;
    f.write("observed.json", &json!({"id":"foreign"}))?;
    assert!(!invoke()?.status.success());
    assert!(!f.root.path().join("args").exists());
    Ok(())
}
