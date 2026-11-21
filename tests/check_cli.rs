use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

type Result = std::result::Result<(), Box<dyn Error>>;

struct Fixture {
    root: tempfile::TempDir,
    state: Value,
}

impl Fixture {
    fn new(checks: Value) -> std::result::Result<Self, Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        ladyshell::state::create_directory(&root.path().join("state"))?;
        let binary = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";
        let state = json!({"schema_version":2,"sandbox_name":"test","sandbox_id":"id","policy_hash":"hash","codex_binary":binary,"owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"test","workspace":"default"},"desired_inputs":{"evaluated":{"config":{"checks":checks,"sandbox":{"provider":"test-provider"}}}}});
        let fixture = Self { root, state };
        fixture.save()?;
        fixture.write("observed.json", &json!({"id":"id","phase":"Ready","configuration_admission":{"policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"}}))?;
        fixture.write(
            "policy.json",
            &json!({"policy":ladyshell::policy::native_policy(binary)?}),
        )?;
        fs::write(fixture.root.path().join("provider"), "available")?;
        let executable = fixture.root.path().join("openshell");
        fs::write(
            &executable,
            r#"#!/bin/bash
set -euo pipefail
[[ -z ${OPENSHELL_GATEWAY+x} ]]
[[ "$1 $2 $3 $4 $5 $6" == '--gateway test --workspace default --color never' ]]
shift 6
case "$1 $2" in
  'sandbox get') /bin/cat "$FIXTURE/observed.json" ;;
  'policy get') /bin/cat "$FIXTURE/policy.json" ;;
  'provider get') [[ "$3" == test-provider ]]; /bin/cat "$FIXTURE/provider" ;;
  'sandbox exec')
    if [[ "${@: -2:1}" == /usr/local/bin/ladyshell && "${@: -1}" == snapshot-list ]]; then /bin/cat "$FIXTURE/inventory.json"; exit; fi
    count=0
    [[ ! -f "$FIXTURE/count" ]] || read -r count < "$FIXTURE/count"
    count=$((count+1))
    printf '%s\n' "$count" > "$FIXTURE/count"
    printf '%s\0' "$@" > "$FIXTURE/args.$count"
    while [[ "$1" != -- ]]; do shift; done
    shift
    case "$1" in
      fixture-pass) printf 'check output\n' ;;
      fixture-fail) exit 37 ;;
      fixture-signal) kill -TERM $$ ;;
      fixture-wait)
        trap 'exit 143' TERM
        : > "$FIXTURE/ready"
        for ((i=0;i<500;i++)); do /bin/sleep 0.01; done
        exit 98 ;;
      *) exit 97 ;;
    esac
    for name in observed.json policy.json provider inventory.json; do
      [[ ! -f "$FIXTURE/next-$name" ]] || /bin/cat "$FIXTURE/next-$name" > "$FIXTURE/$name"
    done ;;
  *) exit 99 ;;
esac
"#,
        )?;
        fs::set_permissions(executable, fs::Permissions::from_mode(0o700))?;
        Ok(fixture)
    }

    fn write(&self, name: &str, value: &Value) -> Result {
        fs::write(self.root.path().join(name), serde_json::to_vec(value)?)?;
        Ok(())
    }

    fn save(&self) -> Result {
        self.write("state/state.json", &self.state)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
        command
            .env_clear()
            .args(["check", "--state"])
            .arg(self.root.path().join("state"))
            .env("PATH", self.root.path())
            .env("FIXTURE", self.root.path())
            .env("OPENSHELL_GATEWAY", "must-not-override-context");
        command
    }

    fn no_execution(&self) -> bool {
        !self.root.path().join("count").exists()
    }
}

#[test]
fn checks_preserve_arguments_output_order_and_first_failure() -> Result {
    let fixture = Fixture::new(json!([
        [
            "fixture-pass",
            "literal with spaces",
            "$(touch HOST_SENTINEL)",
            "a;b",
            "line\nbreak"
        ],
        ["fixture-fail"],
        ["fixture-pass"]
    ]))?;
    let before = fs::read(fixture.root.path().join("state/state.json"))?;
    let output = fixture
        .command()
        .current_dir(fixture.root.path())
        .output()?;
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(output.stdout, b"check output\n");
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("count"))?,
        "2\n"
    );
    let bytes = fs::read(fixture.root.path().join("args.1"))?;
    let args: Vec<&str> = std::str::from_utf8(&bytes)?
        .split_terminator('\0')
        .collect();
    assert_eq!(
        args,
        [
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/sandbox/workspace/project",
            "--timeout",
            "300",
            "--env",
            "HOME=/sandbox",
            "--env",
            "CARGO_HOME=/sandbox/workspace/cache/cargo",
            "--env",
            "XDG_CACHE_HOME=/sandbox/workspace/cache",
            "--env",
            "ZIG_GLOBAL_CACHE_DIR=/sandbox/workspace/cache/zig",
            "--env",
            "PKG_CONFIG_PATH=/usr/local/lib/ladyshell/pkgconfig",
            "--env",
            "LD_LIBRARY_PATH=/usr/local/lib/ladyshell",
            "test",
            "--",
            "fixture-pass",
            "literal with spaces",
            "$(touch HOST_SENTINEL)",
            "a;b",
            "line\nbreak"
        ]
    );
    assert!(!fixture.root.path().join("HOST_SENTINEL").exists());
    assert_eq!(
        before,
        fs::read(fixture.root.path().join("state/state.json"))?
    );
    Ok(())
}

#[test]
fn checks_reject_missing_or_malformed_configuration_before_execution() -> Result {
    for checks in [
        Value::Null,
        json!([]),
        json!([["fixture-pass"], []]),
        json!([["fixture-pass"], [""]]),
        json!([["fixture-pass"], ["bad\0command"]]),
        json!([["fixture-pass"], [3]]),
    ] {
        let fixture = Fixture::new(checks)?;
        let output = fixture.command().output()?;
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(fixture.no_execution());
    }
    let fixture = Fixture::new(json!([["fixture-pass"]]))?;
    fs::remove_file(fixture.root.path().join("state/state.json"))?;
    let output = fixture.command().output()?;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8(output.stderr)?.contains("État absent"));
    assert!(fixture.no_execution());
    Ok(())
}

#[test]
fn checks_refuse_unverified_identity_policy_and_provider() -> Result {
    for (file, pointer, value) in [
        ("observed.json", "/id", json!("replacement")),
        ("observed.json", "/labels/ladyshell.owner", json!("other")),
        ("observed.json", "/phase", json!("Stopped")),
        (
            "observed.json",
            "/configuration_admission/policy_hash",
            json!("changed"),
        ),
        (
            "policy.json",
            "/policy/landlock/compatibility",
            json!("best_effort"),
        ),
    ] {
        let fixture = Fixture::new(json!([["fixture-pass"]]))?;
        let mut document: Value =
            serde_json::from_slice(&fs::read(fixture.root.path().join(file))?)?;
        *document
            .pointer_mut(pointer)
            .ok_or("missing fixture field")? = value;
        fixture.write(file, &document)?;
        let output = fixture.command().output()?;
        assert_eq!(output.status.code(), Some(2), "{pointer}: {output:?}");
        assert!(fixture.no_execution());
    }
    for provider in [Some("expired"), Some("revoked"), None] {
        let fixture = Fixture::new(json!([["fixture-pass"]]))?;
        let path = fixture.root.path().join("provider");
        match provider {
            Some(text) => fs::write(path, text)?,
            None => fs::remove_file(path)?,
        }
        let output = fixture.command().output()?;
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(fixture.no_execution());
    }
    Ok(())
}

#[test]
fn checks_revalidate_between_commands() -> Result {
    for drift in ["provider", "policy.json", "observed.json"] {
        let fixture = Fixture::new(json!([["fixture-pass"], ["fixture-pass"]]))?;
        let text = match drift {
            "provider" => "expired",
            "policy.json" => "{\"policy\":{}}",
            _ => "{\"id\":\"replacement\",\"phase\":\"Ready\",\"configuration_admission\":{\"policy_hash\":\"hash\"},\"labels\":{\"ladyshell.owner\":\"owner\"}}",
        };
        fs::write(fixture.root.path().join(format!("next-{drift}")), text)?;
        let output = fixture.command().output()?;
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_eq!(
            fs::read_to_string(fixture.root.path().join("count"))?,
            "1\n"
        );
    }
    Ok(())
}

struct RunningCheck(Child);
impl Drop for RunningCheck {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_ready(path: &Path, child: &mut Child) -> Result {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(child.try_wait()?.is_none(), "check exited before execution");
        assert!(Instant::now() < deadline, "check did not start");
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn checks_hold_a_session_lease_and_preserve_termination() -> Result {
    let fixture = Fixture::new(json!([["fixture-wait"], ["fixture-pass"]]))?;
    let state = fixture.root.path().join("state");
    let mut child = RunningCheck(
        fixture
            .command()
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    wait_ready(&fixture.root.path().join("ready"), &mut child.0)?;
    let lock = ladyshell::state::StateLock::acquire(&state)?;
    assert!(ladyshell::state::SessionLock::acquire(&state, true).is_err());
    drop(lock);
    // SAFETY: the PID belongs to our live child, whose exit is reaped below.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
    assert_eq!(child.0.wait()?.code(), Some(143));
    let _lease = ladyshell::state::SessionLock::acquire(&state, true)?;
    assert_eq!(
        fs::read_to_string(fixture.root.path().join("count"))?,
        "1\n"
    );
    Ok(())
}

#[test]
fn checks_return_success_or_remote_signal_status() -> Result {
    for (program, status) in [("fixture-pass", 0), ("fixture-signal", 143)] {
        let fixture = Fixture::new(json!([[program]]))?;
        let output = fixture.command().output()?;
        assert_eq!(output.status.code(), Some(status), "{output:?}");
    }
    Ok(())
}

fn pruning_plan(fixture: &Fixture) -> std::result::Result<std::path::PathBuf, Box<dyn Error>> {
    use ladybom::deps::{self, graph, prune_validation};
    let project = fixture.root.path().join("project");
    fs::create_dir(&project)?;
    fs::write(
        project.join("package.json"),
        json!({"dependencies":{"a":"1"}}).to_string(),
    )?;
    fs::write(
        project.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0"}}})
            .to_string(),
    )?;
    let before = graph::project(deps::scan_project(&project)?)?;
    let request =
        graph::RemovalRequest::new(&before, vec![graph::root_catalog(&before)?[0].id.clone()])?;
    fs::write(project.join("package.json"), "{}")?;
    let after = graph::project(deps::scan_project(&project)?)?;
    let plan = prune_validation::plan(&before, &after, &request, &project, &[])?;
    fixture.write("inventory.json", &serde_json::to_value(&plan.expected)?)?;
    let path = fixture.root.path().join("validation-plan.json");
    fs::write(&path, serde_json::to_vec(&plan)?)?;
    Ok(path)
}
fn prune_command(fixture: &Fixture, plan: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
    command
        .env_clear()
        .args(["deps", "prune", "validate", "--state"])
        .arg(fixture.root.path().join("state"))
        .arg("--plan")
        .arg(plan)
        .env("PATH", fixture.root.path())
        .env("FIXTURE", fixture.root.path());
    command
}
#[test]
fn pruning_validation_binds_checks_to_sources_and_reports_failures() -> Result {
    let fixture = Fixture::new(json!([
        ["fixture-pass"],
        ["fixture-fail"],
        ["fixture-pass"]
    ]))?;
    let plan = pruning_plan(&fixture)?;
    let output = prune_command(&fixture, &plan).output()?;
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["passed"], false);
    assert_eq!(receipt["checks"].as_array().ok_or("checks")?.len(), 2);
    assert_eq!(receipt["checks"][1]["exit_code"], 37);
    let fixture = Fixture::new(json!([["fixture-pass"]]))?;
    let plan = pruning_plan(&fixture)?;
    let output = prune_command(&fixture, &plan).output()?;
    assert!(output.status.success(), "{output:?}");
    let receipt: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(receipt["passed"], true);
    assert_eq!(receipt["sandbox_id"], "id");
    assert_eq!(
        receipt["checks"][0]["stdout_sha256"],
        ladyshell::files::hash(b"check output\n")
    );
    Ok(())
}

#[test]
fn pruning_validation_refuses_pending_continuous_handoff() -> Result {
    let mut fixture = Fixture::new(json!([["fixture-pass"]]))?;
    let plan = pruning_plan(&fixture)?;
    let mut session = ladyshell::continuous::model::Session::new(
        "task".into(),
        "id".into(),
        "owner".into(),
        "runtime".into(),
        "a".repeat(64),
        "b".repeat(64),
    )?;
    session.begin_checkpoint("checkpoint", 0)?;
    fixture.state["continuous"] = serde_json::to_value(session)?;
    fixture.save()?;
    let output = prune_command(&fixture, &plan).output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Continuous handoff"));
    assert!(!fixture.root.path().join("count").exists());
    Ok(())
}
#[test]
fn pruning_validation_rejects_source_drift_before_and_after_execution() -> Result {
    for after in [false, true] {
        let fixture = Fixture::new(json!([["fixture-pass"]]))?;
        let plan = pruning_plan(&fixture)?;
        fixture.write(
            if after {
                "next-inventory.json"
            } else {
                "inventory.json"
            },
            &json!({}),
        )?;
        let output = prune_command(&fixture, &plan).output()?;
        assert!(!output.status.success(), "{output:?}");
        assert!(
            output.stdout.is_empty(),
            "No success receipt for changed sources"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Sources de validation divergentes")
        );
        if !after {
            assert!(fixture.no_execution());
        }
    }
    for drift in ["provider", "observed.json", "policy.json"] {
        let fixture = Fixture::new(json!([["fixture-pass"]]))?;
        let plan = pruning_plan(&fixture)?;
        fs::write(
            fixture.root.path().join(drift),
            if drift == "provider" { "expired" } else { "{}" },
        )?;
        let output = prune_command(&fixture, &plan).output()?;
        assert!(!output.status.success());
        assert!(fixture.no_execution());
    }
    Ok(())
}

#[test]
fn pruning_validation_requires_an_exclusive_session_lease() -> Result {
    let fixture = Fixture::new(json!([["fixture-pass"]]))?;
    let plan = pruning_plan(&fixture)?;
    let _lease = ladyshell::state::SessionLock::acquire(&fixture.root.path().join("state"), false)?;
    let output = prune_command(&fixture, &plan).output()?;
    assert!(!output.status.success());
    assert!(fixture.no_execution());
    assert!(output.stdout.is_empty());
    Ok(())
}
