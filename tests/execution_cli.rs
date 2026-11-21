use ladyshell::execution::{Invocation, Record};
use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

const ORIGINAL_INTENT: &str = r#"{
  "composition":{"node":{"parent":"original-root-intent","graph":{"id":"selected-check","version":1,"digest":"1111111111111111111111111111111111111111111111111111111111111111"},"node":"check","kind":"provider"}},
  "task":"original-go-project-check",
  "profile":"selected-sandbox-execution",
  "profile_revision":"reviewed-v1",
  "delegation":"original-delegation",
  "intent":"original-invocation",
  "operation":"execute",
  "target":{"provider":"ladyshell","tenant":"project-owner","subject":"installed-receiver"},
  "arguments":{"task":"go-check","context":{"selection":"reviewed","checkout":"pinned"}},
  "expected_version":null,
  "expected_dependencies":[],
  "evidence_revision":1
}"#;
const SCOPE: &str = "--reviewed/target-and-task";
const ID: &str = "original-invocation";
const CONTAINER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CODEX: &str = "/nix/store/00000000000000000000000000000000-ladyshell-codex/bin/codex";

struct Fixture {
    root: tempfile::TempDir,
    receiver_id: String,
    invocation: Invocation,
    deadline: u64,
}

impl Fixture {
    fn new(gate: &str, output_limit: u32) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let path = root.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(path.join("project"))?;
        ladyshell::state::create_directory(&path.join("state"))?;
        let inputs = json!({
            "project": path.join("project"),
            "evaluated":{"config":{"sandbox":{"provider":"test-provider"}}}
        });
        let current = json!({
            "schema_version":2, "sandbox_name":"test", "sandbox_id":"id",
            "policy_hash":"hash", "codex_binary":CODEX, "owner":"owner",
            "image_id":"image", "project_snapshot":"snapshot", "build_dir":"build",
            "snapshot_binary":"/usr/local/bin/ladyshell",
            "context":{"gateway":"test","workspace":"default"},
            "desired_hash":ladyshell::plan::digest(&inputs)?,
            "desired_inputs":inputs
        });
        write_json(&path.join("state/state.json"), &current)?;
        write_json(
            &path.join("policy.json"),
            &json!({"policy":ladyshell::policy::native_policy(CODEX)?}),
        )?;
        write_json(
            &path.join("owner.json"),
            &json!({"task":"1".repeat(64),"deployment":"2".repeat(64),"epoch":7,"incarnation":"3".repeat(32)}),
        )?;
        write_json(
            &path.join("tasks.json"),
            &json!([{"id":"go-check","argv":["fixture-task","exact argument",""],"timeout_seconds":30,"output_limit_bytes":output_limit}]),
        )?;
        fs::write(path.join("gate"), gate)?;
        fs::write(path.join("container-id"), CONTAINER)?;
        runtime(path, false, CONTAINER)?;
        script(
            &path.join("openshell"),
            r#"#!/bin/bash
set -euo pipefail
[[ "$1 $2 $3 $4 $5 $6" == '--gateway test --workspace default --color never' ]]
shift 6
barrier() {
    if [[ $(<"$FIXTURE/gate") == "$1" ]]; then
        printf '%s %s\n' "$PPID" "$$" > "$FIXTURE/$1.tmp"
        /bin/mv "$FIXTURE/$1.tmp" "$FIXTURE/$1"
        while [[ -d "$FIXTURE" && ! -f "$FIXTURE/release" ]]; do /bin/sleep 0.01; done
    fi
}
case "$1 $2" in
    'sandbox get') [[ "$3 $4 $5" == 'test --output json' ]]; /bin/cat "$FIXTURE/observed.json" ;;
    'policy get') [[ "$3 $4 $5 $6" == 'test --full --output json' ]]; /bin/cat "$FIXTURE/policy.json" ;;
    'provider get') [[ "$3" == test-provider ]]; printf 'available\n' ;;
    'sandbox exec')
        if [[ "$3 $4 $5 $6 $7 $8" == '--no-login-shell --no-tty test -- /usr/local/bin/ladyshell snapshot-list' ]]; then
            # Installation also observes inventory. Only gate post-install workers.
            if [[ -f "$FIXTURE/install-complete" ]]; then barrier inventory; fi
            printf '{}'; exit
        fi
        [[ "$3 $4 $5 $6 $7 $8" == '--no-tty --no-login-shell --workdir /sandbox/workspace/project --timeout 30' ]]
        while [[ "$1" != -- ]]; do shift; done
        shift
        [[ "$#" == 3 && "$1" == fixture-task && "$2" == 'exact argument' && -z "$3" ]]
        printf 'launch\n' >> "$FIXTURE/count"
        barrier launch
        if [[ -f "$FIXTURE/overflow" ]]; then
            printf '%0256d' 0
        else
            printf 'original stdout\n'
            printf 'original stderr\n' >&2
        fi ;;
    *) exit 98 ;;
esac
"#,
        )?;
        script(
            &path.join("docker"),
            r#"#!/bin/bash
set -euo pipefail
[[ "$DOCKER_HOST" == unix:///fixture/docker.sock ]]
case "$1" in
    ps)
        [[ "$2 $3 $4 $5 $6 $7 $8 $9" == '-a --no-trunc --filter label=openshell.ai/sandbox-id=id --filter label=openshell.ai/isolation-role=sandbox --format {{.ID}}' ]]
        printf '%s\n' "$(<"$FIXTURE/container-id")" ;;
    inspect)
        [[ "$2" == "$(<"$FIXTURE/container-id")" && "$3" == --format ]]
        /bin/cat "$FIXTURE/container.json" ;;
    info)
        [[ "$2 $3" == '--format {{.ID}}' ]]
        printf 'fixture-daemon\n' ;;
    *) exit 99 ;;
esac
"#,
        )?;
        script(&path.join("ladyshell"), "#!/bin/bash\nexit 99\n")?;

        let installed = successful(install(path, "receiver", "tasks.json").output()?)?;
        let receiver_id = installed["binding"]["receiver_id"]
            .as_str()
            .ok_or("missing receiver identity")?
            .to_owned();
        let invocation = Invocation {
            scope: SCOPE.into(),
            id: ID.into(),
            task: "go-check".into(),
            definition_sha256: installed["definitions"]["go-check"]
                .as_str()
                .ok_or("missing installed definition")?
                .to_owned(),
            intent: serde_json::from_str(ORIGINAL_INTENT)?,
        };
        write_json(
            &path.join("invocation.json"),
            &serde_json::to_value(&invocation)?,
        )?;
        fs::write(path.join("install-complete"), [])?;
        let fixture = Self {
            root,
            receiver_id,
            invocation,
            deadline: unix_now()? + 120,
        };
        successful(fixture.fence("bind").output()?)?;
        successful(fixture.fence("advance").args(["--claim", "0"]).output()?)?;
        successful(fixture.fence("advance").args(["--claim", "11"]).output()?)?;
        Ok(fixture)
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn receiver(&self) -> PathBuf {
        self.path().join("receiver")
    }

    fn selected(&self, name: &str) -> Command {
        let mut command = command(self.path());
        command.args(["execution", name]);
        self.select(&mut command);
        command
    }

    fn select(&self, command: &mut Command) {
        command
            .arg("--receiver")
            .arg(self.receiver())
            .args(["--receiver-id", &self.receiver_id]);
    }

    fn keyed(&self, name: &str) -> Command {
        let mut command = self.selected(name);
        command.arg(format!("--scope={SCOPE}")).args(["--id", ID]);
        command
    }

    fn fence(&self, action: &str) -> Command {
        let mut command = command(self.path());
        command.args(["execution", "fence", action]);
        self.select(&mut command);
        command
            .arg(format!("--scope={SCOPE}"))
            .arg("--owner")
            .arg(self.path().join("owner.json"));
        command
    }

    fn submit(&self, file: &str, claim: u64, before: u64) -> Command {
        let mut command = self.selected("submit");
        command
            .arg("--invocation")
            .arg(self.path().join(file))
            .args(["--reference", "host-admission", "--admit-before"])
            .arg(before.to_string())
            .arg("--owner")
            .arg(self.path().join("owner.json"))
            .arg("--claim")
            .arg(claim.to_string());
        command
    }

    fn status(&self) -> Result<Value> {
        successful(self.keyed("status").output()?)
    }

    fn output(&self, stream: &str, offset: u32, length: u32) -> Command {
        let mut command = self.keyed("output");
        command
            .args(["--stream", stream, "--offset"])
            .arg(offset.to_string())
            .arg("--length")
            .arg(length.to_string());
        command
    }

    fn barrier(&self, name: &str) -> Result<(libc::pid_t, libc::pid_t)> {
        let path = self.path().join(name);
        let mut marker = String::new();
        wait_for(name, || {
            if path.try_exists()? {
                marker = fs::read_to_string(&path)?;
                return Ok(true);
            }
            Ok(false)
        })?;
        let (worker, transport) = marker.trim().split_once(' ').ok_or("malformed barrier")?;
        Ok((worker.parse()?, transport.parse()?))
    }

    fn release(&self) -> Result {
        fs::write(self.path().join("release"), [])?;
        Ok(())
    }

    fn assert_single_launch(&self) -> Result {
        assert_eq!(fs::read(self.path().join("count"))?, b"launch\n");
        Ok(())
    }

    fn receipt(&self, phase: &str) -> Result<Value> {
        let mut status = Value::Null;
        wait_for(phase, || {
            status = self.status()?;
            Ok(status["record"]["phase"] == phase && status["worker_observed"] == false)
        })?;
        Ok(status["record"].take())
    }
}

fn command(path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladyshell"));
    command
        .env_clear()
        .env("PATH", path)
        .env("HOME", path)
        .env("FIXTURE", path)
        .env("DOCKER_HOST", "unix:///fixture/docker.sock")
        .current_dir(path);
    command
}

fn install(path: &Path, receiver: &str, tasks: &str) -> Command {
    let mut command = command(path);
    command
        .args(["execution", "install", "--state"])
        .arg(path.join("state"))
        .arg("--receiver")
        .arg(path.join(receiver))
        .arg("--tasks")
        .arg(path.join(tasks));
    command
}

fn write_json(path: &Path, value: &Value) -> Result {
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}

fn runtime(path: &Path, stopped: bool, id: &str) -> Result {
    write_json(
        &path.join("observed.json"),
        &json!({
            "id":"id","phase":if stopped {"Stopped"} else {"Ready"},
            "configuration_admission":{"policy_hash":"hash"},"labels":{"ladyshell.owner":"owner"},
            "annotations":{"internal.openshell.ai/runtime-generation":"generation"}
        }),
    )?;
    write_json(
        &path.join("container.json"),
        &json!({"id":id,"image":"image",
            "state":{"StartedAt":"2026-01-01T00:00:00Z","Running":!stopped,"Paused":false,"Restarting":false},
            "labels":{"openshell.ai/sandbox-id":"id","openshell.ai/sandbox-name":"test",
            "openshell.ai/sandbox-workspace":"default","openshell.ai/isolation-role":"sandbox",
            "openshell.ai/managed-by":"openshell"}}),
    )
}

fn script(path: &Path, source: &str) -> Result {
    fs::write(path, source)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn successful(output: Output) -> Result<Value> {
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn refused(output: Output) -> Result<String> {
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    Ok(String::from_utf8(output.stderr)?)
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn wait_for(description: &str, mut predicate: impl FnMut() -> Result<bool>) -> Result {
    let until = Instant::now() + Duration::from_secs(15);
    while !predicate()? {
        if Instant::now() >= until {
            return Err(format!("fixture barrier timed out: {description}").into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn block_reply() -> Result<(io::PipeReader, Stdio)> {
    let (reader, mut writer) = io::pipe()?;
    // SAFETY: F_GETPIPE_SZ reads the capacity of this live pipe descriptor.
    let capacity = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETPIPE_SZ) };
    if capacity < 0 {
        return Err(io::Error::last_os_error().into());
    }
    writer.write_all(&vec![0; capacity as usize])?;
    Ok((reader, Stdio::from(writer)))
}

struct Submitting(Child);
impl Drop for Submitting {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn kill_worker(pid: libc::pid_t) -> Result {
    assert!(pid > 1);
    // SAFETY: The fixture wrote its live parent PID at the barrier.
    if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[test]
fn killed_submitter_recovers_one_original_receipt_and_verified_output() -> Result {
    let f = Fixture::new("launch", 4096)?;
    let (_reader, reply) = block_reply()?;
    let mut submit = Submitting(
        f.submit("invocation.json", 11, f.deadline)
            .stdout(reply)
            .spawn()?,
    );
    let (worker, _) = f.barrier("launch")?;
    assert!(submit.0.try_wait()?.is_none());
    // SAFETY: The fixture records the PID of its own live supervisor.
    assert_eq!(unsafe { libc::getsid(worker) }, worker);
    submit.0.kill()?;
    submit.0.wait()?;

    let running = f.status()?;
    assert_eq!(running["record"]["phase"], "dispatching");
    assert_eq!(running["worker_observed"], true);
    refused(f.keyed("recover").output()?)?;
    refused(f.keyed("worker").output()?)?;
    let duplicate = successful(f.submit("invocation.json", 999, 1).output()?)?;
    assert_eq!(duplicate["is_new"], false);
    assert_eq!(duplicate["record"], running["record"]);

    f.release()?;
    let receipt = f.receipt("completed")?;
    assert_eq!(
        receipt["invocation"]["intent"],
        serde_json::from_str::<Value>(ORIGINAL_INTENT)?
    );
    assert_eq!(receipt["outcome"]["provenance"], "openshell_client");
    assert_eq!(
        receipt["outcome"]["result"],
        json!({"kind":"exit","code":0})
    );
    assert_eq!(
        receipt["outcome"]["stdout"]["sha256"],
        ladyshell::files::hash(b"original stdout\n")
    );
    assert!(serde_json::to_vec(&receipt["outcome"])?.len() < 1024);
    assert!(!serde_json::to_string(&receipt)?.contains("original stdout"));

    // Losing the original acknowledgement and reconnecting after the receipt
    // require neither a live runtime nor a replacement admission.
    fs::rename(f.path().join("state"), f.path().join("offline-state"))?;
    fs::remove_file(f.path().join("openshell"))?;
    fs::remove_file(f.path().join("docker"))?;
    assert_eq!(f.status()?["record"], receipt);
    let mut reordered = serde_json::to_string(&f.invocation)?;
    reordered = reordered.replace(
        r#""checkout":"pinned","selection":"reviewed""#,
        r#""selection":"reviewed","checkout":"pinned""#,
    );
    assert!(reordered.contains(r#""selection":"reviewed","checkout":"pinned""#));
    fs::write(f.path().join("reordered.json"), reordered)?;
    let duplicate = successful(f.submit("reordered.json", 0, 0).output()?)?;
    assert_eq!(duplicate["is_new"], false);
    assert_eq!(duplicate["record"], receipt);
    let mut conflict = f.invocation.clone();
    conflict.intent["arguments"]["context"]["selection"] = json!("changed");
    write_json(
        &f.path().join("conflict.json"),
        &serde_json::to_value(&conflict)?,
    )?;
    assert!(refused(f.submit("conflict.json", 11, f.deadline).output()?)?.contains("Conflicting"));
    refused(f.keyed("worker").output()?)?;
    f.assert_single_launch()?;

    for (stream, offset, length, expected) in [
        ("stdout", 0, 6, &b"origin"[..]),
        ("stderr", 9, 7, &b"stderr\n"[..]),
    ] {
        let result = f.output(stream, offset, length).output()?;
        assert!(result.status.success(), "{result:?}");
        assert_eq!(result.stdout, expected);
    }
    refused(f.output("stdout", 0, 1_048_577).output()?)?;
    let directory = f.receiver().join(f.invocation.key().digest()?);
    for (name, mode) in [("", 0o700), ("stdout", 0o600), ("stderr", 0o600)] {
        assert_eq!(
            fs::metadata(directory.join(name))?.permissions().mode() & 0o777,
            mode
        );
    }
    fs::write(directory.join("stdout"), b"tampered stdout\n")?;
    refused(f.output("stdout", 0, 1).output()?)?;
    Ok(())
}

#[test]
fn retained_submit_does_not_leak_an_inheritable_client_pipe() -> Result {
    let f = Fixture::new("launch", 4096)?;
    let (mut reader, writer) = io::pipe()?;
    let writer_fd = writer.as_raw_fd();
    let mut submit = f.submit("invocation.json", 11, f.deadline);
    // SAFETY: The launcher hook only duplicates our live pipe writer and
    // reads errno if fcntl fails. F_DUPFD creates an inheritable descriptor.
    unsafe {
        submit.pre_exec(move || {
            if libc::fcntl(writer_fd, libc::F_DUPFD, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let accepted = successful(submit.output()?)?;
    assert_eq!(accepted["is_new"], true);
    drop(writer);

    f.barrier("launch")?;
    let running = f.status()?;
    assert_eq!(running["worker_observed"], true);
    assert_eq!(running["record"]["phase"], "dispatching");
    // SAFETY: The new pipe reader is live and has no other status flags to preserve.
    if unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    wait_for("client pipe EOF", || match reader.read(&mut [0]) {
        Ok(length) => {
            assert_eq!(length, 0);
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error.into()),
    })?;
    assert_eq!(f.status()?["worker_observed"], true);

    f.release()?;
    f.receipt("completed")?;
    f.assert_single_launch()?;
    Ok(())
}

#[test]
fn retained_detached_session_reports_exec_failure() -> Result {
    let temp = tempfile::tempdir()?;
    let mut command = Command::new(temp.path().join("missing"));
    ladyshell::process::detached_session(&mut command);
    let error = command
        .spawn()
        .err()
        .ok_or("detached spawn lost its child error report")?;
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    Ok(())
}

#[test]
fn retained_submit_compares_original_intent_before_reading_replacement_owner() -> Result {
    let f = Fixture::new("", 4096)?;
    successful(f.submit("invocation.json", 11, f.deadline).output()?)?;
    let receipt = f.receipt("completed")?;
    let owner_path = f.path().join("owner.json");
    fs::remove_file(&owner_path)?;
    let duplicate = successful(f.submit("invocation.json", 11, f.deadline).output()?)?;
    assert_eq!(duplicate["is_new"], false);
    assert_eq!(duplicate["record"], receipt);

    let mut changed = f.invocation.clone();
    changed.intent["profile_revision"] = json!("changed");
    write_json(
        &f.path().join("different.json"),
        &serde_json::to_value(&changed)?,
    )?;
    assert!(refused(f.submit("different.json", 11, f.deadline).output()?)?.contains("Conflicting"));

    fs::write(owner_path, b"{malformed")?;
    let duplicate = successful(f.submit("invocation.json", 0, 0).output()?)?;
    assert_eq!(duplicate["is_new"], false);
    assert_eq!(duplicate["record"], receipt);

    let mut fresh = f.invocation.clone();
    fresh.id = "fresh-intent".into();
    write_json(&f.path().join("fresh.json"), &serde_json::to_value(&fresh)?)?;
    assert!(refused(f.submit("fresh.json", 11, f.deadline).output()?)?.contains("JSON"));
    let store = ladyshell::execution::Store::open(&f.receiver(), &f.receiver_id)?;
    assert!(store.lookup(&fresh)?.is_none());
    f.assert_single_launch()?;
    Ok(())
}

#[test]
fn orphan_before_dispatch_is_consumed_and_delayed_worker_refuses() -> Result {
    let f = Fixture::new("inventory", 4096)?;
    let submission = successful(f.submit("invocation.json", 11, f.deadline).output()?)?;
    assert_eq!(submission["is_new"], true);
    let (worker, _) = f.barrier("inventory")?;
    assert_eq!(f.status()?["record"]["phase"], "accepted");
    refused(f.keyed("worker").output()?)?;
    assert_eq!(f.status()?["worker_observed"], true);
    kill_worker(worker)?;
    assert_eq!(f.receipt("accepted")?, submission["record"]);
    f.release()?;

    let recovered = successful(f.keyed("recover").output()?)?;
    assert_eq!(recovered["phase"], "uncertain");
    assert_eq!(recovered["outcome"], Value::Null);
    assert_eq!(successful(f.keyed("recover").output()?)?, recovered);
    assert_eq!(
        successful(f.submit("invocation.json", 11, f.deadline).output()?)?["record"],
        recovered
    );
    refused(f.keyed("worker").output()?)?;
    assert!(!f.path().join("count").exists());
    Ok(())
}

#[test]
fn killed_supervisor_preserves_fence_until_exact_stopped_runtime_is_observed() -> Result {
    let f = Fixture::new("launch", 4096)?;
    successful(f.submit("invocation.json", 11, f.deadline).output()?)?;
    let (worker, _) = f.barrier("launch")?;
    kill_worker(worker)?;
    f.receipt("dispatching")?;
    f.release()?;
    let state = f.path().join("state");
    assert!(ladyshell::state::SessionLock::acquire(&state, true).is_err());
    let recovered = successful(f.keyed("recover").output()?)?;
    assert_eq!(recovered["phase"], "uncertain");
    assert_eq!(recovered["outcome"], Value::Null);
    let reconcile = || {
        let mut command = f.keyed("reconcile");
        command.args(["--reason", "independently stopped original workload"]);
        command
    };
    refused(reconcile().output()?)?;
    let replaced = "b".repeat(64);
    fs::write(f.path().join("container-id"), &replaced)?;
    runtime(f.path(), true, &replaced)?;
    refused(reconcile().output()?)?;
    assert!(ladyshell::state::SessionLock::acquire(&state, true).is_err());

    fs::write(f.path().join("container-id"), CONTAINER)?;
    runtime(f.path(), true, CONTAINER)?;
    let reconciled = successful(reconcile().output()?)?;
    assert_eq!(reconciled["phase"], "uncertain");
    assert_eq!(
        reconciled["reconciliations"][0]["evidence"]["observation"]["phase"],
        "Stopped"
    );
    assert_eq!(reconciled["environment"], recovered["environment"]);
    assert_eq!(f.status()?["record"], reconciled);
    let _lease = ladyshell::state::SessionLock::acquire(&state, true)?;
    f.assert_single_launch()?;
    Ok(())
}

#[test]
fn strict_host_admission_and_private_bounded_output() -> Result {
    let f = Fixture::new("", 16)?;
    let tasks = fs::read_to_string(f.path().join("tasks.json"))?;
    let duplicate_task_field =
        tasks.replacen(r#""id":"go-check""#, r#""id":"extra","id":"go-check""#, 1);
    fs::write(f.path().join("duplicate-task.json"), duplicate_task_field)?;
    refused(install(f.path(), "other-receiver", "duplicate-task.json").output()?)?;
    assert!(!f.path().join("other-receiver").exists());

    let input = serde_json::to_string(&f.invocation)?;
    let duplicated = input.replacen(
        r#""selection":"reviewed""#,
        r#""selection":"reviewed","selection":"changed""#,
        1,
    );
    fs::write(f.path().join("duplicate.json"), duplicated)?;
    refused(f.submit("duplicate.json", 11, f.deadline).output()?)?;
    let with_clock = input.replacen('{', r#"{"now":0,"#, 1);
    fs::write(f.path().join("clock.json"), with_clock)?;
    refused(f.submit("clock.json", 11, f.deadline).output()?)?;
    fs::write(
        f.path().join("oversize.json"),
        format!("{input}{}", " ".repeat(32 * 1024)),
    )?;
    assert!(refused(f.submit("oversize.json", 11, f.deadline).output()?)?.contains("too large"));
    refused(f.submit("invocation.json", 10, f.deadline).output()?)?;
    refused(f.submit("invocation.json", 11, unix_now()?).output()?)?;
    refused(f.keyed("status").output()?)?;
    assert!(!f.path().join("count").exists());

    let wrong_id = command(f.path())
        .args(["execution", "status", "--receiver"])
        .arg(f.receiver())
        .arg("--receiver-id")
        .arg("0".repeat(64))
        .arg(format!("--scope={SCOPE}"))
        .args(["--id", ID])
        .output()?;
    assert!(refused(wrong_id)?.contains("receiver identity"));

    fs::write(f.path().join("overflow"), [])?;
    successful(f.submit("invocation.json", 11, f.deadline).output()?)?;
    let receipt = f.receipt("uncertain")?;
    let typed: Record = serde_json::from_value(receipt.clone())?;
    assert_eq!(typed.admission.claim, 11);
    assert_eq!(
        typed.admission.owner.ok_or("missing retained owner")?.epoch,
        7
    );
    assert_eq!(receipt["outcome"]["result"], json!({"kind":"output_limit"}));
    assert_eq!(receipt["outcome"]["stdout"]["length"], 16);
    assert_eq!(receipt["outcome"]["stdout"]["truncated"], true);
    let output = f.output("stdout", 0, 16).output()?;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"0000000000000000");
    let retained = f
        .receiver()
        .join(f.invocation.key().digest()?)
        .join("stdout");
    assert_eq!(fs::metadata(retained)?.permissions().mode() & 0o777, 0o600);
    f.assert_single_launch()?;
    Ok(())
}
