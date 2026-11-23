use super::*;
use crate::{
    continuous::{
        host::Observation,
        model::{Acknowledgement, Session},
    },
    files,
    snapshot::{Entry, Inventory},
    state::{self, SessionLock},
};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::symlink, path::PathBuf};

fn select_broker_fixture(f: &mut Fixture) -> Result<()> {
    f.current["image_profile"] = json!("openshell-wasi");
    f.current["broker_binary"] = json!("/nix/store/synthetic-worker/bin/lo-executor-worker");
    f.current["storage"] = json!({});
    f.current
        .as_object_mut()
        .ok_or_else(|| invalid("expected object fixture"))?
        .remove("codex_binary");
    files::publish_json(&f.state.join("state.json"), &f.current, true)
}

#[test]
fn broker_upload_uses_original_environment_and_fixed_bounded_transport() -> Result<()> {
    let mut f = fixture()?;
    select_broker_fixture(&mut f)?;
    let bytes = b"synthetic component input; Stage is a separate operation";
    let digest = files::hash(bytes);
    let environment = f.store.catalog().environment.clone();
    let encoded = serde_json::to_vec(&json!({"Ok":{
        "component":digest,"bytes":bytes.len()}}))?;
    let receipt = upload_with(
        &environment,
        &digest,
        bytes,
        30,
        &mut f.driver,
        |command, timeout, limit, input| {
            let args: Vec<_> = command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let last = &args[args.len() - 6..];
            assert_eq!(
                last,
                [
                    "/usr/local/bin/lo-executor-worker",
                    "broker-upload",
                    "/var/lib/ladyshell/broker/control",
                    "/var/lib/ladyshell/broker/artifacts",
                    "/var/lib/ladyshell/broker/incoming",
                    &digest
                ]
            );
            assert_eq!(input, Some(bytes.as_slice()));
            assert_eq!(timeout, Duration::from_secs(30));
            assert_eq!(limit, 16384);
            (
                ClientResult::Exit { code: 0 },
                CapturedOutputs {
                    stdout: CapturedStream {
                        bytes: encoded,
                        truncated: false,
                    },
                    stderr: CapturedStream::default(),
                },
            )
        },
    )?;
    assert_eq!(receipt.component, digest);
    assert_eq!(receipt.bytes, bytes.len() as u64);
    Ok(())
}

#[test]
fn broker_upload_refuses_changed_runtime_input_or_profile_before_transport() -> Result<()> {
    let mut f = fixture()?;
    let environment = f.store.catalog().environment.clone();
    let bytes = b"input";
    let digest = files::hash(bytes);
    let launched = std::cell::Cell::new(false);
    let no_launch =
        |_: Command, _: Duration, _: usize, _: Option<&[u8]>| -> (ClientResult, CapturedOutputs) {
            launched.set(true);
            (ClientResult::IoFailure, CapturedOutputs::default())
        };
    assert!(upload_with(&environment, &digest, bytes, 30, &mut f.driver, no_launch).is_err());
    select_broker_fixture(&mut f)?;
    assert!(upload_with(
        &environment,
        &digest,
        b"changed",
        30,
        &mut f.driver,
        no_launch
    )
    .is_err());
    assert!(upload_with(&environment, &digest, bytes, 0, &mut f.driver, no_launch).is_err());
    let oversize = vec![0; 2 * 1024 * 1024 + 1];
    assert!(upload_with(
        &environment,
        &files::hash(&oversize),
        &oversize,
        30,
        &mut f.driver,
        no_launch
    )
    .is_err());
    f.driver.generation = "changed-generation".into();
    assert!(upload_with(&environment, &digest, bytes, 30, &mut f.driver, no_launch).is_err());
    assert!(
        !launched.get(),
        "refused upload must not initiate transport"
    );
    Ok(())
}

#[test]
fn broker_upload_never_treats_truncated_mismatched_or_lost_output_as_a_receipt() -> Result<()> {
    let mut f = fixture()?;
    select_broker_fixture(&mut f)?;
    let environment = f.store.catalog().environment.clone();
    let bytes = b"input";
    let digest = files::hash(bytes);
    for kind in ["truncated", "changed", "lost", "operation_error", "extra"] {
        let mut reply = json!({"Ok":{"component":digest,"bytes":bytes.len()}});
        if kind == "changed" {
            reply["Ok"]["component"] = json!("a".repeat(64));
        }
        if kind == "operation_error" {
            reply = json!({"Err":"No space left on device"});
        }
        if kind == "extra" {
            reply["Ok"]["unbound"] = json!(true);
        }
        let encoded = serde_json::to_vec(&reply)?;
        let launched = std::cell::Cell::new(false);
        let result = upload_with(
            &environment,
            &digest,
            bytes,
            30,
            &mut f.driver,
            |_, _, _, _| {
                launched.set(true);
                (
                    if kind == "lost" {
                        ClientResult::IoFailure
                    } else {
                        ClientResult::Exit { code: 0 }
                    },
                    CapturedOutputs {
                        stdout: CapturedStream {
                            bytes: encoded,
                            truncated: kind == "truncated",
                        },
                        stderr: CapturedStream::default(),
                    },
                )
            },
        );
        assert!(launched.get(), "{kind} must exercise transport output");
        assert!(result.is_err(), "{kind} must remain unresolved");
    }
    Ok(())
}
struct Observed {
    generation: String,
    phase: String,
    verified: bool,
    source: Inventory,
    inventories: usize,
    revoke_during_inventory: bool,
}
impl Default for Observed {
    fn default() -> Self {
        Self {
            generation: "generation1".into(),
            phase: "Ready".into(),
            verified: true,
            source: Inventory::new(),
            inventories: 0,
            revoke_during_inventory: false,
        }
    }
}
impl Driver for Observed {
    fn observe(&mut self, current: &Value) -> Result<Observation> {
        Ok(Observation {
            sandbox_id: state::text(current, "sandbox_id")?.into(),
            owner: state::text(current, "owner")?.into(),
            runtime: self.generation.clone(),
            phase: self.phase.clone(),
        })
    }
    fn verify(&mut self, _: &Value) -> Result<()> {
        if self.verified {
            Ok(())
        } else {
            Err(invalid("provider or policy revoked"))
        }
    }
    fn inventory(&mut self, _: &Value) -> Result<Inventory> {
        self.inventories += 1;
        if self.revoke_during_inventory {
            self.verified = false;
        }
        Ok(self.source.clone())
    }
    fn export(&mut self, _: &Value, _: &Path) -> Result<Value> {
        unreachable!()
    }
    fn stop(&mut self, _: &Value) -> Result<()> {
        unreachable!()
    }
    fn start(&mut self, _: &Value) -> Result<()> {
        unreachable!()
    }
    fn apply(&mut self, _: &Value, _: &[u8]) -> Result<Acknowledgement> {
        unreachable!()
    }
    fn can_swap_source(&mut self, _: &Value) -> Result<bool> {
        unreachable!()
    }
}
struct Fixture {
    root: tempfile::TempDir,
    state: PathBuf,
    current: Value,
    store: Store,
    key: Key,
    driver: Observed,
}
fn fixture() -> Result<Fixture> {
    fixture_with_continuous(true)
}
fn fixture_with_continuous(continuous: bool) -> Result<Fixture> {
    fixture_with_input(continuous, None)
}
fn fixture_with_input(continuous: bool, input: Option<InputChannel>) -> Result<Fixture> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(
        root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let state = root.path().join("state");
    state::create_directory(&state)?;
    let project = root.path().join("project");
    fs::create_dir(&project)?;
    let session = Session::new(
        "task".into(),
        "sb".into(),
        "owner".into(),
        "generation1".into(),
        "b".repeat(64),
        "c".repeat(64),
    )?;
    let mut current = json!({"schema_version":2,"sandbox_name":"example","sandbox_id":"sb","owner":"owner","image_id":"image","desired_hash":"desired","policy_hash":"policy","context":{"gateway":"gw","workspace":"ws"},"codex_binary":"codex","snapshot_binary":"/usr/local/bin/ladyshell","project_snapshot":"old","build_dir":"build","desired_inputs":{"project":project,"evaluated":{"config":{"sources":{"exclude":["old"]}}}}});
    if continuous {
        current["continuous"] = serde_json::to_value(session)?;
    }
    current["desired_hash"] = json!(crate::plan::digest(&current["desired_inputs"])?);
    files::publish_json(&state.join("state.json"), &current, false)?;
    let tasks = vec![TaskDefinition {
        id: "task".into(),
        argv: vec!["cmd".into(), "weird argument".into(), "".into()],
        timeout_seconds: 3,
        output_limit_bytes: 4096,
        input,
    }];
    let mut driver = Observed::default();
    let receiver = root.path().join("receiver");
    let binding = install_with(&state, &receiver, tasks, &mut driver)?;
    let store = Store::open(&receiver, &binding.receiver_id)?;
    store.bind_owner("scope", None)?;
    store.advance_claim("scope", None, 1)?;
    let i = Invocation {
        scope: "scope".into(),
        id: "id".into(),
        task: "task".into(),
        definition_sha256: store.catalog().definition_digest("task")?,
        intent: json!({"note":42}),
    };
    let key = i.key();
    store.accept(
        &i,
        &Admission {
            reference: "ref".into(),
            admit_before: 100,
            owner: None,
            claim: 1,
        },
        10,
    )?;
    Ok(Fixture {
        root,
        state,
        current,
        store,
        key,
        driver,
    })
}
fn no_launch(
    _: Command,
    _: Duration,
    _: usize,
    _: Option<&[u8]>,
) -> (ClientResult, CapturedOutputs) {
    unreachable!("refused work launched")
}
#[test]
fn every_changed_preflight_consumes_request_without_launch() -> Result<()> {
    for changed in [
        "source",
        "runtime",
        "verification",
        "exclusions",
        "continuous",
        "owner",
        "claim",
        "expiry",
        "policy",
        "desired",
        "image",
        "name",
        "directory",
    ] {
        let mut f = fixture()?;
        let mut now = 20;
        match changed {
            "source" => {
                f.driver.source.insert(
                    "a".into(),
                    Entry {
                        sha256: "0".repeat(64),
                        size: 0,
                        executable: false,
                    },
                );
            }
            "runtime" => f.driver.generation = "generation2".into(),
            "verification" => f.driver.verified = false,
            "exclusions" => {
                f.current["desired_inputs"]["evaluated"]["config"]["sources"]["exclude"] = json!([])
            }
            "continuous" => f.current["continuous"]["epoch"] = json!(1),
            "owner" => f.store.bind_owner(
                "scope",
                Some(&OwnerFence {
                    task: "1".repeat(64),
                    deployment: "2".repeat(64),
                    epoch: 1,
                    incarnation: "3".repeat(32),
                }),
            )?,
            "claim" => f.store.advance_claim("scope", None, 2)?,
            "expiry" => now = 100,
            "policy" => f.current["policy_hash"] = json!("other"),
            "desired" => f.current["desired_hash"] = json!("other"),
            "image" => f.current["image_id"] = json!("other"),
            "name" => f.current["sandbox_name"] = json!("other"),
            "directory" => {
                fs::rename(&f.state, f.root.path().join("old"))?;
                state::create_directory(&f.state)?;
            }
            _ => unreachable!(),
        }
        files::publish_json(&f.state.join("state.json"), &f.current, true)?;
        let r = worker_with(&f.store, &f.key, &mut f.driver, || Ok(now), no_launch)?;
        assert_eq!(r.phase, Phase::Refused, "{changed}");
        assert!(f.store.acquire_worker(&f.key).is_err());
        if matches!(changed, "policy" | "continuous" | "image" | "name") {
            assert_eq!(
                f.driver.inventories, 1,
                "{changed} contacted a sandbox inventory with a changed state binding"
            );
        }
        SessionLock::acquire(&f.state, false)?;
    }
    Ok(())
}
#[test]
fn dispatch_once_and_release_fence_only_for_intact_completed_receipt() -> Result<()> {
    let mut f = fixture()?;
    let counter = f.root.path().join("count");
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |cmd, timeout, limit, input| {
            assert!(input.is_none());
            let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy()).collect();
            assert!(args.ends_with(&[
                "example".into(),
                "--".into(),
                "cmd".into(),
                "weird argument".into(),
                "".into()
            ]));
            assert!(SessionLock::acquire(&f.state, false).is_err());
            assert!(f.store.acquire_worker(&f.key).is_err());
            let mut shell = Command::new("sh");
            shell
                .args([
                    "-c",
                    "echo ran >> \"$1\"; printf evidence; printf warnings >&2",
                    "sh",
                ])
                .arg(&counter);
            super::super::capture::run_with_input(shell, timeout, limit, input)
        },
    )?;
    assert_eq!(r.phase, Phase::Completed);
    assert_eq!(fs::read_to_string(counter)?, "ran\n");
    assert!(worker_with(&f.store, &f.key, &mut f.driver, || Ok(21), no_launch).is_err());
    SessionLock::acquire(&f.state, true)?;
    Ok(())
}

#[test]
fn reopened_worker_delivers_original_retained_intent_to_fixed_command() -> Result<()> {
    let mut f = fixture_with_input(true, Some(InputChannel::IntentJsonV1 { max_bytes: 128 }))?;
    let original = f.store.inspect(&f.key)?;
    let expected = serde_json::to_vec(&original.invocation.intent)?;
    f.store = Store::open(f.store.directory(), &original.binding.receiver_id)?;
    let record = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |cmd, timeout, limit, input| {
            assert_eq!(input, Some(expected.as_slice()));
            let args: Vec<_> = cmd.get_args().map(|s| s.to_string_lossy()).collect();
            assert!(args.ends_with(&["cmd".into(), "weird argument".into(), "".into()]));
            capture::run_with_input(Command::new("cat"), timeout, limit, input)
        },
    )?;
    assert_eq!(record.phase, Phase::Completed);
    assert_eq!(record.invocation, original.invocation);
    let outcome = record
        .outcome
        .ok_or_else(|| invalid("missing retained outcome"))?;
    assert_eq!(outcome.stdout.length as usize, expected.len());
    assert_eq!(outcome.stdout.sha256, files::hash(&expected));
    assert!(worker_with(&f.store, &f.key, &mut f.driver, || Ok(21), no_launch).is_err());
    Ok(())
}
#[test]
fn uncertain_retains_state_exclusion_until_same_stopped_generation_is_observed() -> Result<()> {
    let mut f = fixture()?;
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |_, timeout, limit, input| {
            let mut c = Command::new("sh");
            c.args(["-c", "printf error >&2; exit 1"]);
            super::super::capture::run_with_input(c, timeout, limit, input)
        },
    )?;
    assert_eq!(r.phase, Phase::Uncertain);
    assert!(SessionLock::acquire(&f.state, true).is_err());
    assert!(!f.store.worker_present(&f.key)?);
    assert!(reconcile_with(&f.store, &f.key, "observed", &mut f.driver).is_err());
    f.driver.phase = "Stopped".into();
    f.driver.generation = "different".into();
    assert!(reconcile_with(&f.store, &f.key, "observed", &mut f.driver).is_err());
    f.driver.generation = "generation1".into();
    let pending = f.root.path().join("original-fence");
    let fence = f.state.join("retained-execution.json");
    fs::copy(&fence, &pending)?;
    let r = reconcile_with(&f.store, &f.key, "observed", &mut f.driver)?;
    assert_eq!(r.phase, Phase::Uncertain);
    assert_eq!(r.reconciliations.len(), 1);
    // Reconstitute the durable prefix after note publication and before unlink.
    fs::copy(pending, &fence)?;
    assert!(SessionLock::acquire(&f.state, false).is_err());
    assert_eq!(r.reconciliations[0].evidence["operator_uid"], unsafe {
        libc::geteuid()
    });
    let r = reconcile_with(&f.store, &f.key, "observed", &mut f.driver)?;
    assert_eq!(r.reconciliations.len(), 1);
    SessionLock::acquire(&f.state, true)?;
    Ok(())
}
#[test]
fn hostile_fence_entries_block_all_ordinary_sessions() -> Result<()> {
    let root = tempfile::tempdir()?;
    let fence = root.path().join("retained-execution.json");
    symlink("absent", &fence)?;
    assert!(SessionLock::acquire(root.path(), false).is_err());
    fs::remove_file(&fence)?;
    fs::write(root.path().join("other"), b"{}")?;
    fs::hard_link(root.path().join("other"), &fence)?;
    assert!(SessionLock::acquire(root.path(), true).is_err());
    fs::remove_file(&fence)?;
    fs::create_dir(fence)?;
    assert!(SessionLock::acquire(root.path(), true).is_err());
    Ok(())
}

#[test]
fn last_clock_check_prevents_spawn_after_durable_dispatch() -> Result<()> {
    let mut f = fixture()?;
    let mut times = [20, 20, 100].into_iter();
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(times.next().unwrap_or(100)),
        no_launch,
    )?;
    assert_eq!(r.phase, Phase::Uncertain);
    assert!(r.dispatched_at.is_some());
    assert!(SessionLock::acquire(&f.state, false).is_err());
    assert!(r.reason.as_deref().is_some_and(|s| s.contains("deadline")));
    Ok(())
}

fn prefix(f: &Fixture, finish: bool) -> Result<()> {
    let owned = f.store.acquire_worker(&f.key)?;
    let record = f.store.inspect(&f.key)?;
    let lock = StateLock::acquire_existing(&f.state)?;
    let session = SessionLock::acquire(&lock.directory, true)?;
    Fence::for_record(&f.store, &record).install(&session)?;
    if finish {
        f.store.begin(&owned, 20)?;
        let mut out = CapturedOutputs::default();
        out.stdout.bytes = b"evidence".to_vec();
        f.store
            .complete(&owned, ClientResult::Exit { code: 0 }, out, 21)?;
    }
    Ok(())
}
#[test]
fn interrupted_fence_install_cannot_become_a_refusal_or_fresh_dispatch() -> Result<()> {
    let mut f = fixture()?;
    prefix(&f, false)?;
    let r = worker_with(&f.store, &f.key, &mut f.driver, || Ok(20), no_launch)?;
    assert_eq!(r.phase, Phase::Uncertain);
    assert!(SessionLock::acquire(&f.state, false).is_err());
    f.driver.phase = "Stopped".into();
    reconcile_with(&f.store, &f.key, "confirmed", &mut f.driver)?;
    SessionLock::acquire(&f.state, false)?;
    Ok(())
}
#[test]
fn recover_only_clears_matching_fence_with_both_outputs_intact() -> Result<()> {
    for damage in [
        "none",
        "state",
        "stdout",
        "intent",
        "fence",
        "other_fence",
        "link",
    ] {
        let f = fixture()?;
        prefix(&f, true)?;
        let outdir = f.store.directory().join(f.key.digest()?);
        let fence = f.state.join("retained-execution.json");
        match damage {
            "state" => {
                fs::rename(&f.state, f.root.path().join("original"))?;
                state::create_directory(&f.state)?;
                fs::copy(
                    f.root.path().join("original/retained-execution.json"),
                    &fence,
                )?;
            }
            "stdout" => fs::write(outdir.join("stdout"), b"replaced")?,
            "intent" => fs::remove_file(outdir.join("intent.json"))?,
            "fence" => fs::write(&fence, b"{}")?,
            "other_fence" => {
                let mut v = crate::json::parse(&fs::read(&fence)?)?;
                v["key"]["id"] = json!("other");
                fs::write(&fence, serde_json::to_vec(&v)?)?;
            }
            "link" => fs::hard_link(&fence, f.root.path().join("copy"))?,
            _ => {}
        }
        assert!(SessionLock::acquire(&f.state, false).is_err());
        if damage == "none" {
            assert_eq!(recover(&f.store, &f.key)?.phase, Phase::Completed);
            SessionLock::acquire(&f.state, false)?;
        } else {
            assert!(recover(&f.store, &f.key).is_err(), "{damage}");
            assert!(SessionLock::acquire(&f.state, false).is_err());
        }
    }
    Ok(())
}
#[test]
fn worker_crash_helper() -> Result<()> {
    let Some(root) = std::env::var_os("LADYSHELL_UNIT_RETAINED_CRASH_DIR") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let receiver_id = fs::read_to_string(root.join("receiver-id"))?;
    let store = Store::open(&root.join("receiver"), &receiver_id)?;
    let key = Key {
        scope: "scope".into(),
        id: "id".into(),
    };
    worker_with(
        &store,
        &key,
        &mut Observed::default(),
        || Ok(20),
        |_, _, _, _| {
            if root.join("after").exists() {
                let mut cmd = Command::new("sh");
                cmd.args(["-c", "echo ran >> \"$1\"", "sh"])
                    .arg(root.join("count"));
                assert!(cmd.status().is_ok_and(|s| s.success()));
            }
            assert!(fs::write(root.join("barrier"), b"ready").is_ok());
            loop {
                std::thread::park()
            }
        },
    )?;
    Ok(())
}
#[test]
fn sigkill_before_and_after_spawn_keeps_managed_environment_blocked() -> Result<()> {
    use std::{process::Stdio, time::Instant};
    for after in [false, true] {
        let f = fixture()?;
        let root = f.root.path();
        fs::write(root.join("receiver-id"), &f.store.binding().receiver_id)?;
        if after {
            fs::write(root.join("after"), b"")?;
        }

        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "execution::runtime::tests::worker_crash_helper"])
            .env("LADYSHELL_UNIT_RETAINED_CRASH_DIR", root)
            .stdout(Stdio::null())
            .spawn()?;
        let end = Instant::now() + Duration::from_secs(10);
        while !root.join("barrier").try_exists()? {
            if child.try_wait()?.is_some() || Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                return Err(invalid("Worker fixture never reached dispatch barrier"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(status(&f.store, &f.key)?.worker_observed);
        assert!(recover(&f.store, &f.key).is_err());
        child.kill()?;
        child.wait()?;
        let before = status(&f.store, &f.key)?;
        assert!(!before.worker_observed);
        assert_eq!(before.record.phase, Phase::Dispatching);
        assert_eq!(status(&f.store, &f.key)?.record, before.record);
        assert!(SessionLock::acquire(&f.state, true).is_err());
        assert_eq!(recover(&f.store, &f.key)?.phase, Phase::Uncertain);
        assert!(SessionLock::acquire(&f.state, false).is_err());
        assert_eq!(root.join("count").exists(), after);
        if after {
            assert_eq!(fs::read_to_string(root.join("count"))?, "ran\n");
        }
    }
    Ok(())
}

#[test]
fn abandoned_unpublished_fence_stage_does_not_wedge_future_work() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut f = fixture()?;
    let staged = f.state.join(".retained-execution.json.pending");
    fs::write(&staged, b"partial")?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |_, timeout, limit, input| {
            capture::run_with_input(Command::new("true"), timeout, limit, input)
        },
    )?;
    assert_eq!(r.phase, Phase::Completed);
    assert!(!staged.exists());
    Ok(())
}

#[test]
fn ordinary_installation_binds_runtime_live_inventory_and_excludes_project_and_state() -> Result<()>
{
    let mut f = fixture()?;
    f.current
        .as_object_mut()
        .ok_or_else(|| invalid("fixture state object"))?
        .remove("continuous");
    files::publish_json(&f.state.join("state.json"), &f.current, true)?;
    let tasks = f.store.catalog().tasks.clone();
    let project = f.root.path().join("project");
    for path in [project.join("receiver"), f.state.join("receiver")] {
        assert!(install_with(&f.state, &path, tasks.clone(), &mut f.driver).is_err());
        assert!(!path.exists());
    }
    let receiver = f.root.path().join("ordinary");
    f.driver.source.insert(
        "unit".into(),
        Entry {
            size: 0,
            executable: false,
            sha256: "0".repeat(64),
        },
    );
    let b = install_with(&f.state, &receiver, tasks, &mut f.driver)?;
    let store = Store::open(&receiver, &b.receiver_id)?;
    let env = &store.catalog().environment;
    assert_eq!(env.runtime, "generation1");
    assert!(env.continuous.is_null());
    assert_eq!(env.exclusions, ["old"]);
    assert_eq!(env.source_sha256, plan::digest(&f.driver.source)?);
    let r = f.store.inspect(&f.key)?;
    fs::rename(&f.state, f.root.path().join("vanished"))?;
    let mut changed = r.admission.clone();
    changed.admit_before = 0;
    let duplicate = submit(&f.store, &r.invocation, &changed)?;
    assert!(!duplicate.is_new);
    assert_eq!(r, duplicate.record);
    Ok(())
}

#[test]
fn selected_installation_refuses_changed_generation_before_receiver_creation() -> Result<()> {
    let mut f = fixture()?;
    let selected = state::select_generation(&f.state)?;
    let tasks = f.store.catalog().tasks.clone();
    let receiver = f.root.path().join("selected-receiver");
    let mut changed = f.current.clone();
    changed["owner"] = json!("replacement");
    files::publish_json(&f.state.join("state.json"), &changed, true)?;
    let error = install_selected(
        &f.state,
        &receiver,
        tasks.clone(),
        &mut f.driver,
        Some(&selected),
    )
    .err()
    .ok_or_else(|| invalid("replacement installed"))?;
    assert!(error.to_string().contains("selection"), "{error}");
    assert!(!receiver.exists());
    files::publish_json(&f.state.join("state.json"), &f.current, true)?;
    let binding = install_selected(&f.state, &receiver, tasks, &mut f.driver, Some(&selected))?;
    let store = Store::open(&receiver, &binding.receiver_id)?;
    assert_eq!(store.catalog().environment.owner, f.current["owner"]);
    Ok(())
}

#[test]
fn provider_revocation_during_live_inventory_refuses_before_dispatch() -> Result<()> {
    let mut f = fixture()?;
    f.driver.revoke_during_inventory = true;
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |_, _, _, _| (ClientResult::Exit { code: 0 }, CapturedOutputs::default()),
    )?;
    assert_eq!(r.phase, Phase::Refused);
    assert!(r.dispatched_at.is_none());
    Ok(())
}

mod standalone_sync;

#[test]
fn untrusted_snapshot_binary_refuses_install_before_inventory() -> Result<()> {
    let mut f = fixture()?;
    f.current["snapshot_binary"] = json!("/sandbox/workspace/project/helper");
    files::publish_json(&f.state.join("state.json"), &f.current, true)?;
    let receiver = f.root.path().join("rejected");
    let result = install_with(
        &f.state,
        &receiver,
        f.store.catalog().tasks.clone(),
        &mut f.driver,
    );
    assert_eq!(
        f.driver.inventories, 1,
        "untrusted helper reached inventory"
    );
    assert!(result.is_err());
    assert!(!receiver.exists());
    Ok(())
}

#[test]
fn untrusted_snapshot_binary_refuses_accepted_worker_before_inventory() -> Result<()> {
    let mut f = fixture()?;
    f.current["snapshot_binary"] = json!("/sandbox/workspace/project/helper");
    files::publish_json(&f.state.join("state.json"), &f.current, true)?;
    let r = worker_with(
        &f.store,
        &f.key,
        &mut f.driver,
        || Ok(20),
        |_, _, _, _| (ClientResult::Exit { code: 0 }, CapturedOutputs::default()),
    )?;
    assert_eq!(
        f.driver.inventories, 1,
        "untrusted helper reached inventory"
    );
    assert_eq!(r.phase, Phase::Refused);
    assert!(r.dispatched_at.is_none());
    Ok(())
}

// The real receiver journal and fence survive a synthetic lost transport.
// Only the external runtime/transport are substituted in this unit fixture.
fn orphaned_broker() -> Result<Fixture> {
    orphaned_broker_operation("execute")
}
fn orphaned_broker_operation(kind: &str) -> Result<Fixture> {
    let mut f = fixture_with_continuous(false)?;
    select_broker_fixture(&mut f)?;
    let binding = install_with(
        &f.state,
        &f.root.path().join("broker-receiver"),
        vec![TaskDefinition {
            id: "lo-broker".into(),
            argv: [
                "/usr/local/bin/lo-executor-worker",
                "broker",
                "/var/lib/ladyshell/broker/control",
                "/var/lib/ladyshell/broker/artifacts",
                "/var/lib/ladyshell/broker/incoming",
            ]
            .map(String::from)
            .to_vec(),
            timeout_seconds: 3,
            output_limit_bytes: 16384,
            input: Some(InputChannel::IntentJsonV1 { max_bytes: 16384 }),
        }],
        &mut f.driver,
    )?;
    f.store = Store::open(&f.root.path().join("broker-receiver"), &binding.receiver_id)?;
    f.store.bind_owner("scope", None)?;
    f.store.advance_claim("scope", None, 1)?;
    let invocation = Invocation {
        scope: "scope".into(),
        id: "original".into(),
        task: "lo-broker".into(),
        definition_sha256: f.store.catalog().definition_digest("lo-broker")?,
        intent: json!({"format":1,"operation":{"kind":kind,"start":{
            "request":{"fixture":"original typed LO request"},"input":"original input"}}}),
    };
    f.key = invocation.key();
    f.store.accept(
        &invocation,
        &Admission {
            reference: "ref".into(),
            admit_before: 100,
            owner: None,
            claim: 1,
        },
        10,
    )?;
    // Drop ownership after the dispatch marker, without a receiver completion.
    let worker = f.store.acquire_worker(&f.key)?;
    let lock = StateLock::acquire_existing(&f.state)?;
    let session = SessionLock::acquire(&f.state, true)?;
    Fence::for_record(&f.store, &f.store.inspect(&f.key)?).install(&session)?;
    f.store.begin(&worker, 20)?;
    drop(session);
    drop(lock);
    drop(worker);
    f.store.recover(&f.key, 21)?;
    Ok(f)
}

#[test]
fn orphan_observation_preserves_original_uncertainty_and_fence() -> Result<()> {
    let mut f = orphaned_broker()?;
    let before = serde_json::to_value(f.store.inspect(&f.key)?)?;
    let fence = fs::read(f.state.join("retained-execution.json"))?;
    let result = observe_broker_with(
        &f.store,
        &f.key,
        &"a".repeat(64),
        &mut f.driver,
        |command, timeout, limit, input| {
            let argv: Vec<_> = command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                &argv[argv.len() - 5..],
                [
                    "/usr/local/bin/lo-executor-worker",
                    "broker",
                    "/var/lib/ladyshell/broker/control",
                    "/var/lib/ladyshell/broker/artifacts",
                    "/var/lib/ladyshell/broker/incoming"
                ]
            );
            assert_eq!(timeout, Duration::from_secs(3));
            assert_eq!(limit, 16384);
            assert_eq!(
                serde_json::from_slice::<Value>(input.unwrap_or_default()).ok(),
                Some(json!({"format":1,"operation":{"kind":"observe","request":{
                    "fixture":"original typed LO request"},"request_digest":"a".repeat(64)}}))
            );
            assert!(matches!(f.store.worker_present(&f.key), Ok(true)));
            assert!(StateLock::acquire_existing(&f.state).is_err());
            assert!(SessionLock::acquire(&f.state, true).is_err());
            (
                ClientResult::Exit { code: 0 },
                CapturedOutputs {
                    stdout: CapturedStream {
                        bytes: b"historical reply validated by LO".to_vec(),
                        truncated: false,
                    },
                    stderr: CapturedStream::default(),
                },
            )
        },
    )?;
    assert_eq!(result, b"historical reply validated by LO");
    assert_eq!(serde_json::to_value(f.store.inspect(&f.key)?)?, before);
    assert_eq!(fs::read(f.state.join("retained-execution.json"))?, fence);
    assert!(SessionLock::acquire(&f.state, true).is_err());
    assert!(f.store.acquire_worker(&f.key).is_err());
    Ok(())
}

#[test]
fn fenced_cleanup_keeps_uncertainty_and_requires_original_generation() -> Result<()> {
    let f = orphaned_broker()?;
    let selected = state::select_generation(&f.state)?;
    let before = serde_json::to_value(f.store.inspect(&f.key)?)?;
    let args = crate::request::Destroy {
        state: f.state.clone(),
        discard_work: false,
    };
    let receipt =
        crate::destroy::with_recovery(&args, &selected, &f.store, &f.key, |lock, current| {
            assert_eq!(current["sandbox_id"], "sb");
            assert_eq!(lock.directory, f.state);
            assert!(SessionLock::acquire(&f.state, true).is_err());
            assert!(f.store.worker_present(&f.key)?);
            assert!(StateLock::acquire_existing(&f.state).is_err());
            Ok(json!({"test":"only the existing sealed cleanup driver may run here"}))
        })?;
    assert_eq!(
        receipt["test"],
        "only the existing sealed cleanup driver may run here"
    );
    assert_eq!(serde_json::to_value(f.store.inspect(&f.key)?)?, before);
    assert!(SessionLock::acquire(&f.state, true).is_err());
    let mut changed = f.current.clone();
    changed["unreviewed_extension"] = json!(true);
    files::publish_json(&f.state.join("state.json"), &changed, true)?;
    assert!(crate::destroy::with_recovery(
        &args,
        &selected,
        &f.store,
        &f.key,
        |_, _| unreachable!("changed generation reached cleanup")
    )
    .is_err());
    Ok(())
}

#[test]
fn orphan_observation_refuses_changed_or_absent_original_evidence() -> Result<()> {
    for damage in [
        "missing_fence",
        "other_fence",
        "runtime",
        "source",
        "state",
        "live_recovery",
        "digest",
        "deleting",
    ] {
        let mut f = orphaned_broker()?;
        let mut held = None;
        let mut digest = "a".repeat(64);
        match damage {
            "missing_fence" => fs::remove_file(f.state.join("retained-execution.json"))?,
            "other_fence" => {
                let path = f.state.join("retained-execution.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["intent_sha256"] = json!("b".repeat(64));
                files::publish_json(&path, &value, true)?;
            }
            "runtime" => f.driver.generation = "replacement".into(),
            "source" => {
                f.driver.source.insert(
                    "changed".into(),
                    Entry {
                        sha256: "0".repeat(64),
                        size: 0,
                        executable: false,
                    },
                );
            }
            "state" => {
                f.current["policy_hash"] = json!("replacement");
                files::publish_json(&f.state.join("state.json"), &f.current, true)?;
            }
            "live_recovery" => held = Some(f.store.acquire_recovery(&f.key)?),
            "digest" => digest = "A".repeat(64),
            "deleting" => fs::write(f.state.join("broker-destroy.json"), b"{}")?,
            _ => unreachable!(),
        }
        assert!(
            observe_broker_with(&f.store, &f.key, &digest, &mut f.driver, no_launch).is_err(),
            "{damage}"
        );
        assert_eq!(f.store.inspect(&f.key)?.phase, Phase::Uncertain);
        assert!(f.store.acquire_worker(&f.key).is_err());
        drop(held);
    }
    Ok(())
}

#[test]
fn fenced_cleanup_permits_interrupted_nonexecution_but_observe_does_not() -> Result<()> {
    let mut f = orphaned_broker_operation("stage")?;
    assert!(
        observe_broker_with(&f.store, &f.key, &"a".repeat(64), &mut f.driver, no_launch).is_err()
    );
    let selected = state::select_generation(&f.state)?;
    let mut args = crate::request::Destroy {
        state: f.state.clone(),
        discard_work: true,
    };
    assert!(crate::destroy::with_recovery(
        &args,
        &selected,
        &f.store,
        &f.key,
        |_, _| unreachable!("discard reached cleanup")
    )
    .is_err());
    args.discard_work = false;
    crate::destroy::with_recovery(&args, &selected, &f.store, &f.key, |_, _| Ok(Value::Null))?;
    // Cleanup after a lost deletion reply must enter the existing journal even
    // when its original remote runtime is absent. No live preflight here.
    fs::write(f.state.join("broker-destroy.json"), b"{}")?;
    crate::destroy::with_recovery(&args, &selected, &f.store, &f.key, |_, _| Ok(Value::Null))?;
    assert_eq!(f.store.inspect(&f.key)?.phase, Phase::Uncertain);
    assert!(SessionLock::acquire(&f.state, true).is_err());
    Ok(())
}

#[test]
fn orphan_observation_never_acknowledges_lost_or_truncated_transport() -> Result<()> {
    for failure in ["lost", "truncated", "oversize"] {
        let mut f = orphaned_broker()?;
        let before = serde_json::to_value(f.store.inspect(&f.key)?)?;
        assert!(observe_broker_with(
            &f.store,
            &f.key,
            &"a".repeat(64),
            &mut f.driver,
            |_, _, _, _| {
                (
                    if failure == "lost" {
                        ClientResult::IoFailure
                    } else {
                        ClientResult::Exit { code: 0 }
                    },
                    CapturedOutputs {
                        stdout: CapturedStream {
                            bytes: vec![0; if failure == "oversize" { 16385 } else { 1 }],
                            truncated: failure == "truncated",
                        },
                        stderr: CapturedStream::default(),
                    },
                )
            }
        )
        .is_err());
        assert_eq!(serde_json::to_value(f.store.inspect(&f.key)?)?, before);
        assert!(SessionLock::acquire(&f.state, true).is_err());
    }
    Ok(())
}
