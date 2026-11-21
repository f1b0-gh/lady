use ladyshell::audit::{
    journal::RunJournal,
    model::{Budget, InvocationStatus, Role, RunStatus},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn private_parent() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn create(parent: &Path, invocations: u32) -> ladyshell::error::Result<RunJournal> {
    RunJournal::create(
        parent,
        &"a".repeat(64),
        Budget {
            invocations,
            seconds: 60,
        },
    )
}

fn document(directory: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&fs::read(
        directory.join("audit-journal.json"),
    )?)?)
}

fn saved(parent: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let journal = create(parent, 2)?;
    Ok(journal.directory().to_path_buf())
}

#[test]
fn invocation_is_durable_before_launch_and_failures_do_not_refund_budget() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 1)?;
    assert!(journal.begin_invocation("first", Role::Hunter).is_err());
    journal.start()?;
    journal.begin_invocation("first", Role::Hunter)?;
    let stored = document(journal.directory())?;
    assert_eq!(stored["status"], "running");
    assert_eq!(stored["invocations"][0]["id"], "first");
    assert!(stored["invocations"][0]["status"].is_null());
    journal.finish_invocation("first", InvocationStatus::Failed)?;
    assert_eq!(
        document(journal.directory())?["invocations"][0]["status"],
        "failed"
    );
    assert!(journal.begin_invocation("second", Role::Verifier).is_err());
    assert!(journal
        .finish_invocation("first", InvocationStatus::Finished)
        .is_err());
    assert_eq!(journal.data().invocations.len(), 1);
    Ok(())
}

#[test]
fn interrupted_pending_attempts_survive_recovery_without_replay_or_restart() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    journal.begin_invocation("first", Role::Recon)?;
    journal.finish_invocation("first", InvocationStatus::Finished)?;
    journal.begin_invocation("second", Role::Hunter)?;
    let directory = journal.directory().to_path_buf();
    drop(journal);
    let mut recovered = RunJournal::open(&directory)?;
    assert_eq!(recovered.data().status, RunStatus::Interrupted);
    assert_eq!(recovered.data().invocations.len(), 2);
    assert_eq!(
        recovered.data().invocations[0].status,
        Some(InvocationStatus::Finished)
    );
    assert_eq!(
        recovered.data().invocations[1].status,
        Some(InvocationStatus::Interrupted)
    );
    assert!(!recovered.data().open_obligations.is_empty());
    assert_eq!(document(&directory)?["status"], "interrupted");
    assert!(recovered.start().is_err());
    assert!(recovered.begin_invocation("third", Role::Verifier).is_err());
    assert!(recovered.finish(RunStatus::Complete).is_err());
    let before = document(&directory)?;
    drop(recovered);
    let _again = RunJournal::open(&directory)?;
    assert_eq!(document(&directory)?, before);
    Ok(())
}

#[test]
fn resource_intents_are_durable_and_cleanup_requires_exact_identity() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    journal.resource_intent("target", "owner", json!({"gateway":"fixture"}))?;
    assert_eq!(
        document(journal.directory())?["resources"][0]["name"],
        "target"
    );
    assert!(!journal.data().cleanup_verified);
    assert!(journal.resource_deleted("target", "different").is_err());
    journal.resource_created("target", "sandbox-1")?;
    assert!(journal.resource_created("target", "sandbox-1").is_err());
    assert!(journal.resource_deleted("target", "different").is_err());
    assert!(journal.resolve_absent_intent("target").is_err());
    journal.resource_deleted("target", "sandbox-1")?;
    assert!(journal.data().cleanup_verified);
    assert_eq!(
        document(journal.directory())?["resources"][0]["deleted"],
        true
    );
    Ok(())
}

#[test]
fn unknown_resource_identity_stays_unverified_until_controller_observes_absence() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    journal.resource_intent("target", "owner", json!({}))?;
    let directory = journal.directory().to_path_buf();
    drop(journal);
    let mut journal = RunJournal::open(&directory)?;
    assert!(!journal.data().cleanup_verified);
    journal.resolve_absent_intent("target")?;
    assert!(journal.data().cleanup_verified);
    assert!(journal.data().resources[0].id.is_none());
    assert_eq!(journal.data().status, RunStatus::Interrupted);
    Ok(())
}

#[test]
fn recovered_intent_can_record_one_reobserved_identity_without_restarting() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    journal.resource_intent("target", "owner", json!({"gateway":"fixture"}))?;
    let directory = journal.directory().to_path_buf();
    drop(journal);
    let mut recovered = RunJournal::open(&directory)?;
    recovered.resource_created("target", "observed-id")?;
    assert_eq!(recovered.data().resources[0].owner, "owner");
    assert_eq!(
        recovered.data().resources[0].context,
        json!({"gateway":"fixture"})
    );
    assert!(recovered.resource_created("target", "other-id").is_err());
    assert!(recovered
        .resource_created("unrelated", "observed-id")
        .is_err());
    assert!(recovered
        .resource_intent("unrelated", "owner", json!({}))
        .is_err());
    assert!(recovered.start().is_err());
    recovered.resource_deleted("target", "observed-id")?;
    assert!(recovered.data().cleanup_verified);
    assert_eq!(recovered.data().status, RunStatus::Interrupted);
    Ok(())
}

#[test]
fn completion_requires_finished_invocations_environment_and_cleanup() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 1)?;
    journal.start()?;
    journal.begin_invocation("first", Role::Hunter)?;
    journal.resource_intent("target", "owner", json!({}))?;
    assert!(journal.finish(RunStatus::Complete).is_err());
    journal.finish_invocation("first", InvocationStatus::Finished)?;
    assert!(journal.finish(RunStatus::Complete).is_err());
    journal.observe_environment()?;
    assert!(journal.finish(RunStatus::Complete).is_err());
    journal.resolve_absent_intent("target")?;
    journal.finish(RunStatus::Complete)?;
    assert_eq!(document(journal.directory())?["status"], "complete");
    assert!(journal.start().is_err());
    assert!(journal.resource_intent("new", "owner", json!({})).is_err());
    assert!(journal.finish(RunStatus::Partial).is_err());
    Ok(())
}

#[test]
fn failed_attempt_or_open_obligation_cannot_become_complete() -> TestResult {
    for failed in [false, true] {
        let temp = private_parent()?;
        let mut journal = create(temp.path(), 1)?;
        journal.start()?;
        journal.observe_environment()?;
        journal.begin_invocation("first", Role::Hunter)?;
        journal.finish_invocation(
            "first",
            if failed {
                InvocationStatus::Failed
            } else {
                InvocationStatus::Finished
            },
        )?;
        if !failed {
            journal.add_obligation("Missing independent validation")?;
        }
        assert!(journal.finish(RunStatus::Complete).is_err());
        journal.finish(RunStatus::Partial)?;
        assert_eq!(journal.data().status, RunStatus::Partial);
    }
    Ok(())
}

#[test]
fn terminal_failure_records_pending_attempts_and_preserves_unresolved_cleanup() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 1)?;
    journal.start()?;
    journal.begin_invocation("first", Role::Hunter)?;
    journal.resource_intent("target", "owner", json!({}))?;
    journal.finish(RunStatus::Failed)?;
    assert_eq!(
        journal.data().invocations[0].status,
        Some(InvocationStatus::Interrupted)
    );
    assert!(!journal.data().cleanup_verified);
    assert!(journal
        .finish_invocation("first", InvocationStatus::Finished)
        .is_err());
    let directory = journal.directory().to_path_buf();
    drop(journal);
    assert_eq!(
        RunJournal::open(&directory)?.data().status,
        RunStatus::Failed
    );
    Ok(())
}

#[test]
fn concurrent_open_refuses_the_held_run_lock() -> TestResult {
    let temp = private_parent()?;
    let journal = create(temp.path(), 2)?;
    assert!(RunJournal::open(journal.directory()).is_err());
    let directory = journal.directory().to_path_buf();
    drop(journal);
    let _recovered = RunJournal::open(&directory)?;
    Ok(())
}

#[test]
fn creates_unique_private_retained_runs_without_adopting_existing_data() -> TestResult {
    let temp = private_parent()?;
    fs::write(temp.path().join("sentinel"), b"unchanged")?;
    let first = create(temp.path(), 2)?;
    let second = create(temp.path(), 2)?;
    assert_ne!(first.directory(), second.directory());
    assert_ne!(first.data().run_id, second.data().run_id);
    let directory = first.directory().to_path_buf();
    assert_eq!(fs::metadata(&directory)?.mode() & 0o077, 0);
    assert_eq!(
        fs::metadata(directory.join("audit-journal.json"))?.mode() & 0o077,
        0
    );
    drop(first);
    assert!(directory.exists());
    assert_eq!(fs::read(temp.path().join("sentinel"))?, b"unchanged");
    Ok(())
}

#[test]
fn strict_recovery_refuses_unknown_fields_versions_and_inconsistent_state() -> TestResult {
    let mutations: &[fn(&mut Value)] = &[
        |v| v["unexpected"] = json!(true),
        |v| v["schema_version"] = json!(99),
        |v| v["run_id"] = json!("../other"),
        |v| v["plan_sha256"] = json!("invalid"),
        |v| v["budget"]["seconds"] = json!(0),
        |v| v["budget"]["unexpected"] = json!(0),
        |v| v["status"] = json!("complete"),
        |v| v["cleanup_verified"] = json!(false),
        |v| v["invocations"] = json!([{"id":"same","role":"hunter","status":null},{"id":"same","role":"hunter","status":null}]),
        |v| v["resources"] = json!([{"name":"target","id":null,"owner":"owner","context":{},"deleted":false,"extra":true}]),
        |v| {
            v["status"] = json!("running");
            v["invocations"] = json!([{"id":"first","role":"hunter"}]);
        },
        |v| {
            v["status"] = json!("running");
            v["cleanup_verified"] = json!(false);
            v["resources"] =
                json!([{"name":"target","owner":"owner","context":{},"deleted":false}]);
        },
    ];
    for mutate in mutations {
        let temp = private_parent()?;
        let directory = saved(temp.path())?;
        let mut data = document(&directory)?;
        mutate(&mut data);
        fs::write(
            directory.join("audit-journal.json"),
            serde_json::to_vec(&data)?,
        )?;
        assert!(RunJournal::open(&directory).is_err(), "accepted {data}");
    }
    Ok(())
}

#[test]
fn strict_recovery_rejects_duplicate_keys_and_oversized_files() -> TestResult {
    let temp = private_parent()?;
    let directory = saved(temp.path())?;
    let file = directory.join("audit-journal.json");
    fs::write(&file, br#"{"schema_version":1,"schema_version":1}"#)?;
    assert!(RunJournal::open(&directory).is_err());
    fs::OpenOptions::new()
        .write(true)
        .open(&file)?
        .set_len(32 * 1024 * 1024 + 1)?;
    assert!(RunJournal::open(&directory).is_err());
    Ok(())
}

#[test]
fn recovery_refuses_symlinks_in_every_directory_component() -> TestResult {
    let temp = private_parent()?;
    let directory = saved(temp.path())?;
    let alias = temp.path().join("alias");
    symlink(&directory, &alias)?;
    assert!(RunJournal::open(&alias).is_err());
    let outer = temp.path().join("outer");
    symlink(temp.path(), &outer)?;
    let name = directory.file_name().ok_or("missing run directory name")?;
    assert!(RunJournal::open(&outer.join(name)).is_err());
    assert!(create(&outer, 2).is_err());
    Ok(())
}

#[test]
fn recovery_refuses_symlink_hardlink_and_fifo_journals() -> TestResult {
    for kind in ["symlink", "hardlink", "fifo"] {
        let temp = private_parent()?;
        let directory = saved(temp.path())?;
        let file = directory.join("audit-journal.json");
        let original = temp.path().join("original");
        fs::rename(&file, &original)?;
        match kind {
            "symlink" => symlink(&original, &file)?,
            "hardlink" => fs::hard_link(&original, &file)?,
            _ => {
                use std::os::unix::ffi::OsStrExt;
                let name = std::ffi::CString::new(file.as_os_str().as_bytes())?;
                // SAFETY: name is a valid, live NUL-terminated path in this fixture.
                let result = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
                assert_eq!(result, 0);
            }
        }
        assert!(RunJournal::open(&directory).is_err(), "accepted {kind}");
    }
    Ok(())
}

#[test]
fn writes_stay_with_pinned_directory_after_path_replacement() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    let original = journal.directory().to_path_buf();
    let retained = temp.path().join("retained");
    fs::rename(&original, &retained)?;
    fs::create_dir(&original)?;
    fs::write(original.join("sentinel"), b"untouched")?;
    journal.start()?;
    journal.begin_invocation("first", Role::Hunter)?;
    assert_eq!(document(&retained)?["invocations"][0]["id"], "first");
    assert!(!original.join("audit-journal.json").exists());
    assert_eq!(fs::read(original.join("sentinel"))?, b"untouched");
    Ok(())
}

#[test]
fn refused_write_does_not_advance_memory_or_overwrite_hostile_destination() -> TestResult {
    let temp = private_parent()?;
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    let file = journal.directory().join("audit-journal.json");
    let original = temp.path().join("copy");
    fs::hard_link(&file, &original)?;
    assert!(journal.begin_invocation("first", Role::Hunter).is_err());
    assert!(journal.data().invocations.is_empty());
    assert!(document(journal.directory())?["invocations"]
        .as_array()
        .is_some_and(Vec::is_empty));
    Ok(())
}

#[test]
fn inputs_and_parent_permissions_are_bounded_before_mutation() -> TestResult {
    let temp = private_parent()?;
    assert!(create(temp.path(), 0).is_err());
    assert!(RunJournal::create(
        temp.path(),
        "bad",
        Budget {
            invocations: 1,
            seconds: 1
        }
    )
    .is_err());
    let mut journal = create(temp.path(), 2)?;
    journal.start()?;
    for id in [String::new(), "../bad".into(), "x".repeat(1025)] {
        assert!(journal.begin_invocation(&id, Role::Hunter).is_err());
        assert!(journal.resource_intent(&id, "owner", json!({})).is_err());
    }
    assert!(journal.add_obligation(" ").is_err());
    assert!(journal.add_obligation(&"x".repeat(65537)).is_err());
    assert!(journal.resource_intent("valid", "", json!({})).is_err());
    assert!(journal
        .resource_intent("valid", "owner", json!({"large":"x".repeat(1024 * 1024)}))
        .is_err());
    journal.begin_invocation("first", Role::Hunter)?;
    assert!(journal.begin_invocation("first", Role::Hunter).is_err());
    assert!(journal
        .finish_invocation("absent", InvocationStatus::Finished)
        .is_err());
    let unsafe_parent = private_parent()?;
    fs::set_permissions(unsafe_parent.path(), fs::Permissions::from_mode(0o777))?;
    assert!(create(unsafe_parent.path(), 2).is_err());
    Ok(())
}

#[test]
fn process_exit_without_destructors_releases_lock_and_preserves_attempts() -> TestResult {
    const CHILD_DIRECTORY: &str = "LADYSHELL_TEST_AUDIT_JOURNAL_CHILD";
    if let Some(parent) = std::env::var_os(CHILD_DIRECTORY) {
        let parent = PathBuf::from(parent);
        let mut journal = create(&parent, 2)?;
        journal.start()?;
        journal.begin_invocation("unfinished", Role::Hunter)?;
        journal.resource_intent("target", "owner", json!({"gateway":"fixture"}))?;
        fs::write(
            parent.join("run-directory"),
            journal.directory().as_os_str().as_encoded_bytes(),
        )?;
        // SAFETY: this isolated fixture exits immediately, intentionally skipping
        // Rust destructors to exercise kernel lock release after process death.
        unsafe { libc::_exit(0) }
    }
    let temp = private_parent()?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process_exit_without_destructors_releases_lock_and_preserves_attempts",
        ])
        .env(CHILD_DIRECTORY, temp.path())
        .output()?;
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    let directory = PathBuf::from(fs::read_to_string(temp.path().join("run-directory"))?);
    let recovered = RunJournal::open(&directory)?;
    assert_eq!(recovered.data().status, RunStatus::Interrupted);
    assert_eq!(recovered.data().invocations.len(), 1);
    assert_eq!(
        recovered.data().invocations[0].status,
        Some(InvocationStatus::Interrupted)
    );
    assert!(!recovered.data().cleanup_verified);
    assert_eq!(recovered.data().resources.len(), 1);
    Ok(())
}

#[test]
fn running_journal_reserves_capacity_for_interruption_record() -> TestResult {
    let temp = private_parent()?;
    let directory = saved(temp.path())?;
    let mut candidate = document(&directory)?;
    let mut obligations: Vec<String> = (0..1021)
        .map(|index| format!("{index:04}-{}", "x".repeat(4091)))
        .collect();
    obligations.push(String::new());
    candidate["open_obligations"] = serde_json::to_value(&obligations)?;
    let remaining = (4 * 1024 * 1024usize)
        .checked_sub(serde_json::to_vec_pretty(&candidate)?.len() + 32)
        .ok_or("fixture already exceeds file limit")?;
    assert!(remaining < 4096);
    candidate["open_obligations"][1021] = json!("y".repeat(remaining));
    fs::write(
        directory.join("audit-journal.json"),
        serde_json::to_vec_pretty(&candidate)?,
    )?;
    let mut journal = RunJournal::open(&directory)?;
    assert!(journal.start().is_err());
    drop(journal);
    let recovered = RunJournal::open(&directory)?;
    assert_eq!(recovered.data().status, RunStatus::Planned);
    Ok(())
}

#[test]
fn terminal_cleanup_can_resolve_only_an_existing_unresolved_intent() -> TestResult {
    for status in [RunStatus::Failed, RunStatus::Blocked, RunStatus::Partial] {
        let temp = private_parent()?;
        let mut journal = create(temp.path(), 7)?;
        journal.start()?;
        journal.resource_intent("target", "owner", json!({"workspace":"default"}))?;
        journal.finish(status.clone())?;
        let directory = journal.directory().to_path_buf();
        drop(journal);
        let mut recovered = RunJournal::open(&directory)?;
        assert!(recovered.resource_created("foreign", "id").is_err());
        assert!(recovered
            .resource_intent("new", "owner", json!({}))
            .is_err());
        recovered.resource_created("target", "observed-id")?;
        assert!(recovered.resource_created("target", "replacement").is_err());
        recovered.resource_deleted("target", "observed-id")?;
        assert!(recovered.data().cleanup_verified);
        assert_eq!(recovered.data().status, status);
    }
    Ok(())
}
