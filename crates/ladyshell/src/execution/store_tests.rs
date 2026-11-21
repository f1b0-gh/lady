use super::*;
use crate::{error::Result, files};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
};

fn catalog() -> Catalog {
    Catalog {
        schema_version: 1,
        environment: EnvironmentPin {
            state: PathBuf::from("/state"),
            state_dev: 1,
            state_ino: 2,
            sandbox_name: "sandbox".into(),
            sandbox_id: "sandbox-a".into(),
            owner: "owner-a".into(),
            policy_hash: "policy".into(),
            desired_hash: "desired".into(),
            image_id: "image-a".into(),
            context: json!({"workspace":"test"}),
            runtime: "a".repeat(64),
            continuous: json!(null),
            source_sha256: "b".repeat(64),
            exclusions: vec!["build".into()],
        },
        tasks: vec![TaskDefinition {
            id: "test".into(),
            argv: vec!["cmd".into(), "".into()],
            timeout_seconds: 5,
            output_limit_bytes: 16,
        }],
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    path: PathBuf,
    b: Binding,
    s: Store,
    i: Invocation,
    a: Admission,
}
fn fixture() -> Result<Fixture> {
    let temp = tempfile::tempdir()?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
    let path = temp.path().join("receiver");
    let c = catalog();
    let i = Invocation {
        scope: "../external/scope".into(),
        id: "/orig/id".into(),
        task: "test".into(),
        definition_sha256: c.definition_digest("test")?,
        intent: json!({"arguments":[1],"evidence":"rev"}),
    };
    let b = Store::create(&path, c)?;
    let s = Store::open(&path, &b.receiver_id)?;
    s.bind_owner(&i.scope, None)?;
    s.advance_claim(&i.scope, None, 1)?;
    Ok(Fixture {
        _temp: temp,
        path,
        b,
        s,
        i,
        a: Admission {
            reference: "r1".into(),
            admit_before: 20,
            owner: None,
            claim: 1,
        },
    })
}
fn owner(e: u64) -> OwnerFence {
    OwnerFence {
        task: "a".repeat(64),
        deployment: "b".repeat(64),
        epoch: e,
        incarnation: "c".repeat(32),
    }
}
#[test]
fn duplicate_after_expiry_retains_original_and_conflicts_compare_all_intent() -> Result<()> {
    let f = fixture()?;
    assert!(f.s.lookup(&f.i)?.is_none());
    let original = f.s.accept(&f.i, &f.a, 10)?;
    assert!(original.is_new);
    let mut a = f.a.clone();
    a.reference = "changed".into();
    a.admit_before = 1000;
    a.claim = 9;
    let duplicate = f.s.accept(&f.i, &a, 500)?;
    assert!(!duplicate.is_new);
    assert_eq!(duplicate.record, original.record);
    let mut conflicting = f.i.clone();
    conflicting.intent["evidence"] = json!("rev2");
    assert!(f.s.accept(&conflicting, &a, 10).is_err());
    assert!(f.s.lookup(&conflicting).is_err());
    let mut other = f.i.clone();
    other.scope = "/different".into();
    f.s.bind_owner(&other.scope, None)?;
    f.s.advance_claim(&other.scope, None, 1)?;
    assert!(f.s.accept(&other, &f.a, 10)?.is_new);
    Ok(())
}
#[test]
fn acceptance_samples_under_lock_at_exclusive_deadline_only_for_new_authorized_work() -> Result<()>
{
    let f = fixture()?;
    let lock = files::open_directory(&f.path)?;
    let called = std::cell::Cell::new(false);
    let mut stale = f.a.clone();
    stale.claim = 2;
    assert!(f
        .s
        .accept_with_clock(&f.i, &stale, || {
            called.set(true);
            Ok(10)
        })
        .is_err());
    assert!(!called.get());

    let error =
        f.s.accept_with_clock(&f.i, &f.a, || {
            assert!(matches!(lock.try_lock(), Err(fs::TryLockError::WouldBlock)));
            called.set(true);
            Ok(f.a.admit_before)
        })
        .err()
        .ok_or_else(|| invalid("Exclusive deadline admitted new work"))?;
    assert!(called.get());
    assert!(error.to_string().contains("admission expired"), "{error}");
    assert!(f.s.lookup(&f.i)?.is_none());

    let mut later = f.a.clone();
    later.admit_before += 10;
    let first = f.s.accept_with_clock(&f.i, &later, || Ok(21))?;
    assert_eq!(first.record.accepted_at, 21);
    let mut replacement = f.a.clone();
    replacement.reference.clear();
    replacement.claim = 0;
    let duplicate = f.s.accept_with_clock(&f.i, &replacement, || {
        Err(invalid("Duplicate tried to sample clock"))
    })?;
    assert!(!duplicate.is_new);
    assert_eq!(duplicate.record, first.record);
    Ok(())
}
#[test]
fn concurrent_openers_reserve_once() -> Result<()> {
    let f = fixture()?;
    let barrier = Arc::new(Barrier::new(4));
    let results = thread::scope(|threads| -> Result<Vec<bool>> {
        let mut all = Vec::new();
        for _ in 0..4 {
            let b = barrier.clone();
            let f = &f;
            all.push(threads.spawn(move || -> Result<bool> {
                let s = Store::open(&f.path, &f.b.receiver_id)?;
                b.wait();
                Ok(s.accept(&f.i, &f.a, 10)?.is_new)
            }));
        }
        all.into_iter()
            .map(|j| j.join().map_err(|_| invalid("worker panicked"))?)
            .collect()
    })?;
    assert_eq!(results.iter().filter(|v| **v).count(), 1);
    Ok(())
}
#[test]
fn owner_and_claim_are_independent_and_dispatch_rechecks_both() -> Result<()> {
    let f = fixture()?;
    let one = owner(1);
    let two = owner(2);
    f.s.bind_owner(&f.i.scope, Some(&one))?;
    assert!(f.s.advance_claim(&f.i.scope, None, 2).is_err());
    let mut a = f.a.clone();
    a.owner = Some(one.clone());
    assert!(f.s.accept(&f.i, &a, 10).is_err());
    f.s.advance_claim(&f.i.scope, Some(&one), 1)?;
    f.s.accept(&f.i, &a, 10)?;
    let key = f.i.key();
    let lease = f.s.acquire_worker(&key)?;
    f.s.advance_claim(&f.i.scope, Some(&one), 2)?;
    assert!(f.s.begin(&lease, 11).is_err());
    assert!(f.s.advance_claim(&f.i.scope, Some(&one), 1).is_err());
    f.s.bind_owner(&f.i.scope, Some(&two))?;
    f.s.advance_claim(&f.i.scope, Some(&two), 1)?;
    assert!(f.s.begin(&lease, 11).is_err());
    assert!(f.s.bind_owner(&f.i.scope, None).is_err());
    assert!(f.s.bind_owner(&f.i.scope, Some(&one)).is_err());
    for changed in [
        OwnerFence {
            incarnation: "d".repeat(32),
            ..two.clone()
        },
        OwnerFence {
            task: "d".repeat(64),
            ..owner(3)
        },
        OwnerFence {
            deployment: "d".repeat(64),
            ..owner(3)
        },
    ] {
        assert!(f.s.bind_owner(&f.i.scope, Some(&changed)).is_err());
    }
    assert_eq!(
        f.s.refuse(&lease, "owner advanced", 12)?.phase,
        Phase::Refused
    );
    assert!(f.s.begin(&lease, 13).is_err());
    assert!(!f.s.accept(&f.i, &a, 30)?.is_new);
    Ok(())
}
#[test]
fn deadlines_are_exclusive_and_a_regressed_clock_does_not_revive_permits() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let lease = f.s.acquire_worker(&f.i.key())?;
    assert!(f.s.begin(&lease, 9).is_err());
    assert!(f.s.begin(&lease, 20).is_err());
    assert!(f.s.begin(&lease, 19).is_err());
    let mut other = f.i.clone();
    other.id = "new".into();
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    assert!(s.accept(&other, &f.a, 19).is_err());
    assert!(s.accept(&other, &f.a, 20).is_err());
    Ok(())
}
#[test]
fn worker_ownership_excludes_recovery_and_foreign_store_then_disappears() -> Result<()> {
    let f = fixture()?;
    let other = fixture()?;
    for x in [&f, &other] {
        x.s.accept(&x.i, &x.a, 10)?;
    }
    let k = f.i.key();
    let lease = f.s.acquire_worker(&k)?;
    assert!(f.s.worker_present(&k)?);
    assert!(f.s.recover(&k, 11).is_err());
    assert!(other.s.begin(&lease, 11).is_err());
    assert_eq!(f.s.begin(&lease, 11)?.phase, Phase::Dispatching);
    assert!(f.s.begin(&lease, 11).is_err());
    drop(lease);
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    assert!(!s.worker_present(&k)?);
    assert_eq!(s.inspect(&k)?.phase, Phase::Dispatching);
    assert_eq!(s.recover(&k, 12)?.phase, Phase::Uncertain);
    assert!(s.acquire_worker(&k).is_err());
    assert!(!s.accept(&f.i, &f.a, 15)?.is_new);
    let other_key = other.i.key();
    assert_eq!(other.s.recover(&other_key, 11)?.phase, Phase::Uncertain);
    assert!(other.s.acquire_worker(&other_key).is_err());
    Ok(())
}
fn capture() -> CapturedOutputs {
    CapturedOutputs {
        stdout: CapturedStream {
            bytes: b"hello".to_vec(),
            truncated: false,
        },
        stderr: CapturedStream::default(),
    }
}
#[test]
fn terminal_receipt_preserves_client_provenance_and_verified_bounded_outputs() -> Result<()> {
    for (result, expected) in [
        (ClientResult::Exit { code: 0 }, Phase::Completed),
        (ClientResult::Exit { code: 5 }, Phase::Uncertain),
        (ClientResult::Signal { signal: 9 }, Phase::Uncertain),
        (ClientResult::Timeout, Phase::Uncertain),
        (ClientResult::OutputLimit, Phase::Uncertain),
        (ClientResult::SpawnFailure, Phase::Uncertain),
        (ClientResult::IoFailure, Phase::Uncertain),
    ] {
        let f = fixture()?;
        let k = f.i.key();
        f.s.accept(&f.i, &f.a, 10)?;
        let lease = f.s.acquire_worker(&k)?;
        f.s.begin(&lease, 11)?;
        f.s.advance_claim(&f.i.scope, None, 2)?;
        let done = f.s.complete(&lease, result.clone(), capture(), 25)?;
        assert_eq!(done.phase, expected);
        let outcome = done
            .outcome
            .as_ref()
            .ok_or_else(|| invalid("missing outcome"))?;
        assert_eq!(outcome.provenance, Provenance::OpenshellClient);
        assert_eq!(outcome.result, result);
        assert!(f
            .s
            .complete(&lease, ClientResult::Exit { code: 0 }, capture(), 26)
            .is_err());
        let s = Store::open(&f.path, &f.b.receiver_id)?;
        assert_eq!(s.inspect(&k)?, done);
        assert_eq!(s.read_output(&k, Stream::Stdout, 1, 3)?, b"ell");
        assert!(s.read_output(&k, Stream::Stdout, 6, 1).is_err());
        let output = f.path.join(k.digest()?).join("stdout");
        fs::write(&output, b"other")?;
        assert!(s.inspect(&k).is_err());
        assert!(s.accept(&f.i, &f.a, 100).is_err());
    }
    Ok(())
}
#[test]
fn missing_intent_and_hostile_replacements_are_never_recreated() -> Result<()> {
    let f = fixture()?;
    let k = f.i.key();
    f.s.accept(&f.i, &f.a, 10)?;
    let file = f.path.join(k.digest()?).join("intent.json");
    let bytes = fs::read(&file)?;
    fs::remove_file(&file)?;
    assert!(f.s.accept(&f.i, &f.a, 11).is_err());
    let outside = f._temp.path().join("outside");
    fs::write(&outside, &bytes)?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    symlink(&outside, &file)?;
    assert!(f.s.inspect(&k).is_err());
    fs::remove_file(&file)?;
    fs::hard_link(&outside, &file)?;
    assert!(f.s.inspect(&k).is_err());
    assert_eq!(fs::read(outside)?, bytes);
    Ok(())
}
#[test]
fn original_parent_and_receiver_are_checked_before_every_effect() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let lease = f.s.acquire_worker(&f.i.key())?;
    let renamed = f._temp.path().with_extension("moved");
    fs::rename(f._temp.path(), &renamed)?;
    // Restore the original parent before the tempdir is dropped.
    let result = f.s.begin(&lease, 11);
    fs::rename(&renamed, f._temp.path())?;
    assert!(result.is_err());
    assert_eq!(f.s.inspect(&f.i.key())?.phase, Phase::Accepted);
    assert!(Store::open(&f.path, &files::hash(b"wrong receiver")).is_err());
    assert!(Store::create(&f.path, catalog()).is_err());
    Ok(())
}
#[test]
fn definitions_bind_all_inputs_and_refuse_over_budget_catalogs() -> Result<()> {
    let c = catalog();
    let base = c.definition_digest("test")?;
    let mut changed = c.clone();
    changed.environment.exclusions.push("output".into());
    assert_ne!(changed.definition_digest("test")?, base);
    let mut changed = c.clone();
    changed.tasks[0].argv.pop();
    assert_ne!(changed.definition_digest("test")?, base);
    for args in [
        vec![],
        vec!["".into()],
        vec!["x".repeat(4097)],
        vec!["a".into(); 129],
        vec!["x".repeat(4096); 9],
        vec!["a\0b".into()],
    ] {
        let mut bad = c.clone();
        bad.tasks[0].argv = args;
        assert!(bad.definition_digest("test").is_err());
    }
    let mut bad = c;
    bad.tasks[0].output_limit_bytes = 1048577;
    assert!(bad.definition_digest("test").is_err());
    Ok(())
}
#[test]
fn interrupted_reservation_and_missing_or_duplicate_metadata_fail_closed() -> Result<()> {
    let f = fixture()?;
    let dir = f.path.join(f.i.key().digest()?);
    fs::create_dir(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    assert!(f.s.accept(&f.i, &f.a, 10).is_err());
    assert!(f.s.lookup(&f.i).is_err());
    assert!(!dir.join("intent.json").exists());
    let f = fixture()?;
    fs::write(
        f.path.join("ledger.json"),
        br#"{"schema_version":1,"schema_version":1}"#,
    )?;
    assert!(Store::open(&f.path, &f.b.receiver_id).is_err());
    assert!(f.s.accept(&f.i, &f.a, 10).is_err());
    fs::remove_file(f.path.join("ledger.json"))?;
    assert!(Store::open(&f.path, &f.b.receiver_id).is_err());
    Ok(())
}
#[test]
fn lost_ownership_on_partial_output_publication_never_authorizes_replay() -> Result<()> {
    let f = fixture()?;
    let k = f.i.key();
    f.s.accept(&f.i, &f.a, 10)?;
    let lease = f.s.acquire_worker(&k)?;
    f.s.begin(&lease, 11)?;
    // A previous writer persisted one stream, then stopped before publishing its receipt.
    let out = f.path.join(k.digest()?).join("stdout");
    fs::write(&out, b"old")?;
    fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;
    assert!(f
        .s
        .complete(&lease, ClientResult::Exit { code: 0 }, capture(), 12)
        .is_err());
    assert!(f.s.advance_claim(&f.i.scope, None, 2).is_err());
    drop(lease);
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    assert_eq!(s.recover(&k, 15)?.phase, Phase::Uncertain);
    assert_eq!(fs::read(out)?, b"old");
    assert!(!s.accept(&f.i, &f.a, 16)?.is_new);
    Ok(())
}
#[test]
fn duplicate_object_order_is_irrelevant_but_array_order_is_intent() -> Result<()> {
    let f = fixture()?;
    let mut i = f.i.clone();
    i.intent = serde_json::from_str(r#"{"z":{"b":1,"a":2},"x":[1,2]}"#)?;
    let original = f.s.accept(&i, &f.a, 10)?;
    i.intent = serde_json::from_str(r#"{"x":[1,2],"z":{"a":2,"b":1}}"#)?;
    assert_eq!(f.s.lookup(&i)?, Some(original.record));
    i.intent["x"] = json!([2, 1]);
    assert!(f.s.lookup(&i).is_err());
    Ok(())
}
#[test]
fn malformed_ids_budget_and_excess_capture_refuse_before_effect() -> Result<()> {
    let f = fixture()?;
    for (scope, id, intent) in [
        ("x".repeat(257), "id".into(), json!(null)),
        ("scope".into(), "".into(), json!(1)),
        ("scope".into(), "id".into(), json!("x".repeat(16384))),
    ] {
        let i = Invocation {
            scope,
            id,
            intent,
            ..f.i.clone()
        };
        assert!(f.s.accept(&i, &f.a, 10).is_err());
    }
    let a = Admission {
        reference: "r".repeat(1025),
        ..f.a.clone()
    };
    assert!(f.s.accept(&f.i, &a, 10).is_err());
    f.s.accept(&f.i, &f.a, 10)?;
    let lease = f.s.acquire_worker(&f.i.key())?;
    f.s.begin(&lease, 11)?;
    let mut bad = capture();
    bad.stderr.bytes = vec![0; 17];
    assert!(f
        .s
        .complete(&lease, ClientResult::Exit { code: 0 }, bad, 12)
        .is_err());
    assert!(f
        .s
        .complete(&lease, ClientResult::Exit { code: 0 }, capture(), 12)
        .is_ok());
    Ok(())
}
#[test]
fn storage_capacity_reserves_output_for_already_accepted_workers() -> Result<()> {
    let f = fixture()?;
    let path = f._temp.path().join("large");
    let mut c = catalog();
    c.tasks[0].output_limit_bytes = 1048576;
    let def = c.definition_digest("test")?;
    let b = Store::create(&path, c)?;
    let s = Store::open(&path, &b.receiver_id)?;
    s.bind_owner(&f.i.scope, None)?;
    s.advance_claim(&f.i.scope, None, 1)?;
    let mut accepted = 0;
    for n in 0..17 {
        let i = Invocation {
            id: n.to_string(),
            definition_sha256: def.clone(),
            ..f.i.clone()
        };
        if s.accept(&i, &f.a, 10).is_err() {
            break;
        }
        accepted += 1;
    }
    assert!((1..16).contains(&accepted));
    let key = Key {
        scope: f.i.scope.clone(),
        id: "0".into(),
    };
    let lease = s.acquire_worker(&key)?;
    s.begin(&lease, 11)?;
    let full = CapturedStream {
        bytes: vec![42; 1048576],
        truncated: true,
    };
    let result = s.complete(
        &lease,
        ClientResult::OutputLimit,
        CapturedOutputs {
            stdout: full.clone(),
            stderr: full,
        },
        12,
    )?;
    let evidence = result
        .outcome
        .ok_or_else(|| invalid("missing output-limit receipt"))?;
    assert!(evidence.stdout.truncated);
    assert_eq!(evidence.stdout.length, 1048576);
    assert_eq!(s.read_output(&key, Stream::Stderr, 1048575, 1)?, vec![42]);
    Ok(())
}
#[test]
fn direct_json_callers_cannot_bypass_retention_depth_or_input_limits() -> Result<()> {
    let f = fixture()?;
    let mut intent = json!(1);
    for _ in 0..100 {
        intent = serde_json::Value::Array(vec![intent]);
    }
    let i = Invocation {
        intent,
        ..f.i.clone()
    };
    assert!(f.s.accept(&i, &f.a, 10).is_err());
    assert!(f.s.lookup(&f.i)?.is_none());
    let mut c = catalog();
    c.tasks = vec![c.tasks[0].clone(); 65];
    assert!(c.definition_digest("test").is_err());
    Ok(())
}
#[test]
fn reconciliation_preserves_terminal_uncertainty_and_bounds_operator_evidence() -> Result<()> {
    let f = fixture()?;
    let k = f.i.key();
    f.s.accept(&f.i, &f.a, 10)?;
    assert!(f
        .s
        .record_reconciliation(&k, "stopped", &json!({}), 11)
        .is_err());
    let uncertain = f.s.recover(&k, 12)?;
    assert!(f
        .s
        .record_reconciliation(&k, "stopped", &json!({}), 11)
        .is_err());
    assert!(f
        .s
        .record_reconciliation(&k, "stopped", &json!("x".repeat(8192)), 13)
        .is_err());
    assert!(f
        .s
        .record_reconciliation(&k, &"x".repeat(1025), &json!({}), 13)
        .is_err());
    for n in 0..16 {
        let r = f.s.record_reconciliation(
            &k,
            "operator verified stop",
            &json!({"observed":n}),
            13 + n,
        )?;
        assert_eq!(r.phase, Phase::Uncertain);
        assert_eq!(r.finished_at, uncertain.finished_at);
        assert_eq!(r.reconciliations.len(), (n + 1) as usize);
        assert_eq!(r.reconciliations[0].evidence, json!({"observed":0}));
    }
    assert!(f
        .s
        .record_reconciliation(&k, "again", &json!({}), 30)
        .is_err());
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    let record = s.accept(&f.i, &f.a, 50)?.record;
    assert_eq!(record.reconciliations.len(), 16);
    assert_eq!(record.reconciliations[15].at, 28);
    assert!(s.acquire_worker(&k).is_err());
    Ok(())
}
#[test]
fn epoch_zero_acknowledges_initialization_and_never_permits_effects() -> Result<()> {
    let f = fixture()?;
    let mut i = f.i.clone();
    i.scope = "initial".into();
    f.s.bind_owner(&i.scope, None)?;
    f.s.advance_claim(&i.scope, None, 0)?;
    assert!(f
        .s
        .accept(
            &i,
            &Admission {
                claim: 0,
                ..f.a.clone()
            },
            10
        )
        .is_err());
    f.s.advance_claim(&i.scope, None, 1)?;
    assert!(f.s.advance_claim(&i.scope, None, 0).is_err());
    assert!(f.s.accept(&i, &f.a, 10)?.is_new);
    Ok(())
}
#[test]
fn reopened_writer_cannot_use_a_lease_from_another_handle() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let w = f.s.acquire_worker(&f.i.key())?;
    let reopened = Store::open(&f.path, &f.b.receiver_id)?;
    assert!(reopened.begin(&w, 11).is_err());
    assert_eq!(f.s.begin(&w, 11)?.phase, Phase::Dispatching);
    Ok(())
}
#[test]
fn original_receipt_survives_a_crash_between_receipt_and_index_fsync() -> Result<()> {
    let f = fixture()?;
    let k = f.i.key();
    f.s.accept(&f.i, &f.a, 10)?;
    let w = f.s.acquire_worker(&k)?;
    f.s.begin(&w, 11)?;
    let marker = f.path.join("ledger.json");
    let dispatch_index = fs::read(&marker)?;
    let terminal =
        f.s.complete(&w, ClientResult::Exit { code: 0 }, capture(), 12)?;
    drop(w);
    // Reproduce the persisted prefix before the final index replacement.
    fs::write(marker, dispatch_index)?;
    let reopened = Store::open(&f.path, &f.b.receiver_id)?;
    assert_eq!(reopened.inspect(&k)?, terminal);
    assert!(!reopened.accept(&f.i, &f.a, 13)?.is_new);
    assert!(reopened.recover(&k, 13).is_err());
    assert!(reopened.acquire_worker(&k).is_err());
    Ok(())
}
#[test]
fn dispatch_samples_the_clock_only_after_the_final_fence_check() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let w = f.s.acquire_worker(&f.i.key())?;
    f.s.advance_claim(&f.i.scope, None, 2)?;
    let called = std::cell::Cell::new(false);
    assert!(f
        .s
        .begin_with_clock(&w, || {
            called.set(true);
            Ok(11)
        })
        .is_err());
    assert!(!called.get());
    Ok(())
}
#[test]
fn interrupted_ledger_replacement_allows_independent_admission_and_fence_updates() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let pending = f.path.join(".ledger.json.pending");
    fs::write(&pending, b"interrupted ledger write")?;
    fs::set_permissions(&pending, fs::Permissions::from_mode(0o600))?;
    let reopened = Store::open(&f.path, &f.b.receiver_id)?;
    let unrelated = Invocation {
        id: "another".into(),
        ..f.i.clone()
    };
    assert!(reopened.accept(&unrelated, &f.a, 10)?.is_new);
    assert!(!reopened.accept(&f.i, &f.a, 10)?.is_new);
    reopened.advance_claim(&f.i.scope, None, 2)?;
    let another = Store::open(&f.path, &f.b.receiver_id)?;
    let worker = another.acquire_worker(&unrelated.key())?;
    assert!(another.begin(&worker, 11).is_err());
    assert_eq!(another.inspect(&f.i.key())?.phase, Phase::Accepted);
    Ok(())
}
#[test]
fn truncated_capture_cannot_be_a_successful_completion() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let w = f.s.acquire_worker(&f.i.key())?;
    f.s.begin(&w, 11)?;
    let mut c = capture();
    c.stdout.truncated = true;
    let done = f.s.complete(&w, ClientResult::Exit { code: 0 }, c, 12)?;
    assert_eq!(done.phase, Phase::Uncertain);
    assert_eq!(
        done.outcome
            .ok_or_else(|| invalid("Missing partial capture"))?
            .result,
        ClientResult::Exit { code: 0 }
    );
    Ok(())
}
#[test]
fn process_exit_releases_ownership_without_reopening_dispatch() -> Result<()> {
    const PATH_ENV: &str = "LADYSHELL_TEST_DISPATCH_RECEIVER";
    const BINDING_ENV: &str = "LADYSHELL_TEST_DISPATCH_BINDING";
    if let Some(path) = std::env::var_os(PATH_ENV) {
        let binding = std::env::var(BINDING_ENV).map_err(|_| invalid("Missing test binding"))?;
        let s = Store::open(&PathBuf::from(path), &binding)?;
        let k = Key {
            scope: "../external/scope".into(),
            id: "/orig/id".into(),
        };
        let w = s.acquire_worker(&k)?;
        s.begin(&w, 11)?;
        std::process::exit(0);
    }
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let result = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "execution::store_tests::process_exit_releases_ownership_without_reopening_dispatch",
        ])
        .env(PATH_ENV, &f.path)
        .env(BINDING_ENV, &f.b.receiver_id)
        .output()?;
    assert!(result.status.success());
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    let k = f.i.key();
    assert_eq!(s.inspect(&k)?.phase, Phase::Dispatching);
    assert!(!s.worker_present(&k)?);
    assert!(s.acquire_worker(&k).is_err());
    assert_eq!(s.recover(&k, 12)?.phase, Phase::Uncertain);
    assert!(!s.accept(&f.i, &f.a, 15)?.is_new);
    Ok(())
}
#[test]
fn output_evidence_without_a_dispatch_marker_blocks_a_new_worker() -> Result<()> {
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    let k = f.i.key();
    let dir = f.path.join(k.digest()?);
    fs::write(dir.join("stderr"), b"observed previous client")?;
    fs::set_permissions(dir.join("stderr"), fs::Permissions::from_mode(0o600))?;
    assert!(f.s.acquire_worker(&k).is_err());
    assert!(f.s.accept(&f.i, &f.a, 11).is_err());
    Ok(())
}

thread_local! {
    static FAIL_OBSERVATION: std::cell::Cell<Option<(u64,u64)>> = const { std::cell::Cell::new(None) };
}
fn fail_observation_on(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path)?;
    FAIL_OBSERVATION.set(Some((m.dev(), m.ino())));
    Ok(())
}
pub(super) fn observation_fault(dir: &fs::File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = dir.metadata()?;
    if FAIL_OBSERVATION.get() == Some((m.dev(), m.ino())) {
        FAIL_OBSERVATION.set(None);
        return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
    }
    Ok(())
}
#[test]
fn unindexed_transitions_require_a_successful_durability_barrier() -> Result<()> {
    for phase in [Phase::Dispatching, Phase::Refused, Phase::Uncertain] {
        let f = fixture()?;
        let k = f.i.key();
        f.s.accept(&f.i, &f.a, 10)?;
        let index = f.path.join("ledger.json");
        let old = fs::read(&index)?;
        if phase == Phase::Uncertain {
            f.s.recover(&k, 10)?;
        } else {
            let worker = f.s.acquire_worker(&k)?;
            if phase == Phase::Dispatching {
                f.s.begin(&worker, 10)?;
            } else {
                f.s.refuse(&worker, "preflight refused", 10)?;
            }
        }
        fs::write(&index, old)?;
        let reopened = Store::open(&f.path, &f.b.receiver_id)?;
        let directory = f.path.join(k.digest()?);
        fail_observation_on(&directory)?;
        assert!(reopened.inspect(&k).is_err());
        fail_observation_on(&directory)?;
        assert!(Store::open(&f.path, &f.b.receiver_id)?
            .accept(&f.i, &f.a, 10)
            .is_err());
        assert_eq!(reopened.inspect(&k)?.phase, phase);
        assert!(reopened.acquire_worker(&k).is_err());
    }
    Ok(())
}
#[test]
fn observing_a_ledger_including_idempotent_fences_requires_its_directory_barrier() -> Result<()> {
    let f = fixture()?;
    fail_observation_on(&f.path)?;
    assert!(Store::open(&f.path, &f.b.receiver_id).is_err());
    fail_observation_on(&f.path)?;
    assert!(f.s.advance_claim(&f.i.scope, None, 1).is_err());
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    fail_observation_on(&f.path)?;
    assert!(s.bind_owner(&f.i.scope, None).is_err());
    Ok(())
}
#[test]
fn interrupted_worker_receipt_and_interrupted_recovery_allow_explicit_recovery() -> Result<()> {
    let f = fixture()?;
    let k = f.i.key();
    f.s.accept(&f.i, &f.a, 10)?;
    let worker = f.s.acquire_worker(&k)?;
    f.s.begin(&worker, 11)?;
    drop(worker);
    let dir = f.path.join(k.digest()?);
    for (name, bytes) in [
        (
            ".receipt.json.pending",
            b"partial original client receipt".as_slice(),
        ),
        (".recovery.pending", b"interrupted recovery write"),
    ] {
        fs::write(dir.join(name), bytes)?;
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600))?;
    }
    let reopened = Store::open(&f.path, &f.b.receiver_id)?;
    assert_eq!(reopened.recover(&k, 14)?.phase, Phase::Uncertain);
    assert_eq!(
        fs::read(dir.join(".receipt.json.pending"))?,
        b"partial original client receipt"
    );
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    assert_eq!(s.inspect(&k)?.phase, Phase::Uncertain);
    assert!(!s.accept(&f.i, &f.a, 15)?.is_new);
    assert!(s.acquire_worker(&k).is_err());
    Ok(())
}
#[test]
fn restrictive_subprocess_umask_preserves_private_published_files_and_reopen() -> Result<()> {
    const ENV: &str = "LADYSHELL_TEST_RESTRICTIVE_UMASK";
    if let Some(p) = std::env::var_os(ENV) {
        let path = PathBuf::from(p);
        let pin = std::env::var("LADYSHELL_TEST_UMASK_BINDING")
            .map_err(|_| invalid("Missing umask test binding"))?;
        let s = Store::open(&path, &pin)?;
        // SAFETY: umask is process-wide. Only this dedicated test process changes it.
        unsafe { libc::umask(0o277) };
        s.advance_claim("administration", None, 1)?;
        let k = Key {
            scope: "../external/scope".into(),
            id: "/orig/id".into(),
        };
        let worker = s.acquire_worker(&k)?;
        s.begin(&worker, 10)?;
        s.complete(&worker, ClientResult::Exit { code: 0 }, capture(), 11)?;
        assert_eq!(
            Store::open(&path, &pin)?.inspect(&k)?.phase,
            Phase::Completed
        );
        let dir = path.join(k.digest()?);
        for p in [
            path.join("ledger.json"),
            dir.join("dispatch.json"),
            dir.join("receipt.json"),
            dir.join("stdout"),
            dir.join("stderr"),
        ] {
            assert_eq!(fs::metadata(p)?.permissions().mode() & 0o7777, 0o600);
        }
        let b = Store::create(&path.with_file_name("restrictive-create"), catalog())?;
        Store::open(&path.with_file_name("restrictive-create"), &b.receiver_id)?;
        return Ok(());
    }
    let f = fixture()?;
    f.s.accept(&f.i, &f.a, 10)?;
    f.s.bind_owner("administration", None)?;
    let o=std::process::Command::new(std::env::current_exe()?).args(["--exact","execution::store_tests::restrictive_subprocess_umask_preserves_private_published_files_and_reopen","--nocapture"]).env(ENV,&f.path).env("LADYSHELL_TEST_UMASK_BINDING",&f.b.receiver_id).output()?;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    Ok(())
}
#[test]
fn reused_ledger_staging_rejects_links_and_preserves_their_targets() -> Result<()> {
    let f = fixture()?;
    let stage = f.path.join(".ledger.json.pending");
    let outside = f._temp.path().join("private-data");
    fs::write(&outside, b"unrelated")?;
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
    for hard in [false, true] {
        if hard {
            fs::hard_link(&outside, &stage)?;
        } else {
            symlink(&outside, &stage)?;
        }
        let s = Store::open(&f.path, &f.b.receiver_id)?;
        assert!(s.advance_claim(&f.i.scope, None, 2).is_err());
        assert_eq!(fs::read(&outside)?, b"unrelated");
        assert!(stage.exists());
        fs::remove_file(&stage)?;
    }
    Ok(())
}

#[test]
fn interrupted_first_admission_remains_reserved_and_does_not_block_other_keys() -> Result<()> {
    let f = fixture()?;
    let before = fs::read(f.path.join("ledger.json"))?;
    f.s.accept(&f.i, &f.a, 10)?;
    fs::write(f.path.join("ledger.json"), before)?;
    let stage = f.path.join(".ledger.json.pending");
    fs::write(&stage, b"interrupted acceptance commit")?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o600))?;
    let s = Store::open(&f.path, &f.b.receiver_id)?;
    assert!(s.lookup(&f.i).is_err());
    assert!(s.acquire_worker(&f.i.key()).is_err());
    let other = Invocation {
        id: "another".into(),
        ..f.i.clone()
    };
    assert!(s.accept(&other, &f.a, 10)?.is_new);
    assert!(s.accept(&f.i, &f.a, 11).is_err());
    let orphan = f.path.join(f.i.key().digest()?);
    fs::write(orphan.join("stdout"), b"unexpected data")?;
    let third = Invocation {
        id: "third".into(),
        ..f.i.clone()
    };
    assert!(s.accept(&third, &f.a, 11).is_err());
    Ok(())
}

#[test]
fn orphan_reservations_and_unpublished_intents_consume_receiver_capacity() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    for with_bytes in [false, true] {
        let f = fixture()?;
        let count = if with_bytes { 60 } else { 1024 };
        for n in 0..count {
            let dir = f.path.join(format!("{n:064x}"));
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
            if with_bytes {
                let path = dir.join(".intent.json.pending");
                let file = fs::File::create(path)?;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.set_len(512 * 1024)?;
            }
        }
        assert!(f.s.accept(&f.i, &f.a, 10).is_err());
        assert!(!f.path.join(f.i.key().digest()?).exists());
    }
    Ok(())
}
#[test]
fn oversized_or_linked_orphan_staging_blocks_unrelated_admission() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let f = fixture()?;
    let dir = f.path.join("e".repeat(64));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let path = dir.join(".intent.json.pending");
    let file = fs::File::create(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.set_len(512 * 1024 + 1)?;
    assert!(f.s.accept(&f.i, &f.a, 10).is_err());
    file.set_len(1)?;
    fs::hard_link(&path, f._temp.path().join("shared"))?;
    assert!(f.s.accept(&f.i, &f.a, 10).is_err());
    Ok(())
}

#[test]
fn interrupted_mkdir_preserves_keys_without_blocking_unrelated_growth() -> Result<()> {
    for mode in [0o500, 0o400, 0o100, 0o000] {
        for reconcile_first in [false, true] {
            let f = fixture()?;
            let accepted = f.s.accept(&f.i, &f.a, 10)?.record;
            let known = f.i.key();
            assert_eq!(accepted.phase, Phase::Accepted);
            f.s.recover(&known, 11)?;
            let unavailable = Invocation {
                id: "interrupted mkdir".into(),
                ..f.i.clone()
            };
            let key = unavailable.key();
            let dir = f.path.join(key.digest()?);
            fs::create_dir(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(mode))?;
            let reopened = Store::open(&f.path, &f.b.receiver_id)?;
            assert!(reopened.lookup(&unavailable).is_err());
            assert!(reopened.inspect(&key).is_err());
            assert!(reopened.worker_present(&key).is_err());
            assert!(reopened.acquire_worker(&key).is_err());
            assert!(reopened.accept(&unavailable, &f.a, 12).is_err());
            assert_eq!(reopened.inspect(&known)?.phase, Phase::Uncertain);
            assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o7777, mode);
            let another = Invocation {
                id: "independent".into(),
                ..f.i.clone()
            };
            if reconcile_first {
                assert_eq!(
                    reopened
                        .record_reconciliation(&known, "stopped", &json!({}), 12)?
                        .reconciliations
                        .len(),
                    1
                );
                assert!(reopened.accept(&another, &f.a, 12)?.is_new);
            } else {
                assert!(reopened.accept(&another, &f.a, 12)?.is_new);
                assert_eq!(
                    reopened
                        .record_reconciliation(&known, "stopped", &json!({}), 12)?
                        .reconciliations
                        .len(),
                    1
                );
            }
            assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o7777, 0o700);
            assert!(fs::read_dir(&dir)?.next().is_none());
            assert!(reopened.accept(&unavailable, &f.a, 13).is_err());
            assert!(reopened.acquire_worker(&key).is_err());
        }
    }
    Ok(())
}

#[test]
fn masked_unindexed_directories_still_require_private_ownership_and_bounded_contents() -> Result<()>
{
    let f = fixture()?;
    let dir = f.path.join("c".repeat(64));
    fs::create_dir(&dir)?;
    let evidence = dir.join("unexpected");
    fs::write(&evidence, b"preserve")?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000))?;
    for _ in 0..2 {
        assert!(f.s.accept(&f.i, &f.a, 10).is_err());
    }
    assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o7777, 0o700);
    assert_eq!(fs::read(&evidence)?, b"preserve");
    fs::remove_file(&evidence)?;
    for mode in [0o750, 0o701, 0o1700] {
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode))?;
        assert!(f.s.accept(&f.i, &f.a, 10).is_err());
        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o7777, mode);
    }
    Ok(())
}
