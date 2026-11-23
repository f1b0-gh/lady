use ladyshell::{
    environment_lock::atomic_json,
    error::Result,
    state::{self, Selection, StateLock},
};
use serde_json::{json, Value};
use std::os::unix::fs::MetadataExt;

fn root() -> Result<tempfile::TempDir> {
    let parent = std::path::Path::new("/tmp/lady");
    match std::fs::create_dir(parent) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), std::fs::metadata(".")?.uid());
    Ok(tempfile::Builder::new()
        .prefix("lifecycle-selection-")
        .tempdir_in(parent)?)
}
fn current() -> Value {
    json!({"schema_version":2,"sandbox_name":"original","sandbox_id":"id",
        "policy_hash":"policy","owner":"owner","desired_hash":"desired",
        "image_id":"image","project_snapshot":"snapshot","build_dir":"build",
        "codex_binary":"binary","context":{"gateway":"g","workspace":"w"}})
}

#[test]
fn selection_binds_original_directory_and_exact_record() -> Result<()> {
    let root = root()?;
    let original = root.path().join("state");
    let lock = StateLock::acquire(&original)?;
    let record = json!({"plan":"reviewed"});
    let selected = Selection::capture(&lock, &record)?;
    selected.verify(&lock, &record)?;
    assert!(selected.verify(&lock, &json!({"plan":"changed"})).is_err());
    drop(lock);
    std::fs::rename(&original, root.path().join("retained"))?;
    let replacement = StateLock::acquire(&original)?;
    assert!(selected.verify(&replacement, &record).is_err());
    Ok(())
}

#[test]
fn environment_selection_survives_export_progress_but_rejects_generation_changes() -> Result<()> {
    let root = root()?;
    let state = root.path().join("state");
    let lock = StateLock::acquire(&state)?;
    let current = current();
    atomic_json(&state.join("state.json"), &current)?;
    drop(lock);
    let selected = state::select_generation(&state)?;
    let lock = StateLock::acquire(&state)?;
    let mut exported = current.clone();
    exported["last_sync"] = json!("/retained/export");
    selected.verify_generation(&lock, &exported)?;
    for field in [
        "owner",
        "policy_hash",
        "sandbox_id",
        "desired_hash",
        "continuous",
        "storage",
    ] {
        let mut changed = exported.clone();
        changed[field] = json!("replacement");
        assert!(
            selected.verify_generation(&lock, &changed).is_err(),
            "accepted {field}"
        );
    }
    Ok(())
}

#[test]
fn changed_generation_refuses_destruction_before_backend_or_journal() -> Result<()> {
    let root = root()?;
    let state = root.path().join("state");
    let lock = StateLock::acquire(&state)?;
    atomic_json(&state.join("state.json"), &current())?;
    drop(lock);
    let selected = state::select_generation(&state)?;
    let mut changed = current();
    changed["owner"] = json!("replacement");
    atomic_json(&state.join("state.json"), &changed)?;
    let error = ladyshell::destroy::run_pinned(
        &ladyshell::request::Destroy {
            state: state.clone(),
            discard_work: false,
        },
        &selected,
    )
    .err()
    .ok_or_else(|| ladyshell::error::Error::InvalidInput {
        message: "changed generation accepted".into(),
    })?;
    assert!(error.to_string().contains("selection"), "{error}");
    assert!(!state.join("destroy.json").exists());
    assert!(!state.join("broker-destroy.json").exists());
    Ok(())
}

#[test]
fn changed_cancellation_record_refuses_before_backend_or_journal() -> Result<()> {
    let root = root()?;
    let state = root.path().join("state");
    let lock = StateLock::acquire(&state)?;
    let desired = json!({"context":{"gateway":"g","workspace":"w"},"evaluated":{"config":{"image":{"profile":"openshell-worker-v1"},"storage":{"control":{"bytes":65536,"inodes":32},"artifacts":{"bytes":65536,"inodes":32},"incoming":{"bytes":65536,"inodes":32}}}}});
    let mut operation = json!({"schema_version":2,"desired_hash":ladyshell::plan::digest(&desired)?,"desired_inputs":desired,"state_before":null,"observed_before":{},"phase":"planned","owner":"a".repeat(32),"sandbox_name":"er-aaaaaaaaaaaa","restore_only":false,"build":null,"result":null});
    atomic_json(&state.join("operation.json"), &operation)?;
    drop(lock);
    let selected = ladyshell::destroy::select_cancellation(&state)?;
    operation["owner"] = json!("b".repeat(32));
    operation["sandbox_name"] = json!("er-bbbbbbbbbbbb");
    atomic_json(&state.join("operation.json"), &operation)?;
    let error = ladyshell::destroy::cancel_broker_pinned(
        &ladyshell::request::Existing {
            state: state.clone(),
        },
        &selected,
    )
    .err()
    .ok_or_else(|| ladyshell::error::Error::InvalidInput {
        message: "changed cancellation accepted".into(),
    })?;
    assert!(error.to_string().contains("selection"), "{error}");
    assert!(!state.join("broker-cancel.json").exists());
    Ok(())
}
