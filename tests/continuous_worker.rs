use ladyshell::{
    continuous::{
        model::*,
        worker::{self, WorkerStep},
    },
    plan, snapshot,
};
use serde_json::json;
use std::{fs, path::Path};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn offer(old: &Path, new: &Path) -> Result<(RefreshOffer, serde_json::Value)> {
    let before = plan::digest(&snapshot::inventory(old)?)?;
    let mut state = Session::new(
        "task".into(),
        "sandbox".into(),
        "owner".into(),
        "before".into(),
        "a".repeat(64),
        before.clone(),
    )?;
    state.begin_checkpoint("checkpoint", 0)?;
    state.finish_checkpoint("checkpoint", "after", before)?;
    let context = json!({"objective":"Continue after upstream changes","reported_by_agent":"Untrusted task explanation"});
    Ok((
        RefreshOffer::new(
            &state,
            "refresh",
            plan::digest(&snapshot::inventory(new)?)?,
            plan::digest(&context)?,
        )?,
        context,
    ))
}

#[test]
fn source_swap_preserves_old_tree_deletes_files_and_recovers_each_boundary() -> Result {
    use std::os::unix::fs::PermissionsExt;
    for fail_at in [
        None,
        Some(WorkerStep::Staged),
        Some(WorkerStep::BackupCopied),
        Some(WorkerStep::SourceFileRemoved),
        Some(WorkerStep::ProjectRemoved),
        Some(WorkerStep::Installed),
        Some(WorkerStep::ContextWritten),
        Some(WorkerStep::MarkerWritten),
    ] {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("project");
        let source = temp.path().join("source");
        let control = temp.path().join("control");
        fs::create_dir(&root)?;
        fs::create_dir(&source)?;
        fs::write(root.join("remove"), "retained original")?;
        fs::write(root.join("file-to-dir"), "old file")?;
        fs::create_dir_all(root.join("node_modules/nested/empty"))?;
        fs::write(
            root.join("node_modules/nested/generated"),
            "retained generated data",
        )?;
        fs::create_dir(source.join("file-to-dir"))?;
        fs::write(source.join("file-to-dir/new"), "new source")?;
        fs::write(source.join("script"), "#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(source.join("script"), fs::Permissions::from_mode(0o755))?;
        let (offer, context) = offer(&root, &source)?;
        let bundle = worker::bundle(&offer, "after", &context, &source)?;
        let first = worker::apply_with(&root, &control, &bundle, |step| {
            if Some(step) == fail_at {
                return Err(ladyshell::error::Error::InvalidInput {
                    message: "injected interruption".into(),
                });
            }
            Ok(())
        });
        assert_eq!(first.is_ok(), fail_at.is_none(), "{fail_at:?}");
        let ack = worker::apply(&root, &control, &bundle)?;
        assert_eq!(ack, Acknowledgement::for_offer(&offer, "after"));
        assert_eq!(snapshot::inventory(&root)?, snapshot::inventory(&source)?);
        assert_eq!(
            fs::read(control.join("refresh/previous/remove"))?,
            b"retained original"
        );
        assert_eq!(
            fs::read(control.join("refresh/previous/node_modules/nested/generated"))?,
            b"retained generated data"
        );
        assert!(!root.join("node_modules").exists());
        assert_eq!(worker::inspect(&root, &control, &offer)?, Some(ack.clone()));
        assert_eq!(worker::apply(&root, &control, &bundle)?, ack);
        fs::write(root.join("unfinished"), "agent continuation")?;
        assert!(worker::apply(&root, &control, &bundle).is_err());
        assert_eq!(fs::read(root.join("unfinished"))?, b"agent continuation");
    }
    Ok(())
}

#[test]
fn noop_preserves_generated_dependencies_and_reused_attempt_cannot_change_request() -> Result {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("project");
    let source = temp.path().join("source");
    let control = temp.path().join("control");
    fs::create_dir(&root)?;
    fs::create_dir(&source)?;
    fs::write(root.join("code"), "same")?;
    fs::write(source.join("code"), "same")?;
    fs::create_dir(root.join("node_modules"))?;
    fs::write(root.join("node_modules/installed"), "dependency")?;
    let (offer, context) = offer(&root, &source)?;
    let bundle = worker::bundle(&offer, "after", &context, &source)?;
    worker::apply(&root, &control, &bundle)?;
    assert_eq!(
        fs::read(root.join("node_modules/installed"))?,
        b"dependency"
    );
    let mut different = offer.clone();
    different.context = "f".repeat(64);
    assert!(worker::bundle(&different, "after", &context, &source).is_err());
    different = offer.clone();
    different.owner = "other".into();
    let another = worker::bundle(&different, "after", &context, &source)?;
    assert!(worker::apply(&root, &control, &another).is_err());
    Ok(())
}

#[test]
fn worker_refuses_stale_tree_symlinks_corrupt_payload_and_cross_epoch() -> Result {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("project");
    let source = temp.path().join("source");
    let control = temp.path().join("control");
    fs::create_dir(&root)?;
    fs::create_dir(&source)?;
    fs::write(root.join("code"), "old")?;
    fs::write(source.join("code"), "new")?;
    let (offer, context) = offer(&root, &source)?;
    let bundle = worker::bundle(&offer, "after", &context, &source)?;
    fs::write(root.join("code"), "dirty")?;
    assert!(worker::apply(&root, &control, &bundle).is_err());
    assert_eq!(fs::read(root.join("code"))?, b"dirty");
    fs::write(root.join("code"), "old")?;
    symlink("/etc/passwd", source.join("link"))?;
    assert!(worker::bundle(&offer, "after", &context, &source).is_err());
    fs::remove_file(source.join("link"))?;
    let mut broken = bundle.clone();
    broken.truncate(broken.len() / 2);
    assert!(worker::apply(&root, &control, &broken).is_err());
    assert_eq!(fs::read(root.join("code"))?, b"old");
    worker::apply(&root, &control, &bundle)?;
    let mut stale = offer.clone();
    stale.attempt = "another-attempt".into();
    assert!(worker::apply(
        &root,
        &control,
        &worker::bundle(&stale, "after", &context, &source)?
    )
    .is_err());
    Ok(())
}

#[test]
fn hostile_inventory_paths_lengths_and_hardlinks_are_refused_before_source_effects() -> Result {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("project");
    let source = temp.path().join("source");
    let control = temp.path().join("control");
    fs::create_dir(&root)?;
    fs::create_dir(&source)?;
    fs::write(root.join("code"), "old")?;
    fs::write(source.join("code"), "new")?;
    let (offer, context) = offer(&root, &source)?;
    let bundle = worker::bundle(&offer, "after", &context, &source)?;
    let length = u64::from_be_bytes(bundle[..8].try_into()?) as usize;
    let original: serde_json::Value = serde_json::from_slice(&bundle[8..8 + length])?;
    for path in [
        "../escape",
        "/absolute",
        ".git/config",
        ".jj/repo",
        "a/../b",
        "a\\b",
    ] {
        let mut request = original.clone();
        let entry = request["inventory"]["code"].clone();
        request["inventory"] = json!({path:entry});
        request["offer"]["tree"] = json!(plan::digest(&request["inventory"])?);
        let header = serde_json::to_vec(&request)?;
        let mut payload = (header.len() as u64).to_be_bytes().to_vec();
        payload.extend(header);
        payload.extend_from_slice(&bundle[8 + length..]);
        assert!(worker::apply(&root, &control, &payload).is_err(), "{path}");
        assert_eq!(fs::read(root.join("code"))?, b"old");
    }
    let mut request = original;
    request["inventory"]["code"]["size"] = json!(snapshot::FILE_LIMIT + 1);
    request["offer"]["tree"] = json!(plan::digest(&request["inventory"])?);
    let header = serde_json::to_vec(&request)?;
    let mut payload = (header.len() as u64).to_be_bytes().to_vec();
    payload.extend(header);
    assert!(worker::apply(&root, &control, &payload).is_err());
    fs::hard_link(source.join("code"), temp.path().join("alias"))?;
    assert!(worker::bundle(&offer, "after", &context, &source).is_err());
    assert_eq!(fs::read(root.join("code"))?, b"old");
    Ok(())
}
