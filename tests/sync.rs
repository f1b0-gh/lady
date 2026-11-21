use ladyshell::{
    error::Result,
    files, snapshot,
    sync::{self, Transport},
};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
};
struct Fixture {
    root: PathBuf,
    fetches: usize,
    inventories: usize,
    corrupt: bool,
    race: bool,
}
impl Transport for Fixture {
    fn inventory(&mut self) -> Result<Vec<u8>> {
        self.inventories += 1;
        if self.race && self.inventories == 2 {
            fs::write(self.root.join("new.txt"), b"concurrent")?;
        }
        Ok(serde_json::to_vec(&snapshot::inventory(&self.root)?)?)
    }
    fn file(&mut self, path: &str) -> Result<Vec<u8>> {
        self.fetches += 1;
        let mut payload = snapshot::read_file(&self.root, path)?;
        if self.corrupt {
            payload.data = "eA==".into();
        }
        Ok(serde_json::to_vec(&payload)?)
    }
}
fn fixture(root: &Path) -> Fixture {
    Fixture {
        root: root.into(),
        fetches: 0,
        inventories: 0,
        corrupt: false,
        race: false,
    }
}
fn state(base: &Path) -> Result<Value> {
    let inventory = snapshot::inventory(base)?;
    let records: serde_json::Map<String, Value> = inventory
        .into_iter()
        .map(|(p, e)| (p, json!({"sha256":e.sha256,"executable":e.executable})))
        .collect();
    Ok(
        json!({"schema_version":2,"sandbox_id":"test-id","project_snapshot":base,"host_sources":records,"sync":{"destination":"exports"}}),
    )
}
#[test]
fn incremental_export_fetches_only_changes_and_tracks_deletions() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let base = temp.path().join("base");
    let remote = temp.path().join("remote");
    fs::create_dir(&base)?;
    fs::create_dir(&remote)?;
    fs::write(base.join("a"), b"same")?;
    fs::write(remote.join("a"), b"same")?;
    let mut transport = fixture(&remote);
    let first = sync::sync_with(
        &state(&base)?,
        &temp.path().join("state"),
        &mut transport,
        false,
    )?;
    assert_eq!(transport.fetches, 0);
    fs::write(remote.join("b"), b"new")?;
    let second = sync::sync_with(&first, &temp.path().join("state"), &mut transport, false)?;
    assert_eq!(transport.fetches, 1);
    fs::remove_file(remote.join("a"))?;
    let third = sync::sync_with(&second, &temp.path().join("state"), &mut transport, false)?;
    assert_eq!(transport.fetches, 1);
    let path = ladyshell::state::text(&third, "last_sync")?;
    let manifest = ladyshell::json::parse(&files::read_limited(
        &Path::new(path).join("manifest.json"),
        1024 * 1024,
    )?)?;
    assert_eq!(manifest["deletions"], json!(["a"]));
    assert!(!Path::new(path).join("project/a").exists());
    assert_eq!(fs::read(base.join("a"))?, b"same");
    Ok(())
}
#[test]
fn corrupt_transfer_and_concurrent_changes_never_publish() -> Result<()> {
    for race in [false, true] {
        let temp = tempfile::tempdir()?;
        let base = temp.path().join("base");
        let remote = temp.path().join("remote");
        fs::create_dir(&base)?;
        fs::create_dir(&remote)?;
        fs::write(remote.join("a"), b"original")?;
        let mut transport = fixture(&remote);
        transport.corrupt = !race;
        transport.race = race;
        let directory = temp.path().join("state");
        assert!(sync::sync_with(&state(&base)?, &directory, &mut transport, false).is_err());
        assert_eq!(fs::read_dir(directory.join("exports"))?.count(), 0);
    }
    Ok(())
}
#[test]
fn rejects_hostile_inventory_and_duplicate_json() -> Result<()> {
    for path in [
        "../escape",
        "/escape",
        "a//b",
        "a/./b",
        ".env",
        "target/a",
        "a/.ssh/key",
    ] {
        let bytes = serde_json::to_vec(
            &json!({path:{"sha256":files::hash(b""),"executable":false,"size":0}}),
        )?;
        assert!(sync::parse_inventory(&bytes).is_err(), "{path}");
    }
    assert!(sync::parse_inventory(br#"{"a":{},"a":{}}"#).is_err());
    let record = json!({"sha256":files::hash(b""),"executable":false,"size":0});
    assert!(
        sync::parse_inventory(&serde_json::to_vec(&json!({"a":record,"a/b":record}))?).is_err()
    );
    for record in [
        json!({"sha256":"invalid","executable":false,"size":0}),
        json!({"sha256":files::hash(b""),"executable":1,"size":0}),
        json!({"sha256":files::hash(b""),"executable":false,"size":snapshot::FILE_LIMIT+1}),
    ] {
        assert!(sync::parse_inventory(&serde_json::to_vec(&json!({"a":record}))?).is_err());
    }
    Ok(())
}
#[test]
fn rejects_symlink_ancestors_and_modified_reuse() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let base = temp.path().join("base");
    let remote = temp.path().join("remote");
    fs::create_dir(&base)?;
    fs::create_dir(&remote)?;
    fs::write(base.join("a"), b"same")?;
    fs::write(remote.join("a"), b"same")?;
    let initial = state(&base)?;
    fs::write(base.join("a"), b"changed")?;
    assert!(sync::sync_with(
        &initial,
        &temp.path().join("state"),
        &mut fixture(&remote),
        false
    )
    .is_err());
    std::os::unix::fs::symlink(&remote, temp.path().join("link"))?;
    assert!(snapshot::read_file(&temp.path().join("link"), "a").is_err());
    std::os::unix::fs::symlink(&base, remote.join("linked"))?;
    assert!(snapshot::inventory(&remote).is_err());
    Ok(())
}
#[test]
fn preserves_executable_files_and_separates_metadata_from_payload() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let base = temp.path().join("base");
    let remote = temp.path().join("remote");
    fs::create_dir(&base)?;
    fs::create_dir(&remote)?;
    fs::write(
        remote.join("manifest.json"),
        b"project data, not host metadata",
    )?;
    fs::write(remote.join("run"), b"#!/bin/sh\n")?;
    fs::set_permissions(remote.join("run"), fs::Permissions::from_mode(0o755))?;
    fs::write(remote.join(".env"), b"excluded")?;
    fs::create_dir(remote.join("target"))?;
    fs::write(remote.join("target/cache"), b"excluded")?;
    let next = sync::sync_with(
        &state(&base)?,
        &temp.path().join("state"),
        &mut fixture(&remote),
        true,
    )?;
    let export = Path::new(ladyshell::state::text(&next, "last_sync")?);
    assert_eq!(
        fs::read(export.join("project/manifest.json"))?,
        b"project data, not host metadata"
    );
    assert_eq!(
        fs::metadata(export.join("project/run"))?
            .permissions()
            .mode()
            & 0o111,
        0o111
    );
    assert!(!export.join("project/.env").exists());
    assert!(!export.join("project/target").exists());
    assert!(temp.path().join("state/state.json").exists());
    Ok(())
}
#[test]
fn refuses_inventory_count_and_aggregate_limits() -> Result<()> {
    let empty = snapshot::Entry {
        sha256: files::hash(b""),
        executable: false,
        size: 0,
    };
    let mut inventory = snapshot::Inventory::new();
    for i in 0..5001 {
        inventory.insert(format!("f{i}"), empty.clone());
    }
    assert!(snapshot::validate(&inventory).is_err());
    inventory.clear();
    for i in 0..17 {
        let mut entry = empty.clone();
        entry.size = snapshot::FILE_LIMIT;
        inventory.insert(format!("f{i}"), entry);
    }
    assert!(snapshot::validate(&inventory).is_err());
    Ok(())
}
#[test]
fn custom_exclusions_apply_to_worker_and_are_enforced_by_host() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let remote = temp.path().join("remote");
    let base = temp.path().join("base");
    fs::create_dir(&remote)?;
    fs::create_dir(&base)?;
    fs::write(remote.join("generated.log"), b"excluded")?;
    fs::write(remote.join("README.md"), b"included")?;
    let filtered = snapshot::inventory_filtered(&remote, &["generated.log".into()])?;
    assert!(!filtered.contains_key("generated.log"));
    assert!(filtered.contains_key("README.md"));
    let mut initial = state(&base)?;
    initial["desired_inputs"] =
        json!({"evaluated":{"config":{"sources":{"exclude":["generated.log"]}}}});
    assert!(sync::sync_with(
        &initial,
        &temp.path().join("state"),
        &mut fixture(&remote),
        false
    )
    .is_err());
    Ok(())
}
