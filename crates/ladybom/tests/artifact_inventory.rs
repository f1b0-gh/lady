#![allow(clippy::unwrap_used)]
use ladybom::artifact::inspect_rootfs;
use serde_json::json;
use std::{
    fs,
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, PermissionsExt},
    },
};
use tempfile::TempDir;

fn fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("payload"), b"payload").unwrap();
    let manifest = json!({"schema_version":1,"self_excluded":"inventory.json",
        "resolved_plan":{},"files":[{"path":"payload","kind":"file",
        "mode":fs::metadata(root.join("payload")).unwrap().permissions().mode() & 0o7777,
        "bytes":7,"sha256":ladybom::files::hash(b"payload")}]});
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    (temp, root)
}

#[test]
fn verifies_exact_delivered_content() {
    let (_temp, root) = fixture();
    let inventory = inspect_rootfs(&root, std::path::Path::new("inventory.json")).unwrap();
    assert_eq!(inventory.files.len(), 1);
    assert_eq!(inventory.files[0].path, "payload");
    fs::write(root.join("payload"), b"changed").unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
}

#[test]
fn refuses_added_missing_and_linked_files() {
    for case in ["added", "missing", "linked"] {
        let (_temp, root) = fixture();
        match case {
            "added" => fs::write(root.join("extra"), b"x").unwrap(),
            "missing" => fs::remove_file(root.join("payload")).unwrap(),
            _ => {
                fs::remove_file(root.join("payload")).unwrap();
                symlink("/etc/passwd", root.join("payload")).unwrap();
            }
        }
        assert!(
            inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err(),
            "{case}"
        );
    }
}

#[test]
fn refuses_linked_root_ancestor_and_non_regular_input() {
    let (temp, root) = fixture();
    symlink(&root, temp.path().join("alias")).unwrap();
    assert!(inspect_rootfs(
        &temp.path().join("alias"),
        std::path::Path::new("inventory.json")
    )
    .is_err());
    assert!(inspect_rootfs(&root, std::path::Path::new("../inventory.json")).is_err());
    fs::remove_file(root.join("inventory.json")).unwrap();
    symlink("/etc/passwd", root.join("inventory.json")).unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
    let (_temp, root) = fixture();
    // Non-UTF8 names are rejected, never silently dropped from inventory.
    fs::write(root.join(std::ffi::OsStr::from_bytes(b"\xff")), b"x").unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
}

#[test]
fn refuses_duplicate_unknown_and_unsafe_manifest_entries() {
    let (_temp, root) = fixture();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("inventory.json")).unwrap()).unwrap();
    for name in ["../escape", "/absolute", "a//b", "./payload"] {
        let mut value = original.clone();
        value["files"][0]["path"] = json!(name);
        fs::write(
            root.join("inventory.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(
            inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err(),
            "{name}"
        );
    }
    let mut value = original.clone();
    value["unknown"] = json!(true);
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
    let mut value = original.clone();
    value["files"]
        .as_array_mut()
        .unwrap()
        .push(original["files"][0].clone());
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
    fs::write(
        root.join("inventory.json"),
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
}

#[test]
fn inventories_symlinks_without_following_them() {
    let (_temp, root) = fixture();
    symlink("/a/host/path/that/does/not/exist", root.join("link")).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("inventory.json")).unwrap()).unwrap();
    value["files"].as_array_mut().unwrap().push(json!({"path":"link","kind":"symlink","mode":0o777,"target":"/a/host/path/that/does/not/exist"}));
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert_eq!(
        inspect_rootfs(&root, std::path::Path::new("inventory.json"))
            .unwrap()
            .files
            .len(),
        2
    );
}

#[test]
fn refuses_declared_size_and_depth_before_reading_payload() {
    let (_temp, root) = fixture();
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("inventory.json")).unwrap()).unwrap();
    for field in ["bytes", "path"] {
        let mut value = original.clone();
        value["files"][0][field] = if field == "bytes" {
            json!(32u64 * 1024 * 1024 * 1024 + 1)
        } else {
            json!(vec!["a"; 65].join("/"))
        };
        fs::write(
            root.join("inventory.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
    }
}

#[test]
fn refuses_nonregular_delivered_entry() {
    let (_temp, root) = fixture();
    fs::remove_file(root.join("payload")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(root.join("payload")).unwrap();
    assert!(inspect_rootfs(&root, std::path::Path::new("inventory.json")).is_err());
}
