use ladyboot::artifact::inspect;
use nickel_util::files::hash;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn store(path: &Path) -> Result<(PathBuf, String)> {
    let output = Command::new("nix-store").arg("--add").arg(path).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = PathBuf::from(String::from_utf8(output.stdout)?.trim());
    let output = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "path-info",
            "--json",
            "--json-format",
            "1",
        ])
        .arg(&path)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)?;
    let nar = value[path.to_str().ok_or("path")?]["narHash"]
        .as_str()
        .ok_or("NAR")?
        .to_owned();
    Ok((path, nar))
}
fn fixture() -> Result<(tempfile::TempDir, Value)> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("rootfs");
    fs::create_dir_all(root.join("usr/share/ladyboot"))?;
    fs::write(root.join("kernel"), b"kernel")?;
    fs::set_permissions(root.join("kernel"), fs::Permissions::from_mode(0o444))?;
    let config = json!({"needs":["bootc-base"],"schema_version":1,"architecture":"x86_64-linux","os_id":"fixture","revision":1});
    let mut entries = vec![];
    for path in ["usr", "usr/share", "usr/share/ladyboot"] {
        entries.push(json!({"path":path,"kind":"directory","mode":0o555}));
    }
    entries.push(
        json!({"path":"kernel","kind":"file","mode":0o444,"bytes":6,"sha256":hash(b"kernel")}),
    );
    let manifest = serde_json::to_vec(
        &json!({"schema_version":1,"self_excluded":"usr/share/ladyboot/inventory.json","resolved_plan":{"requested":config},"files":entries}),
    )?;
    fs::write(root.join("usr/share/ladyboot/inventory.json"), &manifest)?;
    fs::set_permissions(
        root.join("usr/share/ladyboot/inventory.json"),
        fs::Permissions::from_mode(0o444),
    )?;
    for path in ["usr/share/ladyboot", "usr/share", "usr"] {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o555))?;
    }
    let (root_path, root_nar) = store(&root)?;
    let image = temp.path().join("synthetic-image");
    fs::write(&image, b"synthetic image identity")?;
    let (image_path, image_nar) = store(&image)?;
    let receipt = json!({"schema_version":1,"inputs":{"schema_version":1,"profile":"bootc","configuration":config,"inputs_sha256":{},"evaluator":"fixture","modules_sha256":{}},"target":"bootc-image","store_path":image_path,"nar_hash":image_nar,"rootfs":{"store_path":root_path,"nar_hash":root_nar,"inventory_sha256":hash(&manifest)}});
    // Restore the temporary tree permissions so cleanup does not depend on uid 0.
    for path in ["usr", "usr/share", "usr/share/ladyboot"] {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o755))?;
    }
    Ok((temp, receipt))
}
fn check(temp: &Path, receipt: &Value) -> Result<Value> {
    let file = temp.join("receipt.json");
    fs::write(&file, serde_json::to_vec(receipt)?)?;
    Ok(inspect(&file)?)
}
#[test]
fn image_inspection_verifies_associated_rootfs_and_rejects_bad_receipts() -> Result {
    let (temp, valid) = fixture()?;
    assert!(check(temp.path(), &valid).is_ok());
    for mutation in 0..5 {
        let mut value = valid.clone();
        match mutation {
            0 => value["rootfs"] = Value::Null,
            1 => value["rootfs"]["store_path"] = json!("/does/not/exist"),
            2 => value["rootfs"]["nar_hash"] = json!("INVALID"),
            3 => value["rootfs"]["inventory_sha256"] = json!("0".repeat(64)),
            _ => value["inputs"]["configuration"]["needs"] = json!(["bootc-base", "diagnostics"]),
        }
        assert!(
            check(temp.path(), &value).is_err(),
            "accepted corrupt image receipt mutation {mutation}"
        );
    }
    assert_eq!(check(temp.path(), &valid)?["observed"]["verified"], true);
    Ok(())
}
#[test]
fn rootfs_inspection_requires_matching_association_and_inventory_digest() -> Result {
    let (temp, mut valid) = fixture()?;
    valid["target"] = json!("rootfs");
    valid["store_path"] = valid["rootfs"]["store_path"].clone();
    valid["nar_hash"] = valid["rootfs"]["nar_hash"].clone();
    assert!(check(temp.path(), &valid).is_ok());
    let mut changed = valid.clone();
    changed["rootfs"]["inventory_sha256"] = json!("0".repeat(64));
    assert!(
        check(temp.path(), &changed).is_err(),
        "accepted mismatched inventory digest"
    );
    changed = valid.clone();
    changed["rootfs"]["store_path"] =
        json!("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-another-root");
    assert!(
        check(temp.path(), &changed).is_err(),
        "accepted mismatched rootfs association"
    );
    Ok(())
}
