use ladyboot::inventory::verify;
use nickel_util::files::hash;
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
};

fn fixture(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root.join("usr/share/ladyboot"))?;
    fs::write(root.join("kernel"), b"kernel")?;
    let mut rows = vec![];
    for path in ["usr", "usr/share", "usr/share/ladyboot"] {
        rows.push(json!({"path":path,"kind":"directory","mode": fs::metadata(root.join(path))?.permissions().mode() & 0o7777}));
    }
    rows.push(json!({"path":"kernel","kind":"file","mode":fs::metadata(root.join("kernel"))?.permissions().mode() & 0o7777,"bytes":6,"sha256":hash(b"kernel")}));
    fs::write(
        root.join("usr/share/ladyboot/inventory.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"self_excluded":"usr/share/ladyboot/inventory.json","resolved_plan":{},"files":rows}),
        )?,
    )?;
    Ok(())
}

#[test]
fn observed_manifest_rejects_changed_extra_and_hostile_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fixture(root)?;
    assert_eq!(verify(root)?["verified"], true);
    fs::write(root.join("extra"), b"x")?;
    assert!(verify(root).is_err());
    fs::remove_file(root.join("extra"))?;
    fs::write(root.join("kernel"), b"tamper")?;
    assert!(verify(root).is_err());
    fs::write(root.join("kernel"), b"kernel")?;
    let manifest = root.join("usr/share/ladyboot/inventory.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    value["files"][0]["path"] = "../escape".into();
    fs::write(&manifest, serde_json::to_vec(&value)?)?;
    assert!(verify(root).is_err());
    fixture(root)?;
    fs::remove_file(root.join("kernel"))?;
    symlink("/etc/passwd", root.join("kernel"))?;
    assert!(verify(root).is_err());
    Ok(())
}

#[test]
fn observed_enablement_excludes_inert_package_example_links(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fixture(root)?;
    let manifest = root.join("usr/share/ladyboot/inventory.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&manifest)?)?;
    let rows = value["files"].as_array_mut().ok_or("missing files")?;
    for directory in [
        "etc",
        "etc/systemd",
        "etc/systemd/system",
        "etc/systemd/system/basic.target.wants",
        "usr/lib",
        "usr/lib/nix",
        "usr/lib/nix/store",
        "usr/lib/nix/store/package",
        "usr/lib/nix/store/package/example",
        "usr/lib/nix/store/package/example/systemd",
        "usr/lib/nix/store/package/example/systemd/system",
        "usr/lib/nix/store/package/example/systemd/system/basic.target.wants",
    ] {
        fs::create_dir(root.join(directory))?;
        rows.push(json!({"path":directory,"kind":"directory","mode":fs::metadata(root.join(directory))?.permissions().mode() & 0o7777}));
    }
    let active = "etc/systemd/system/basic.target.wants/example.service";
    let inert =
        "usr/lib/nix/store/package/example/systemd/system/basic.target.wants/example.service";
    for path in [active, inert] {
        symlink("/usr/lib/systemd/system/example.service", root.join(path))?;
        rows.push(json!({"path":path,"kind":"symlink","mode":0o777,"target":"/usr/lib/systemd/system/example.service"}));
    }
    fs::write(&manifest, serde_json::to_vec(&value)?)?;
    let observed = verify(root)?;
    let links = observed["enabled_unit_links"]
        .as_array()
        .ok_or("missing unit links")?;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["path"], active);
    Ok(())
}
