// These tests write executable fixtures and spawn processes. Serialize them so
// a concurrent child cannot inherit another fixture's writer and cause ETXTBSY.
static PROCESS_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());

use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::Path,
    process::{Command, Output},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn evidence(partial: bool) -> Value {
    let hash = "0".repeat(64);
    let mut value = json!({"schema_version":1,"archive":{"name":"image.tar.gz","sha256":hash,"bytes":1},
        "inventory":{"manifest_path":"inventory.json","manifest_sha256":hash,"content_bytes":0,"files":[]},
        "store_relative":"store","nix_outputs":[],"go_binaries":[],"elf_files":[],
        "tools":[{"role":"nix","sha256":hash,"bytes":1},{"role":"go-reader","sha256":hash,"bytes":1},{"role":"archive-checker","sha256":hash,"bytes":1}],
        "archive_check":{"archive_sha256":hash,"manifest_sha256":hash,"tool_sha256":hash},"gaps":[]});
    if partial {
        value["gaps"] = json!([{"code":"nix_metadata_unavailable","path":"/nix/store/00000000000000000000000000000000-demo","message":"Fixture gap"}]);
    }
    value
}
fn export(input: &Path, output: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .env_clear()
        .env("PATH", "")
        .args(["artifact", "export", "--evidence"])
        .arg(input)
        .arg("--output")
        .arg(output)
        .output()
}
#[test]
fn offline_export_is_deterministic_private_and_never_overwrites() -> Result {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("evidence.json");
    fs::write(&input, serde_json::to_vec(&evidence(false))?)?;
    let output = temp.path().join("export");
    let result = export(&input, &output)?;
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let manifest: Value = serde_json::from_slice(&fs::read(output.join("manifest.json"))?)?;
    assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o700);
    for entry in manifest["artifacts"].as_array().ok_or("artifacts")? {
        let path = output.join(entry["path"].as_str().ok_or("path")?);
        assert_eq!(entry["sha256"], ladybom::files::hash(&fs::read(&path)?));
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let second = temp.path().join("second");
    assert!(export(&input, &second)?.status.success());
    assert_eq!(
        fs::read(output.join("bom.cdx.json"))?,
        fs::read(second.join("bom.cdx.json"))?
    );
    assert!(!export(&input, &output)?.status.success());
    assert_eq!(
        manifest,
        serde_json::from_slice::<Value>(&fs::read(output.join("manifest.json"))?)?
    );
    Ok(())
}
#[test]
fn partial_coverage_has_exit_two_and_remains_visible() -> Result {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("evidence.json");
    fs::write(&input, serde_json::to_vec(&evidence(true))?)?;
    let output = temp.path().join("export");
    let result = export(&input, &output)?;
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let coverage: Value = serde_json::from_slice(&fs::read(output.join("coverage.json"))?)?;
    assert_eq!(coverage["scope_complete"], false);
    assert_eq!(coverage["os_composition_complete"], false);
    Ok(())
}
#[test]
fn malformed_duplicate_unknown_and_linked_inputs_publish_nothing() -> Result {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let temp = tempfile::tempdir()?;
    let input = temp.path().join("evidence.json");
    let output = temp.path().join("export");
    let valid = serde_json::to_string(&evidence(false))?;
    for text in [
        "{}".into(),
        valid.replacen('{', "{\"schema_version\":1,", 1),
        valid.replacen('{', "{\"unknown\":1,", 1),
    ] {
        fs::write(&input, text)?;
        assert!(!export(&input, &output)?.status.success());
        assert!(!output.exists());
    }
    fs::write(&input, valid)?;
    let linked = temp.path().join("linked");
    symlink(&input, &linked)?;
    assert!(!export(&linked, &output)?.status.success());
    let ancestor = temp.path().join("ancestor");
    symlink(temp.path(), &ancestor)?;
    assert!(!export(&input, &ancestor.join("export"))?.status.success());
    assert!(!output.exists());
    Ok(())
}

#[test]
fn explicit_collect_publishes_partial_evidence_for_offline_export() -> Result {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("root");
    let member = "store/00000000000000000000000000000000-demo";
    fs::create_dir_all(root.join(member))?;
    let rows: Vec<_> = ["store", member]
        .iter()
        .map(|p| json!({"path":p,"kind":"directory", "mode":0o755}))
        .collect();
    for path in ["store", member] {
        fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o755))?;
    }
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"self_excluded":"inventory.json","resolved_plan":{},"files":rows}),
        )?,
    )?;
    let archive = temp.path().join("image.tar");
    fs::write(&archive, b"synthetic")?;
    let unavailable = temp.path().join("unavailable");
    let checker = temp.path().join("checker");
    for (path, body) in [
        (&unavailable, "#!/bin/sh\nexit 1\n"),
        (&checker, "#!/bin/sh\ntest \"$#\" = 2\n"),
    ] {
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let output = temp.path().join("collected");
    let result = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["artifact", "collect", "--rootfs"])
        .arg(&root)
        .args([
            "--manifest",
            "inventory.json",
            "--store-relative",
            "store",
            "--archive",
        ])
        .arg(archive)
        .arg("--nix")
        .arg(&unavailable)
        .arg("--go-reader")
        .arg(&unavailable)
        .arg("--archive-checker")
        .arg(&checker)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(output.join("manifest.json").is_file());
    let evidence: Value = serde_json::from_slice(&fs::read(output.join("evidence.json"))?)?;
    assert_eq!(
        evidence["nix_outputs"].as_array().ok_or("outputs")?.len(),
        1
    );
    assert_eq!(
        export(&output.join("evidence.json"), &temp.path().join("public"))?
            .status
            .code(),
        Some(2)
    );
    Ok(())
}
