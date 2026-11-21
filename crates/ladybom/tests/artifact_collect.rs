#![allow(clippy::unwrap_used)]
// These tests write executable fixtures and spawn processes. Serialize them so
// a concurrent child cannot inherit another fixture's writer and cause ETXTBSY.
static PROCESS_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());

use ladybom::artifact::{collect, CollectOptions};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::TempDir;

const STORE: &str = "/nix/store/00000000000000000000000000000000-demo-1";
const DERIVER: &str = "/nix/store/11111111111111111111111111111111-demo-1.drv";
const NAR: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn script(path: &std::path::Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn fixture(mismatch: bool) -> (TempDir, CollectOptions) {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("root");
    let member = format!("store/{}", STORE.rsplit('/').next().unwrap());
    fs::create_dir_all(root.join(&member)).unwrap();
    fs::write(root.join(&member).join("payload"), b"data").unwrap();
    let mut rows = Vec::new();
    for path in [
        "store".to_string(),
        member.clone(),
        format!("{member}/payload"),
    ] {
        let metadata = fs::metadata(root.join(&path)).unwrap();
        let mut row = json!({"path":path,"mode":metadata.permissions().mode() & 0o7777,
            "kind":if metadata.is_dir() {"directory"} else {"file"}});
        if metadata.is_file() {
            row["bytes"] = json!(4);
            row["sha256"] = json!(ladybom::files::hash(b"data"));
        }
        rows.push(row);
    }
    fs::write(
        root.join("inventory.json"),
        serde_json::to_vec(&json!({"schema_version":1,
        "self_excluded":"inventory.json","resolved_plan":{},"files":rows}))
        .unwrap(),
    )
    .unwrap();
    let archive = temp.path().join("image.tar");
    fs::write(&archive, b"synthetic archive").unwrap();
    let nix = temp.path().join("nix");
    let info = json!({(STORE):{"deriver":DERIVER,"narHash":NAR,"references":[STORE]}});
    let drv = json!({"version":4,"derivations":{(DERIVER.rsplit('/').next().unwrap()):{
        "outputs":{"out":{"path":STORE.rsplit('/').next().unwrap()}},
        "env":{},"structuredAttrs":{"pname":"demo","version":"1"}}}});
    let observed = if mismatch {
        "sha256-BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    } else {
        NAR
    };
    script(&nix, &format!("case \" $* \" in\n*' path-info '*) printf '%s\\n' '{}' ;;\n*' derivation show '*) printf '%s\\n' '{}' ;;\n*' hash path '*) printf '%s\\n' '{}' ;;\n*) exit 2 ;;\nesac", info, drv, observed));
    let go_reader = temp.path().join("go-reader");
    script(&go_reader, "exit 99");
    let archive_checker = temp.path().join("archive-checker");
    script(&archive_checker, "test \"$#\" = 2");
    let options = CollectOptions {
        rootfs: root,
        manifest: "inventory.json".into(),
        archive,
        store_relative: "store".into(),
        nix,
        go_reader,
        archive_checker,
    };
    (temp, options)
}

#[test]
fn collects_only_content_bound_nix_identities() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let evidence = collect(&options).unwrap();
    assert_eq!(evidence.nix_outputs.len(), 1);
    assert_eq!(evidence.nix_outputs[0].store_path, STORE);
    assert_eq!(evidence.nix_outputs[0].name.as_deref(), Some("demo"));
    assert_eq!(evidence.nix_outputs[0].version.as_deref(), Some("1"));
    assert_eq!(evidence.nix_outputs[0].nar_hash.as_deref(), Some(NAR));
    assert!(evidence.gaps.is_empty());
    evidence.validate().unwrap();
}

#[test]
fn refuses_content_mismatch_and_failed_archive_verification() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(true);
    assert!(collect(&options).is_err());
    let (_temp, options) = fixture(false);
    script(&options.archive_checker, "exit 1");
    assert!(collect(&options).is_err());
}

#[test]
fn missing_native_metadata_is_explicitly_partial() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    script(&options.nix, "exit 1");
    let evidence = collect(&options).unwrap();
    assert_eq!(evidence.nix_outputs.len(), 1);
    assert!(evidence.nix_outputs[0].name.is_none());
    assert!(!evidence.gaps.is_empty());
}

#[test]
fn refuses_inventory_changed_by_native_tool() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let target = options
        .rootfs
        .join("store")
        .join(STORE.rsplit('/').next().unwrap())
        .join("payload");
    script(
        &options.archive_checker,
        &format!("printf changed > '{}'", target.display()),
    );
    assert!(collect(&options).is_err());
}

fn elf_fixture(go: bool) -> Vec<u8> {
    let names = if go {
        b"\0.shstrtab\0.go.buildinfo\0".as_slice()
    } else {
        b"\0.shstrtab\0.othersection\0".as_slice()
    };
    let mut bytes = vec![0u8; 256 + names.len() + 32];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&3u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes());
    for (index, name, offset, size, kind) in [
        (1, 1, 256, names.len(), 3),
        (2, 11, 256 + names.len(), 32, 1),
    ] {
        let start = 64 + index * 64;
        bytes[start..start + 4].copy_from_slice(&(name as u32).to_le_bytes());
        bytes[start + 4..start + 8].copy_from_slice(&(kind as u32).to_le_bytes());
        bytes[start + 24..start + 32].copy_from_slice(&(offset as u64).to_le_bytes());
        bytes[start + 32..start + 40].copy_from_slice(&(size as u64).to_le_bytes());
    }
    bytes[256..256 + names.len()].copy_from_slice(names);
    bytes
}
fn replace_payload(options: &CollectOptions, bytes: &[u8]) -> String {
    let relative = format!("store/{}/payload", STORE.rsplit('/').next().unwrap());
    fs::write(options.rootfs.join(&relative), bytes).unwrap();
    let manifest = options.rootfs.join("inventory.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    for entry in value["files"].as_array_mut().unwrap() {
        if entry["path"] == relative {
            entry["bytes"] = json!(bytes.len());
            entry["sha256"] = json!(ladybom::files::hash(bytes));
        }
    }
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    relative
}
fn go_info() -> serde_json::Value {
    json!({"GoVersion":"go1.26.11","Path":"example.test/main/cmd/app",
        "Main":{"Path":"example.test/main","Version":"v1.0.0","Sum":"","Replace":null},
        "Deps":[{"Path":"example.test/dep","Version":"v1.2.3","Sum":"","Replace":null}],
        "Settings":[{"Key":"GOARCH","Value":"amd64"}]})
}
#[test]
fn collects_go_modules_bound_to_the_delivered_binary() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let bytes = elf_fixture(true);
    let path = replace_payload(&options, &bytes);
    script(
        &options.go_reader,
        &format!("printf '%s\\n' '{}'", go_info()),
    );
    let evidence = collect(&options).unwrap();
    assert_eq!(evidence.go_binaries.len(), 1);
    assert_eq!(evidence.go_binaries[0].path, path);
    assert_eq!(evidence.go_binaries[0].sha256, ladybom::files::hash(&bytes));
    assert_eq!(evidence.go_binaries[0].go_version, "go1.26.11");
    assert_eq!(evidence.go_binaries[0].dependencies[0].version, "v1.2.3");
    assert!(evidence.gaps.is_empty());
}
#[test]
fn classifies_non_go_elf_without_running_the_go_reader() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    replace_payload(&options, &elf_fixture(false));
    let evidence = collect(&options).unwrap();
    assert!(evidence.go_binaries.is_empty());
    assert!(evidence.gaps.is_empty());
}
#[test]
fn unsupported_elf_and_unavailable_go_metadata_remain_partial() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for bytes in [b"\x7fELF".to_vec(), elf_fixture(true)] {
        let (_temp, options) = fixture(false);
        replace_payload(&options, &bytes);
        let evidence = collect(&options).unwrap();
        assert!(!evidence.gaps.is_empty());
        assert!(evidence.go_binaries.is_empty());
    }
}
#[test]
fn local_replacements_and_development_versions_remain_explicit() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    replace_payload(&options, &elf_fixture(true));
    let mut info = go_info();
    info["Main"]["Version"] = json!("(devel)");
    info["Deps"][0]["Replace"] = json!({"Path":"../local","Version":"","Sum":"","Replace":null});
    script(&options.go_reader, &format!("printf '%s\\n' '{}'", info));
    let evidence = collect(&options).unwrap();
    assert_eq!(
        evidence.go_binaries[0].dependencies[0]
            .replacement
            .as_ref()
            .unwrap()
            .path,
        "../local"
    );
    assert!(evidence
        .gaps
        .iter()
        .any(|g| g.code == "go_module_version_unknown"));
    assert!(evidence
        .gaps
        .iter()
        .any(|g| g.code == "go_local_replacement"));
}

#[test]
fn refuses_native_output_budget_and_launch_failures() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    script(&options.nix, "/usr/bin/head -c 17000000 /dev/zero");
    assert!(
        collect(&options).is_err(),
        "Nix output limit must not become a metadata gap"
    );
    fs::write(&options.nix, b"#!/missing/collector/interpreter\n").unwrap();
    assert!(
        collect(&options).is_err(),
        "Nix launch failure must not become a metadata gap"
    );
}

#[test]
fn refuses_duplicate_go_modules_and_unknown_reader_fields() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for unknown in [false, true] {
        let (_temp, options) = fixture(false);
        replace_payload(&options, &elf_fixture(true));
        let mut info = go_info();
        if unknown {
            info["unexpected"] = json!(true);
        } else {
            let duplicate = info["Deps"][0].clone();
            info["Deps"].as_array_mut().unwrap().push(duplicate);
        }
        script(&options.go_reader, &format!("printf '%s\\n' '{}'", info));
        assert!(collect(&options).is_err());
    }
}

#[test]
fn oversized_compressed_or_truncated_go_sections_are_partial() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for mode in ["large", "compressed", "truncated"] {
        let (_temp, options) = fixture(false);
        let mut bytes = elf_fixture(true);
        match mode {
            "large" => bytes[224..232].copy_from_slice(&(1024u64 * 1024 + 1).to_le_bytes()),
            "compressed" => bytes[200..208].copy_from_slice(&0x800u64.to_le_bytes()),
            _ => bytes.truncate(80),
        }
        replace_payload(&options, &bytes);
        script(&options.go_reader, "exit 98");
        let evidence = collect(&options).unwrap();
        assert!(evidence.go_binaries.is_empty());
        assert!(evidence
            .gaps
            .iter()
            .any(|g| g.code == "elf_format_unsupported"));
    }
}

#[test]
fn exports_deterministic_cyclonedx_bound_to_the_archive() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let mut evidence = collect(&options).unwrap();
    let mut first = Vec::new();
    ladybom::artifact::write_cyclonedx(&evidence, &mut first).unwrap();
    evidence.inventory.files.reverse();
    evidence.tools.reverse();
    let mut second = Vec::new();
    ladybom::artifact::write_cyclonedx(&evidence, &mut second).unwrap();
    assert_eq!(first, second);
    let bom: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(bom["specVersion"], "1.5");
    assert_eq!(bom["metadata"]["component"]["type"], "operating-system");
    assert_eq!(
        bom["metadata"]["component"]["hashes"][0]["content"],
        evidence.archive.sha256
    );
    assert_eq!(bom["compositions"][0]["aggregate"], "unknown");
    assert!(bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "demo" && c["version"] == "1"));
    assert!(!String::from_utf8(first)
        .unwrap()
        .contains(options.rootfs.to_str().unwrap()));
}

#[test]
fn preserves_distinct_nix_outputs_with_the_same_name_and_version() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let mut evidence = collect(&options).unwrap();
    let original = STORE.rsplit('/').next().unwrap();
    let other = "22222222222222222222222222222222-demo-1";
    let records: Vec<_> = evidence
        .inventory
        .files
        .iter()
        .filter(|f| f.path.contains(original))
        .cloned()
        .collect();
    for mut row in records {
        row.path = row.path.replace(original, other);
        evidence.inventory.content_bytes += row.bytes.unwrap_or(0);
        evidence.inventory.files.push(row);
    }
    let mut output = evidence.nix_outputs[0].clone();
    output.store_path = format!("/nix/store/{other}");
    output.deriver = Some("/nix/store/22222222222222222222222222222222-demo-1.drv".into());
    output.derivation_sha256 = Some(ladybom::files::hash(b"synthetic second derivation"));
    evidence.nix_outputs.push(output);
    let mut bytes = Vec::new();
    ladybom::artifact::write_cyclonedx(&evidence, &mut bytes).unwrap();
    let bom: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let components: Vec<_> = bom["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["name"] == "demo")
        .collect();
    assert_eq!(components.len(), 2);
    assert_ne!(components[0]["bom-ref"], components[1]["bom-ref"]);
}

#[test]
fn refuses_inconsistent_evidence_before_any_export_bytes() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let mut evidence = collect(&options).unwrap();
    evidence.nix_outputs[0].observed_nar_hash =
        Some("sha256-BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
    let mut bytes = Vec::new();
    assert!(ladybom::artifact::write_cyclonedx(&evidence, &mut bytes).is_err());
    assert!(bytes.is_empty());
}

#[test]
fn public_go_export_keeps_local_replacements_partial_without_exposing_paths() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    replace_payload(&options, &elf_fixture(true));
    let mut info = go_info();
    info["Deps"][0]["Replace"] =
        json!({"Path":"../private-source","Version":"","Sum":"","Replace":null});
    script(&options.go_reader, &format!("printf '%s\\n' '{}'", info));
    let evidence = collect(&options).unwrap();
    let mut bytes = Vec::new();
    ladybom::artifact::write_cyclonedx(&evidence, &mut bytes).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("../private-source"));
    let bom: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(bom["compositions"][0]["aggregate"], "incomplete");
}

#[test]
fn reads_large_evidence_with_explicit_bounds_and_strict_keys() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (temp, options) = fixture(false);
    let mut evidence = collect(&options).unwrap();
    for i in 0..10_001 {
        evidence.inventory.files.push(ladybom::artifact::FileEntry {
            path: format!("extra-{i}"),
            kind: "directory".into(),
            mode: 0o755,
            bytes: None,
            sha256: None,
            target: None,
        });
    }
    let path = temp.path().join("evidence.json");
    let bytes = serde_json::to_vec(&evidence).unwrap();
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        ladybom::artifact::read_evidence(&path)
            .unwrap()
            .inventory
            .files
            .len(),
        10_004
    );
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    fs::write(&path, duplicate).unwrap();
    assert!(ladybom::artifact::read_evidence(&path).is_err());
}

#[test]
fn rejects_malformed_local_replacement_evidence_offline() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    replace_payload(&options, &elf_fixture(true));
    let mut info = go_info();
    info["Deps"][0]["Replace"] = json!({"Path":"../local", "Version":"", "Sum":""});
    script(&options.go_reader, &format!("printf '%s\\n' '{}'", info));
    let mut evidence = collect(&options).unwrap();
    evidence.go_binaries[0].dependencies[0]
        .replacement
        .as_mut()
        .unwrap()
        .sum = "bad\nvalue".into();
    assert!(evidence.validate().is_err());
}

#[test]
fn accepts_native_go_omitted_fields_and_marks_absent_main() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    replace_payload(&options, &elf_fixture(true));
    let mut info = go_info();
    info["Main"] = json!({});
    info["Deps"][0].as_object_mut().unwrap().remove("Sum");
    info["Deps"][0].as_object_mut().unwrap().remove("Version");
    script(&options.go_reader, &format!("printf '%s\\n' '{}'", info));
    let evidence = collect(&options).unwrap();
    assert!(evidence.go_binaries[0].main.is_none());
    assert!(evidence
        .gaps
        .iter()
        .any(|g| g.code == "go_main_module_unknown"));
    assert!(evidence
        .gaps
        .iter()
        .any(|g| g.code == "go_module_version_unknown"));
    let mut bytes = Vec::new();
    ladybom::artifact::write_cyclonedx(&evidence, &mut bytes).unwrap();
    let bom: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bom["compositions"][0]["aggregate"], "incomplete");
}

#[test]
fn refuses_private_nix_version_before_publication() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let mut evidence = collect(&options).unwrap();
    evidence.nix_outputs[0].version = Some("/home/private-user/private-source".into());
    evidence.validate().unwrap();
    let mut bytes = Vec::new();
    assert!(ladybom::artifact::write_cyclonedx(&evidence, &mut bytes).is_err());
    assert!(bytes.is_empty());
}

#[test]
fn resolves_native_derivation_from_output_when_recorded_deriver_is_stale() {
    let _fixture_guard = PROCESS_FIXTURES
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let (_temp, options) = fixture(false);
    let stale = "/nix/store/22222222222222222222222222222222-demo-1.drv";
    let body = fs::read_to_string(&options.nix).unwrap();
    let body = body.replace(
        &format!("\"deriver\":\"{DERIVER}\""),
        &format!("\"deriver\":\"{stale}\""),
    );
    let body = body.replace(
        "case \" $* \" in",
        &format!("case \" $* \" in\n*' {stale} '*) exit 1 ;;"),
    );
    fs::write(&options.nix, body).unwrap();
    let evidence = collect(&options).unwrap();
    assert_eq!(evidence.nix_outputs[0].name.as_deref(), Some("demo"));
    assert_eq!(evidence.nix_outputs[0].deriver.as_deref(), Some(DERIVER));
    assert!(evidence.gaps.is_empty());
}
