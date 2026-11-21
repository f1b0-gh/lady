use ladybom::inventory::{preview_filtered, Disposition, EntryKind, Preview};
use std::{fs, os::unix::fs::symlink};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn preview_prunes_exclusions_and_reports_unsupported_without_reading_contents() -> Result {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("code"), b"abc")?;
    fs::create_dir(root.path().join(".git"))?;
    fs::write(root.path().join(".git/secret"), b"secret")?;
    fs::create_dir(root.path().join("credentials"))?;
    fs::write(root.path().join("credentials/code"), b"ok")?;
    fs::write(root.path().join(".env"), b"secret")?;
    fs::write(root.path().join("custom"), b"secret")?;
    let _socket = std::os::unix::net::UnixListener::bind(root.path().join("socket"))?;
    symlink("/etc/passwd", root.path().join("link"))?;
    let huge = fs::File::create(root.path().join("large"))?;
    huge.set_len(ladybom::inventory::FILE_LIMIT as u64 + 1)?;
    let result = preview_filtered(root.path(), &["custom".into()])?;
    assert_eq!(result.entries["code"].size, Some(3));
    assert_eq!(
        result.entries["credentials/code"].disposition,
        Disposition::Included
    );
    assert_eq!(result.entries[".git"].kind, EntryKind::Directory);
    assert!(!result.entries.contains_key(".git/secret"));
    for name in [".git", ".env", "custom"] {
        assert_eq!(
            result.entries[name].disposition,
            Disposition::ExcludedByPolicy
        );
        assert_eq!(result.entries[name].size, None);
    }
    assert_eq!(
        result.entries["socket"].disposition,
        Disposition::UnsupportedType
    );
    assert_eq!(
        result.entries["link"].disposition,
        Disposition::UnsupportedType
    );
    assert_eq!(
        result.entries["large"].disposition,
        Disposition::FileSizeLimit
    );
    Ok(())
}
#[test]
fn preview_rejects_forged_policy_and_pruned_descendants() -> Result {
    let forged = br#"{"schema_version":1,"entries":{".env":{"disposition":"included","kind":"file","size":1}}}"#;
    let preview: Preview = serde_json::from_slice(forged)?;
    assert!(preview.validate(&[]).is_err());
    let forged = br#"{"schema_version":1,"entries":{".git":{"disposition":"excluded_by_policy","kind":"directory","size":null},".git/x":{"disposition":"excluded_by_policy","kind":"file","size":null}}}"#;
    let preview: Preview = serde_json::from_slice(forged)?;
    assert!(preview.validate(&[]).is_err());
    Ok(())
}
#[test]
fn preview_refuses_deep_trees_and_linked_roots() -> Result {
    let root = tempfile::tempdir()?;
    let mut path = root.path().to_path_buf();
    for _ in 0..66 {
        path.push("d");
        fs::create_dir(&path)?;
    }
    assert!(preview_filtered(root.path(), &[]).is_err());
    let external = tempfile::tempdir()?;
    symlink(external.path(), root.path().join("alias"))?;
    assert!(preview_filtered(&root.path().join("alias"), &[]).is_err());
    Ok(())
}
#[test]
fn preview_reports_file_count_limit_without_exporting_overflow() -> Result {
    let root = tempfile::tempdir()?;
    for index in 0..5001 {
        fs::write(root.path().join(format!("file-{index}")), b"")?;
    }
    let preview = preview_filtered(root.path(), &[])?;
    assert_eq!(
        preview
            .entries
            .values()
            .filter(|e| e.disposition == Disposition::Included)
            .count(),
        5000
    );
    assert_eq!(
        preview
            .entries
            .values()
            .filter(|e| e.disposition == Disposition::FileCountLimit)
            .count(),
        1
    );
    Ok(())
}
#[test]
fn preview_rejects_exportability_claims_unsupported_inclusion_and_understated_totals() -> Result {
    for entry in [
        serde_json::json!({"disposition":"included","kind":"symlink","size":null}),
        serde_json::json!({"disposition":"included","kind":"special","size":null}),
        serde_json::json!({"disposition":"included","kind":"file","size":ladybom::inventory::FILE_LIMIT + 1}),
        serde_json::json!({"disposition":"included","kind":"file","size":0,"unsupported":true}),
    ] {
        let value = serde_json::json!({"schema_version":1,"entries":{"code":entry}});
        if let Ok(preview) = serde_json::from_value::<Preview>(value) {
            assert!(preview.validate(&[]).is_err());
        }
    }
    let mut entries = serde_json::Map::new();
    for index in 0..17 {
        entries.insert(format!("code-{index}"), serde_json::json!({"disposition":"included","kind":"file","size":ladybom::inventory::FILE_LIMIT}));
    }
    let value = serde_json::json!({"schema_version":1,"entries":entries});
    let preview: Preview = serde_json::from_value(value.clone())?;
    assert!(preview.validate(&[]).is_err());
    let mut forged = value;
    forged["total_bytes"] = serde_json::json!(0);
    forged["exportable"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Preview>(forged).is_err());
    Ok(())
}
fn quota_preview(included: &[u64], disposition: Disposition, size: u64) -> Preview {
    use ladybom::inventory::PreviewEntry;
    let mut entries = std::collections::BTreeMap::new();
    // Refusal sorts first, deliberately independent of worker traversal order.
    entries.insert(
        "a-refused".into(),
        PreviewEntry {
            disposition,
            kind: EntryKind::File,
            size: Some(size),
        },
    );
    for (index, size) in included.iter().enumerate() {
        entries.insert(
            format!("z-admitted-{index}"),
            PreviewEntry {
                disposition: Disposition::Included,
                kind: EntryKind::File,
                size: Some(*size),
            },
        );
    }
    Preview {
        schema_version: 1,
        entries,
    }
}
#[test]
fn preview_rejects_impossible_and_wrong_precedence_quota_refusals() {
    let file = ladybom::inventory::FILE_LIMIT as u64;
    for disposition in [Disposition::FileCountLimit, Disposition::TotalSizeLimit] {
        assert!(quota_preview(&[], disposition, 0).validate(&[]).is_err());
        assert!(quota_preview(&[], disposition, 1).validate(&[]).is_err());
    }
    assert!(
        quota_preview(&vec![0; 5000], Disposition::FileCountLimit, file + 1)
            .validate(&[])
            .is_err()
    );
    assert!(
        quota_preview(&[file; 16], Disposition::TotalSizeLimit, file + 1)
            .validate(&[])
            .is_err()
    );
    assert!(quota_preview(&[file; 16], Disposition::FileCountLimit, 1)
        .validate(&[])
        .is_err());
    let mut full = vec![file; 15];
    full.push(file - 4984);
    full.extend(vec![1; 4984]);
    // Every admitted file is required to overflow bytes, so count refusal wins.
    assert!(quota_preview(&full, Disposition::TotalSizeLimit, 1)
        .validate(&[])
        .is_err());
}
#[test]
fn preview_accepts_justified_quota_refusals_without_lexical_admission_order() -> Result {
    let file = ladybom::inventory::FILE_LIMIT as u64;
    quota_preview(&[file; 16], Disposition::TotalSizeLimit, 1).validate(&[])?;
    quota_preview(&vec![0; 5000], Disposition::FileCountLimit, 0).validate(&[])?;
    let mut full = vec![file; 16];
    full.extend(vec![0; 4984]);
    // Bytes can overflow before the final zero-byte file fills the count quota.
    quota_preview(&full, Disposition::TotalSizeLimit, 1).validate(&[])?;
    Ok(())
}
