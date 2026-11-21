use ladyshell::{
    merge::merge_files,
    sources::{FileRecord, Snapshot},
};
#[test]
fn merges_independent_changes_and_rejects_same_file_conflict(
) -> Result<(), Box<dyn std::error::Error>> {
    let base = Snapshot::from([(
        "a".into(),
        FileRecord {
            sha256: "base".into(),
            executable: false,
        },
    )]);
    let mut local = base.clone();
    local.insert(
        "b".into(),
        FileRecord {
            sha256: "local".into(),
            executable: false,
        },
    );
    let mut remote = base.clone();
    remote.insert(
        "a".into(),
        FileRecord {
            sha256: "remote".into(),
            executable: false,
        },
    );
    let merged = merge_files(&base, &local, &remote)?;
    assert_eq!(merged.len(), 2);
    assert_eq!(merged.get("a").ok_or("missing")?.origin, "remote");
    local.insert(
        "a".into(),
        FileRecord {
            sha256: "local".into(),
            executable: false,
        },
    );
    assert!(merge_files(&base, &local, &remote).is_err());
    assert!(merge_files(&base, &base, &Snapshot::new())?.is_empty());
    Ok(())
}
