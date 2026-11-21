use super::*;
use crate::environment_lock::atomic_json;
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
fn seed(root: &Path) -> Result<PathBuf> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let project = root.join("project");
    fs::create_dir_all(&project)?;
    let state = root.join("state");
    crate::state::create_directory(&state)?;
    atomic_json(
        &state.join("state.json"),
        &json!({"schema_version":2,"sandbox_name":"one","sandbox_id":"one","policy_hash":"hash","codex_binary":"codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"gateway","workspace":"default"},"desired_inputs":{"project":project}}),
    )?;
    let source = root.join("associations");
    associations::register_at(&source, &state)?;
    Ok(source)
}
#[test]
fn refuses_foreign_future_and_corrupt_databases_without_resetting_them() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let c = Connection::open(&path)?;
    c.execute_batch("PRAGMA user_version=99;")?;
    drop(c);
    let before = fs::read(&path)?;
    assert!(registry.list(&Filter::default()).is_err());
    assert!(registry.refresh(&source).is_err());
    assert_eq!(files::hash(&fs::read(&path)?), files::hash(&before));
    let c = Connection::open(&path)?;
    c.execute_batch("PRAGMA user_version=1; PRAGMA application_id=123;")?;
    drop(c);
    let before = fs::read(&path)?;
    assert!(registry.refresh(&source).is_err());
    assert_eq!(files::hash(&fs::read(&path)?), files::hash(&before));
    fs::write(&path, b"invalid SQLite")?;
    assert!(registry.refresh(&source).is_err());
    assert_eq!(fs::read(&path)?, b"invalid SQLite");
    Ok(())
}
#[test]
fn cannot_mix_association_sources() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let registry = Registry::new(root.path().join("catalog.sqlite3"))?;
    registry.refresh(&source)?;
    assert!(registry
        .refresh(&root.path().join("different-source"))
        .is_err());
    assert_eq!(registry.list(&Filter::default())?.instances.len(), 1);
    Ok(())
}
#[test]
fn transaction_rolls_back_changes_when_history_cannot_be_written() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let id = registry.list(&Filter::default())?.instances[0].id.clone();
    let c = Connection::open(&path)?;
    c.execute_batch("CREATE TRIGGER fail_history BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'fixture refusal'); END;")?;
    drop(c);
    assert!(registry
        .annotate(
            &id,
            &Annotation {
                note: Some("must roll back".into()),
                ..Annotation::default()
            }
        )
        .is_err());
    assert!(registry.get(&id)?.metadata.note.is_empty());
    assert_eq!(registry.history(&id, 0, 100)?.events.len(), 1);
    Ok(())
}
#[test]
fn reads_leave_existing_database_and_directory_unchanged() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("db/catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let before = fs::read(&path)?;
    let entries_before = fs::read_dir(root.path().join("db"))?.count();
    let id = registry.list(&Filter::default())?.instances[0].id.clone();
    registry.get(&id)?;
    registry.history(&id, 0, 100)?;
    assert_eq!(files::hash(&fs::read(&path)?), files::hash(&before));
    assert_eq!(
        fs::read_dir(root.path().join("db"))?.count(),
        entries_before
    );
    Ok(())
}
#[test]
fn private_directory_and_database_permissions_are_required() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("db/catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(registry.get(&"a".repeat(64)).is_err());
    assert!(registry.refresh(&source).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(root.path().join("db"), fs::Permissions::from_mode(0o755))?;
    assert!(registry.refresh(&source).is_err());
    Ok(())
}
#[test]
fn refresh_waits_for_writer_before_observing_sources() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let mut c = Connection::open(&path)?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let r = registry.clone();
    let s = source.clone();
    let (started, received) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let _ = started.send(());
        r.refresh(&s)
    });
    received.recv()?;
    std::thread::sleep(std::time::Duration::from_millis(150));
    atomic_json(
        &root.path().join("state/destroy.json"),
        &json!({"schema_version":1,"sandbox_name":"one","sandbox_id":"one","context":{"gateway":"gateway","workspace":"default"},"owner":"owner","deleted":true}),
    )?;
    tx.commit()?;
    thread.join().map_err(|_| "worker panicked")??;
    assert!(registry.list(&Filter::default())?.instances.is_empty());
    assert_eq!(
        registry
            .list(&Filter {
                include_deleted: true,
                ..Filter::default()
            })?
            .instances[0]
            .observation
            .recorded_status,
        RecordedStatus::Deleted
    );
    Ok(())
}

#[test]
fn wal_header_without_sidecars_is_rejected_without_creating_them() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let c = Connection::open(&path)?;
    c.execute_batch("PRAGMA journal_mode=WAL;")?;
    drop(c);
    let before = fs::read(&path)?;
    assert!(!root.path().join("catalog.sqlite3-wal").exists());
    assert!(registry.list(&Filter::default()).is_err());
    assert!(!root.path().join("catalog.sqlite3-wal").exists());
    assert!(!root.path().join("catalog.sqlite3-shm").exists());
    assert!(registry.refresh(&source).is_err());
    assert_eq!(files::hash(&fs::read(&path)?), files::hash(&before));
    Ok(())
}

#[test]
#[ignore = "Synthetic crash worker, invoked only by the parent interruption test"]
fn interrupted_foreign_write_worker() -> TestResult {
    let Some(path) = std::env::var_os("LADYSHELL_TEST_CRASH_DATABASE") else {
        return Ok(());
    };
    let mut c = Connection::open(path)?;
    if std::env::var_os("LADYSHELL_TEST_CRASH_OWN").is_some() {
        c.execute_batch("PRAGMA cache_size=1;")?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("UPDATE instances SET metadata=hex(zeroblob(20000));")?;
        std::process::exit(0);
    }
    c.execute_batch(
        "PRAGMA cache_size=1; CREATE TABLE fixture (id INTEGER PRIMARY KEY, data BLOB);
        INSERT INTO fixture(data) VALUES (zeroblob(10000));",
    )?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch("UPDATE fixture SET data=randomblob(10000);")?;
    // Deliberately skip Rust destructors to leave a hot rollback journal.
    std::process::exit(0)
}

#[test]
fn foreign_hot_journal_is_refused_without_recovery_or_deletion() -> TestResult {
    use std::os::unix::fs::OpenOptionsExt;
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("foreign.sqlite3");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let worker = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "management::tests::interrupted_foreign_write_worker",
            "--ignored",
        ])
        .env("LADYSHELL_TEST_CRASH_DATABASE", &path)
        .output()?;
    assert!(worker.status.success(), "{worker:?}");
    let journal = root.path().join("foreign.sqlite3-journal");
    let before = fs::read(&path)?;
    let before_journal = fs::read(&journal)?;
    assert!(!before_journal.is_empty());
    let registry = Registry::new(&path)?;
    assert!(registry.refresh(&source).is_err());
    assert_eq!(files::hash(&fs::read(&path)?), files::hash(&before));
    assert_eq!(
        files::hash(&fs::read(&journal)?),
        files::hash(&before_journal)
    );
    Ok(())
}

#[test]
fn interrupted_catalogue_write_recovers_without_losing_committed_metadata() -> TestResult {
    let root = tempfile::tempdir()?;
    let source = seed(root.path())?;
    let path = root.path().join("catalog.sqlite3");
    let registry = Registry::new(&path)?;
    registry.refresh(&source)?;
    let id = registry.list(&Filter::default())?.instances[0].id.clone();
    registry.annotate(
        &id,
        &Annotation {
            note: Some("committed note".into()),
            ..Annotation::default()
        },
    )?;
    let worker = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "management::tests::interrupted_foreign_write_worker",
            "--ignored",
        ])
        .env("LADYSHELL_TEST_CRASH_DATABASE", &path)
        .env("LADYSHELL_TEST_CRASH_OWN", "1")
        .output()?;
    assert!(worker.status.success(), "{worker:?}");
    assert!(root.path().join("catalog.sqlite3-journal").exists());
    registry.refresh(&source)?;
    assert_eq!(registry.get(&id)?.metadata.note, "committed note");
    assert_eq!(registry.history(&id, 0, 100)?.events.len(), 2);
    Ok(())
}
