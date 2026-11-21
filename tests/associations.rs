use ladyshell::{associations, environment_lock::atomic_json};
use serde_json::json;
use std::{fs, io::Cursor, path::Path};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn seed(root: &Path, project: &Path, id: &str) -> ladyshell::error::Result<()> {
    ladyshell::state::create_directory(root)?;
    atomic_json(
        &root.join("state.json"),
        &json!({"schema_version":2,"sandbox_name":id,"sandbox_id":id,"policy_hash":"hash","codex_binary":"codex","owner":"owner","desired_hash":"desired","image_id":"image","project_snapshot":"snapshot","build_dir":"build","context":{"gateway":"gateway","workspace":"default"},"desired_inputs":{"project":project}}),
    )
}
#[test]
fn discovers_from_subdirectories_and_rejects_ambiguous_noninteractive_use() -> Result {
    let t = tempfile::tempdir()?;
    let registry = t.path().join("registry");
    let project = t.path().join("project");
    fs::create_dir_all(project.join("src"))?;
    let a = t.path().join("state-a");
    let b = t.path().join("state-b");
    seed(&a, &project, "first")?;
    seed(&b, &project, "second")?;
    associations::register_at(&registry, &a)?;
    let found = associations::candidates_at(&registry, &project.join("src"))?;
    assert_eq!(found.len(), 1);
    assert_eq!(
        associations::choose(&found, &mut Cursor::new(b""), &mut Vec::new(), false)?,
        a
    );
    associations::register_at(&registry, &b)?;
    let found = associations::candidates_at(&registry, &project)?;
    assert_eq!(found.len(), 2);
    assert!(associations::choose(&found, &mut Cursor::new(b""), &mut Vec::new(), false).is_err());
    assert_eq!(
        associations::choose(&found, &mut Cursor::new(b"2\n"), &mut Vec::new(), true)?,
        b
    );
    assert!(associations::choose(&found, &mut Cursor::new(b"0\n"), &mut Vec::new(), true).is_err());
    assert!(associations::candidates_at(&registry, t.path())?.is_empty());
    Ok(())
}
#[test]
fn detects_replaced_identity_and_does_not_follow_registry_links() -> Result {
    let t = tempfile::tempdir()?;
    let registry = t.path().join("registry");
    let project = t.path().join("project");
    fs::create_dir(&project)?;
    let a = t.path().join("state");
    seed(&a, &project, "first")?;
    associations::register_at(&registry, &a)?;
    seed(&a, &project, "replacement")?;
    assert!(associations::candidates_at(&registry, &project).is_err());
    associations::register_at(&registry, &a)?;
    assert_eq!(associations::candidates_at(&registry, &project)?.len(), 1);
    std::os::unix::fs::symlink(&registry, t.path().join("linked"))?;
    assert!(associations::candidates_at(&t.path().join("linked"), &project).is_err());
    Ok(())
}
#[test]
fn selected_association_is_rechecked_after_state_lock_acquisition() -> Result {
    let t = tempfile::tempdir()?;
    let registry = t.path().join("registry");
    let project = t.path().join("project");
    let other = t.path().join("other");
    fs::create_dir(&project)?;
    fs::create_dir(&other)?;
    let directory = t.path().join("state");
    seed(&directory, &project, "first")?;
    associations::register_at(&registry, &directory)?;
    let selected = associations::candidates_at(&registry, &project)?.remove(0);
    seed(&directory, &other, "replacement")?;
    let lock = ladyshell::state::StateLock::acquire(&directory)?;
    let current = ladyshell::state::load(&lock.directory)?.ok_or("missing state")?;
    assert!(selected.verify(&current).is_err());
    Ok(())
}

#[test]
fn independent_tasks_wait_for_short_registry_contention() -> Result {
    use std::{sync::mpsc, thread, time::Duration};
    let t = tempfile::tempdir()?;
    let registry = t.path().join("registry");
    let project = t.path().join("project");
    fs::create_dir(&project)?;
    let directory = t.path().join("state");
    seed(&directory, &project, "concurrent")?;
    let held = ladyshell::state::StateLock::acquire(&registry)?;
    let (send, receive) = mpsc::channel();
    let r = registry.clone();
    let worker = thread::spawn(move || {
        let result = associations::register_at(&r, &directory);
        let _ = send.send(result.map_err(|e| e.to_string()));
    });
    let before_release = receive.recv_timeout(Duration::from_millis(100));
    drop(held);
    assert!(
        before_release.is_err(),
        "Brief registry contention must wait, not fail: {before_release:?}"
    );
    receive
        .recv_timeout(Duration::from_secs(3))?
        .map_err(std::io::Error::other)?;
    worker.join().map_err(|_| "registry worker panicked")?;
    assert_eq!(associations::candidates_at(&registry, &project)?.len(), 1);
    Ok(())
}
