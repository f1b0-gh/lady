use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn sync_probe() -> Result<()> {
    let Some(dir) = std::env::var_os("LADYSHELL_UNIT_SYNC_FENCE") else {
        return Ok(());
    };
    let args = crate::request::SyncArgs {
        state: Some(dir.into()),
        dry_run: false,
        apply: true,
        export: false,
        json: false,
    };
    let refusal = crate::app::sync(&args)
        .err()
        .ok_or_else(|| invalid("Standalone sync crossed a retained fence"))?;
    println!("{refusal}");
    Ok(())
}

fn check_exclusion(pending: bool) -> Result<()> {
    let f = fixture_with_continuous(false)?;
    let root = f.root.path();
    let probe = root.join("openshell");
    fs::write(
        &probe,
        b"#!/bin/sh\nprintf 'called\\n' >> \"$HITS\"\nexit 1\n",
    )?;
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o700))?;
    let hits = root.join("backend-hits");
    let project = root.join("project");
    let backup = root.join("backup");
    let pending_path = f.state.join("checkout-pending.json");
    if pending {
        fs::create_dir(&backup)?;
        fs::write(project.join("original"), b"retain")?;
        let journal = json!({"schema_version":1,"sandbox_id":"sb","project":project,"export":root.join("export"),
          "backup":backup,"remote":{},"changes":[{"path":"original","before":{"sha256":files::hash(b"retain"),"executable":false},"after":null,
          "before_mode":fs::metadata(project.join("original"))?.permissions().mode() & 0o7777}]});
        files::publish_json(&pending_path, &journal, false)?;
    }
    let before = fs::read(f.state.join("state.json"))?;
    let original_pending = fs::read(&pending_path).ok();
    let worker = f.store.acquire_worker(&f.key)?;
    let record = f.store.inspect(&f.key)?;
    let lock = StateLock::acquire_existing(&f.state)?;
    let lease = SessionLock::acquire(&f.state, true)?;
    Fence::for_record(&f.store, &record).install(&lease)?;
    f.store.begin(&worker, 20)?;
    drop(lock);
    let probe = |reason: &str| -> Result<()> {
        let out = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "--nocapture",
                "execution::runtime::tests::standalone_sync::sync_probe",
            ])
            .env_clear()
            .env("PATH", root)
            .env("HITS", &hits)
            .env("LADYSHELL_UNIT_SYNC_FENCE", &f.state)
            .output()?;
        assert!(!hits.exists(), "standalone sync contacted the backend");
        assert_eq!(fs::read(f.state.join("state.json"))?, before);
        assert_eq!(fs::read(&pending_path).ok(), original_pending);
        if pending {
            assert_eq!(fs::read(project.join("original"))?, b"retain");
            assert!(!backup.join("receipt.json").exists());
        }
        assert!(
            out.status.success() && String::from_utf8_lossy(&out.stdout).contains(reason),
            "{out:?}"
        );
        Ok(())
    };
    probe("is busy (.sessions)")?;
    drop(lease);
    drop(worker);
    assert!(!f.store.worker_present(&f.key)?);
    probe("Retained execution fence blocks use of this environment")
}

#[test]
fn active_and_orphaned_dispatch_block_standalone_sync_backend() -> Result<()> {
    check_exclusion(false)
}
#[test]
fn active_and_orphaned_dispatch_block_pending_checkout_application() -> Result<()> {
    check_exclusion(true)
}
