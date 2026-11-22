use super::*;
use crate::{error::Result, state, storage::export};
use serde_json::{json, Value};
use std::{fs::File, io::Write, path::Path};

struct Fixture {
    present: bool,
    fail_export: bool,
    fail_delete: bool,
    changed: bool,
    remaining_volumes: u8,
    fail_volumes: bool,
    exports: u32,
    deletes: u32,
    crash_delete: Option<std::path::PathBuf>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            present: true,
            fail_export: false,
            fail_delete: false,
            changed: false,
            remaining_volumes: 3,
            fail_volumes: false,
            exports: 0,
            deletes: 0,
            crash_delete: None,
        }
    }
}
impl Driver for Fixture {
    fn verify(&mut self, _: &Value) -> Result<()> {
        if self.changed || !self.present {
            return Err(invalid("Original runtime changed or missing"));
        }
        Ok(())
    }
    fn present(&mut self, _: &Value) -> Result<bool> {
        if self.changed {
            return Err(invalid("Original resource replaced"));
        }
        Ok(self.present)
    }
    fn seal(&mut self, _: &Value, _: &str) -> Result<()> {
        self.verify(&Value::Null)
    }
    fn export(&mut self, _: &Value, request: &export::Request, output: &mut File) -> Result<()> {
        self.exports += 1;
        if self.fail_export {
            self.fail_export = false;
            output.write_all(b"partial transport")?;
            return Err(invalid("transport lost"));
        }
        let mut tar = tar::Builder::new(output);
        let body = serde_json::to_vec(request)?;
        append(&mut tar, "broker-export.json", false, &body)?;
        for path in [
            "control",
            "control/.lifecycle",
            "control/uncertain",
            "artifacts",
            "incoming",
        ] {
            append(&mut tar, path, true, b"")?;
        }
        tar.finish()?;
        Ok(())
    }
    fn delete(&mut self, _: &Value) -> Result<()> {
        self.deletes += 1;
        self.present = false;
        if let Some(path) = &self.crash_delete {
            let mut file = File::create(path)?;
            file.write_all(b"original backend resource deleted")?;
            file.sync_all()?;
            crate::files::open_directory(
                path.parent().ok_or_else(|| invalid("backend directory"))?,
            )?
            .sync_all()?;
            std::process::exit(75);
        }
        if self.fail_delete {
            self.fail_delete = false;
            return Err(invalid("deletion reply lost"));
        }
        Ok(())
    }
    fn remove_storage(&mut self, _: &Value) -> Result<()> {
        if self.fail_volumes {
            self.fail_volumes = false;
            self.remaining_volumes -= 1;
            return Err(invalid("volume acknowledgement lost"));
        }
        self.remaining_volumes = 0;
        Ok(())
    }
}
fn append(tar: &mut tar::Builder<&mut File>, path: &str, dir: bool, body: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_path(path)?;
    header.set_entry_type(if dir {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_size(body.len() as u64);
    header.set_mode(if dir { 0o700 } else { 0o600 });
    header.set_uid(10001);
    header.set_gid(10001);
    header.set_mtime(0);
    header.set_cksum();
    tar.append(&header, body)?;
    Ok(())
}
fn request() -> export::Request {
    let limits = crate::storage::Limits {
        bytes: 65536,
        inodes: 32,
    };
    export::Request {
        format: 1,
        token: "a".repeat(64),
        profile: crate::storage::Profile {
            control: limits.clone(),
            artifacts: limits.clone(),
            incoming: limits,
        },
    }
}
fn current() -> Value {
    json!({"sandbox_id":"original", "sandbox_name":"owned", "owner":"a".repeat(32),
        "image_profile":"openshell-wasi", "desired_inputs":{"evaluated":{"config":{"storage":request().profile}}}})
}
fn lock(path: &Path) -> Result<state::StateLock> {
    state::StateLock::acquire(path)
}

#[test]
fn lost_delete_reply_and_partial_volume_cleanup_resume_without_reexport() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = lock(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    driver.fail_delete = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    assert!(ensure_available(&lock.directory).is_err());
    assert_eq!(driver.exports, 1);
    assert!(!driver.present);
    driver.fail_volumes = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    assert_eq!(driver.remaining_volumes, 2);
    let receipt = run(&lock, &current(), &mut driver)?;
    assert_eq!(receipt["deleted"], true);
    assert_eq!(driver.remaining_volumes, 0);
    assert_eq!(driver.exports, 1);
    assert_eq!(driver.deletes, 1);
    assert_eq!(run(&lock, &current(), &mut driver)?, receipt);
    assert!(lock.directory.join("broker-recovery/export.tar").is_file());
    Ok(())
}
#[test]
fn failed_transport_can_reuse_only_derived_staging_while_original_source_remains() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = lock(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    driver.fail_export = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    let scratch = lock.directory.join("broker-recovery/export.partial");
    assert_eq!(std::fs::read(&scratch)?, b"partial transport");
    assert_eq!(driver.deletes, 0);
    driver.changed = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    assert_eq!(std::fs::read(&scratch)?, b"partial transport");
    driver.changed = false;
    run(&lock, &current(), &mut driver)?;
    assert_eq!(driver.exports, 2);
    assert_eq!(driver.deletes, 1);
    assert!(!scratch.exists());
    Ok(())
}
#[test]
fn missing_runtime_without_deletion_intent_and_changed_state_are_refused() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = lock(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    driver.fail_export = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    let mut changed = current();
    changed["sandbox_id"] = json!("replacement");
    assert!(run(&lock, &changed, &mut driver).is_err());
    driver.present = false;
    assert!(run(&lock, &current(), &mut driver).is_err());
    assert_eq!(driver.remaining_volumes, 3);
    assert_eq!(driver.deletes, 0);
    Ok(())
}
#[test]
fn lost_or_corrupt_export_prevents_completion_even_after_sandbox_deletion() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = lock(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    driver.fail_delete = true;
    assert!(run(&lock, &current(), &mut driver).is_err());
    std::fs::write(
        lock.directory.join("broker-recovery/export.tar"),
        b"substituted",
    )?;
    assert!(run(&lock, &current(), &mut driver).is_err());
    assert_eq!(driver.remaining_volumes, 3);
    Ok(())
}

#[test]
fn managed_entry_points_refuse_even_corrupt_or_dangling_deletion_fences() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = lock(&root.path().join("state"))?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let fence = lock.directory.join("broker-destroy.json");
    std::fs::write(&fence, b"corrupt")?;
    assert!(crate::continuous::host::execution_directory(&lock.directory).is_err());
    std::fs::remove_file(&fence)?;
    std::os::unix::fs::symlink("absent", &fence)?;
    assert!(crate::continuous::host::execution_directory(&lock.directory).is_err());
    Ok(())
}

#[test]
fn abrupt_process_death_after_delete_effect_recovers_original_intent() -> Result<()> {
    const CHILD: &str = "LADYSHELL_DESTROY_CRASH_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        let lock = lock(Path::new(&directory))?;
        let _lease = state::SessionLock::acquire(&lock.directory, true)?;
        let mut driver = Fixture::new();
        driver.crash_delete = Some(lock.directory.join("backend-absent"));
        run(&lock, &current(), &mut driver)?;
        return Err(invalid("Expected abrupt exit before return"));
    }
    let root = tempfile::tempdir()?;
    let directory = root.path().join("state");
    let output = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "destroy::broker::tests::abrupt_process_death_after_delete_effect_recovers_original_intent", "--nocapture"])
        .env(CHILD, &directory).output()?;
    assert_eq!(output.status.code(), Some(75), "{output:?}");
    let lock = lock(&directory)?;
    let _lease = state::SessionLock::acquire(&directory, true)?;
    assert!(directory.join("backend-absent").is_file());
    assert!(directory.join("broker-recovery/export.tar").is_file());
    assert_eq!(
        state::read(&directory.join(JOURNAL))?
            .ok_or_else(|| invalid("Missing deletion journal"))?["phase"],
        "deleting"
    );
    let mut driver = Fixture::new();
    driver.present = false;
    let receipt = run(&lock, &current(), &mut driver)?;
    assert_eq!(receipt["deleted"], true);
    assert_eq!(driver.exports, 0);
    assert_eq!(driver.deletes, 0);
    assert_eq!(driver.remaining_volumes, 0);
    Ok(())
}

#[test]
fn hostile_archive_paths_preserve_original_source_and_refuse_deletion() -> Result<()> {
    for hardlink in [false, true] {
        let root = tempfile::tempdir()?;
        let lock = lock(&root.path().join("state"))?;
        let mut driver = Fixture::new();
        driver.fail_export = true;
        assert!(run(&lock, &current(), &mut driver).is_err());
        let scratch = lock.directory.join("broker-recovery/export.partial");
        let sentinel = root.path().join("sentinel");
        std::fs::write(&sentinel, b"preserve original")?;
        std::fs::remove_file(&scratch)?;
        if hardlink {
            std::fs::hard_link(&sentinel, &scratch)?;
        } else {
            std::os::unix::fs::symlink(&sentinel, &scratch)?;
        }
        assert!(run(&lock, &current(), &mut driver).is_err());
        assert_eq!(std::fs::read(&sentinel)?, b"preserve original");
        assert_eq!(driver.deletes, 0);
        assert_eq!(driver.remaining_volumes, 3);
    }
    Ok(())
}
