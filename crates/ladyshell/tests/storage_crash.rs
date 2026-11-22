//! Kill the provisioning client after the resource effect, before its receipt.
use ladyshell::{
    error::{Error, Result},
    storage::{self, Driver, Intent, Limits, Profile, Receipt},
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
};

struct Files {
    root: PathBuf,
    crash: String,
}
impl Driver for Files {
    fn observe(&mut self, name: &str) -> Result<Option<Value>> {
        match fs::read(self.root.join(name)) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    fn create(&mut self, intent: &Intent) -> Result<()> {
        let value = json!({"Name":intent.name(), "Driver":"local", "CreatedAt":"original",
            "Options":intent.options(), "Labels":intent.labels()});
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.root.join(intent.name()))?;
        file.write_all(&serde_json::to_vec(&value)?)?;
        file.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        if self.crash == "create" {
            std::process::exit(71);
        }
        Ok(())
    }
    fn delete(&mut self, receipt: &Receipt) -> Result<()> {
        let name = receipt.intent().name();
        receipt.verify(&self.observe(&name)?.ok_or_else(|| Error::InvalidInput {
            message: "Missing original resource".into(),
        })?)?;
        fs::remove_file(self.root.join(name))?;
        File::open(&self.root)?.sync_all()?;
        if self.crash == "delete" {
            std::process::exit(72);
        }
        Ok(())
    }
}
fn profile() -> Profile {
    Profile {
        control: Limits {
            bytes: 65536,
            inodes: 128,
        },
        artifacts: Limits {
            bytes: 262144,
            inodes: 128,
        },
        incoming: Limits {
            bytes: 262144,
            inodes: 128,
        },
    }
}

#[test]
fn process_death_between_resource_effect_and_receipt_recovers_original_intents(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "LADYSHELL_STORAGE_CRASH_DIRECTORY";
    let owner = "a".repeat(32);
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let mode = std::env::var("LADYSHELL_STORAGE_CRASH_MODE")?;
        let mut driver = Files {
            root: root.join("resources"),
            crash: mode.clone(),
        };
        if mode == "create" {
            storage::prepare(
                &root.join("journal"),
                &profile(),
                &owner,
                "default",
                &mut driver,
            )?;
        } else if mode == "delete" {
            storage::remove(&root.join("journal"), &mut driver)?;
        }
        return Err("crash point was not reached".into());
    }
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    fs::create_dir(root.join("resources"))?;
    let crash = |mode, expected| -> std::result::Result<(), Box<dyn std::error::Error>> {
        let status = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "process_death_between_resource_effect_and_receipt_recovers_original_intents",
            ])
            .env(CHILD, root)
            .env("LADYSHELL_STORAGE_CRASH_MODE", mode)
            .status()?;
        assert_eq!(status.code(), Some(expected));
        Ok(())
    };
    crash("create", 71)?;
    let journal: Value = serde_json::from_slice(&fs::read(root.join("journal/storage.json"))?)?;
    assert!(journal["entries"][0]["receipt"].is_null());
    assert_eq!(fs::read_dir(root.join("resources"))?.count(), 1);
    let mut driver = Files {
        root: root.join("resources"),
        crash: String::new(),
    };
    let receipts = storage::prepare(
        &root.join("journal"),
        &profile(),
        &owner,
        "default",
        &mut driver,
    )?;
    assert_eq!(receipts.len(), 3);
    assert_eq!(fs::read_dir(root.join("resources"))?.count(), 3);
    crash("delete", 72)?;
    let journal: Value = serde_json::from_slice(&fs::read(root.join("journal/storage.json"))?)?;
    assert_eq!(journal["deleting"], true);
    assert_eq!(journal["entries"][0]["deleted"], false);
    assert_eq!(fs::read_dir(root.join("resources"))?.count(), 2);
    storage::remove(&root.join("journal"), &mut driver)?;
    assert_eq!(fs::read_dir(root.join("resources"))?.count(), 0);
    storage::remove(&root.join("journal"), &mut driver)?;
    Ok(())
}
