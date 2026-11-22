use ladyshell::storage::{Driver, Intent, Receipt};
use ladyshell::storage::{Limits, Profile};
use serde_json::{json, Value};

#[derive(Default)]
struct Volumes {
    volumes: std::collections::BTreeMap<String, Value>,
    created: usize,
    deleted: usize,
    lose_create_reply: bool,
    lose_delete_reply: bool,
}
impl Driver for Volumes {
    fn observe(&mut self, name: &str) -> ladyshell::error::Result<Option<Value>> {
        Ok(self.volumes.get(name).cloned())
    }
    fn create(&mut self, intent: &Intent) -> ladyshell::error::Result<()> {
        assert!(!self.volumes.contains_key(&intent.name()));
        self.created += 1;
        self.volumes.insert(intent.name(), json!({"Name":intent.name(), "Driver":"local",
            "CreatedAt":format!("creation-{}", self.created), "Options":intent.options(), "Labels":intent.labels()}));
        if std::mem::take(&mut self.lose_create_reply) {
            return Err(ladyshell::error::Error::InvalidInput {
                message: "lost create reply".into(),
            });
        }
        Ok(())
    }
    fn delete(&mut self, original: &Receipt) -> ladyshell::error::Result<()> {
        let name = original.intent().name();
        if let Some(value) = self.volumes.get(&name) {
            original.verify(value)?;
        }
        self.volumes.remove(&name);
        self.deleted += 1;
        if std::mem::take(&mut self.lose_delete_reply) {
            return Err(ladyshell::error::Error::InvalidInput {
                message: "lost delete reply".into(),
            });
        }
        Ok(())
    }
}

#[test]
fn storage_recovery_preserves_partial_creates_and_deletes() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let storage = directory.path().join("storage");
    let owner = "a".repeat(32);
    let mut driver = Volumes {
        lose_create_reply: true,
        ..Volumes::default()
    };
    assert!(
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver).is_err()
    );
    assert_eq!(driver.created, 1);
    let receipts =
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver)?;
    assert_eq!(driver.created, 3);
    assert_eq!(receipts.len(), 3);
    assert_eq!(
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver)?,
        receipts
    );
    assert_eq!(driver.created, 3);
    let mut changed = profile();
    changed.artifacts.bytes *= 2;
    assert!(
        ladyshell::storage::prepare(&storage, &changed, &owner, "default", &mut driver).is_err()
    );
    driver.lose_delete_reply = true;
    assert!(ladyshell::storage::remove(&storage, &mut driver).is_err());
    assert_eq!(driver.deleted, 1);
    ladyshell::storage::remove(&storage, &mut driver)?;
    assert_eq!(driver.deleted, 3);
    assert!(driver.volumes.is_empty());
    ladyshell::storage::remove(&storage, &mut driver)?;
    assert_eq!(driver.deleted, 3);
    assert!(
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver).is_err()
    );
    Ok(())
}

#[test]
fn missing_or_replaced_retained_volume_is_never_recreated_or_deleted(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let storage = directory.path().join("storage");
    let mut driver = Volumes::default();
    let owner = "a".repeat(32);
    let receipts =
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver)?;
    let name = receipts[0].intent().name();
    let original = driver
        .volumes
        .remove(&name)
        .ok_or("missing original volume")?;
    assert!(
        ladyshell::storage::prepare(&storage, &profile(), &owner, "default", &mut driver).is_err()
    );
    assert_eq!(driver.created, 3);
    let mut replacement = original;
    replacement["CreatedAt"] = json!("replacement");
    driver.volumes.insert(name, replacement);
    assert!(ladyshell::storage::remove(&storage, &mut driver).is_err());
    assert_eq!(driver.deleted, 0);
    assert_eq!(driver.volumes.len(), 3);
    Ok(())
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
fn storage_scopes_have_distinct_fixed_mounts_and_explicit_caps(
) -> Result<(), Box<dyn std::error::Error>> {
    let intents = profile().intents(&"a".repeat(32), "default")?;
    assert_eq!(intents.len(), 3);
    let targets: std::collections::BTreeSet<_> = intents.iter().map(|i| i.target()).collect();
    let names: std::collections::BTreeSet<_> = intents.iter().map(|i| i.name()).collect();
    assert_eq!(targets.len(), 3);
    assert_eq!(names.len(), 3);
    assert_eq!(intents[0].target(), "/var/lib/ladyshell/broker/control");
    assert_eq!(
        intents[0].options()["o"],
        "size=65536,uid=10001,gid=10001,nr_inodes=128,mode=0700,nosuid,nodev"
    );
    for bad in [0, 4095, u64::MAX] {
        let mut p = profile();
        p.control.bytes = bad;
        assert!(p.intents(&"a".repeat(32), "default").is_err());
    }
    assert!(profile().intents("not-an-owner", "default").is_err());
    assert!(profile().intents(&"a".repeat(32), "../workspace").is_err());
    let mut value = serde_json::to_value(profile())?;
    value["fallback"] = json!("unbounded");
    assert!(serde_json::from_value::<Profile>(value).is_err());
    Ok(())
}

#[test]
fn original_volume_receipt_refuses_replacement_and_weakened_limits(
) -> Result<(), Box<dyn std::error::Error>> {
    let intents = profile().intents(&"a".repeat(32), "default")?;
    let intent = &intents[0];
    let observed = json!({"Name": intent.name(), "Driver":"local", "CreatedAt":"2026-11-22T12:00:00Z",
        "Options":intent.options(), "Labels":intent.labels()});
    let receipt = intent.observe(&observed)?;
    let restored =
        serde_json::from_value::<ladyshell::storage::Receipt>(serde_json::to_value(&receipt)?)?;
    restored.verify(&observed)?;
    for (pointer, value) in [
        ("/CreatedAt", json!("2026-11-22T12:00:01Z")),
        ("/Name", json!("different-volume")),
        ("/Driver", json!("unqualified")),
        (
            "/Options/o",
            json!("size=131072,uid=10001,gid=10001,nr_inodes=128,mode=0700,nosuid,nodev"),
        ),
        ("/Labels/ladyshell.owner", json!("b".repeat(32))),
        (
            "/Labels/openshell.ai~1sandbox-attachable-workspace",
            json!("another-workspace"),
        ),
    ] {
        let mut changed = observed.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing observation field")? = value;
        assert!(
            restored.verify(&changed).is_err(),
            "accepted replacement: {pointer}"
        );
    }
    let mut incomplete = observed;
    incomplete["CreatedAt"] = Value::Null;
    assert!(intent.observe(&incomplete).is_err());
    Ok(())
}

#[test]
fn published_cleanup_requires_the_original_complete_receipt_set(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("storage");
    let mut driver = Volumes::default();
    let receipts = ladyshell::storage::prepare(
        &directory,
        &profile(),
        &"a".repeat(32),
        "default",
        &mut driver,
    )?;
    assert!(ladyshell::storage::remove_original(&directory, &receipts[..2], &mut driver).is_err());
    let mut changed = receipts.clone();
    changed.swap(0, 1);
    assert!(ladyshell::storage::remove_original(&directory, &changed, &mut driver).is_err());
    assert_eq!(driver.deleted, 0);
    assert_eq!(
        ladyshell::state::read(&directory.join("storage.json"))?.ok_or("journal")?["deleting"],
        false
    );
    ladyshell::storage::remove_original(&directory, &receipts, &mut driver)?;
    assert_eq!(driver.deleted, 3);
    Ok(())
}

#[test]
fn partial_cleanup_checks_original_intents_before_adopting_lost_create_reply(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let directory = root.path().join("storage");
    let owner = "a".repeat(32);
    let mut driver = Volumes {
        lose_create_reply: true,
        ..Default::default()
    };
    assert!(
        ladyshell::storage::prepare(&directory, &profile(), &owner, "default", &mut driver)
            .is_err()
    );
    assert!(ladyshell::storage::remove_planned(
        &directory,
        &profile(),
        &"b".repeat(32),
        "default",
        &mut driver
    )
    .is_err());
    assert_eq!(driver.deleted, 0);
    ladyshell::storage::remove_planned(&directory, &profile(), &owner, "default", &mut driver)?;
    assert_eq!(driver.created, 1);
    assert_eq!(driver.deleted, 1);
    assert!(driver.volumes.is_empty());
    Ok(())
}
