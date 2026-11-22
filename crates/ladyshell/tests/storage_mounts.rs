use ladyshell::storage::{verify_mounts, Filesystem, Limits, Profile};
use serde_json::json;

#[test]
fn mounted_caps_require_original_volume_sources_and_independent_filesystems(
) -> Result<(), Box<dyn std::error::Error>> {
    let limit = Limits {
        bytes: 65536,
        inodes: 32,
    };
    let profile = Profile {
        control: limit.clone(),
        artifacts: limit.clone(),
        incoming: limit,
    };
    let intents = profile.intents(&"a".repeat(32), "default")?;
    let receipts = intents
        .iter()
        .map(|intent| {
            intent.observe(&json!({
                "Name":intent.name(), "Driver":"local", "Options":intent.options(),
                "Labels":intent.labels(), "CreatedAt":"2026-11-22T00:00:00Z"
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mounts = json!(intents.iter().map(|intent| json!({"Type":"volume", "Name":intent.name(), "Destination":intent.target(), "RW":true})).collect::<Vec<_>>());
    let stats = intents
        .iter()
        .enumerate()
        .map(|(index, intent)| Filesystem {
            target: intent.target().into(),
            device: index as u64 + 1,
            bytes: 65536,
            available_bytes: 65536,
            inodes: 32,
            available_inodes: 31,
        })
        .collect::<Vec<_>>();
    verify_mounts(&receipts, &mounts, &stats)?;
    let mut changed = mounts.clone();
    changed[0]["Name"] = json!("replacement");
    assert!(verify_mounts(&receipts, &changed, &stats).is_err());
    changed = mounts.clone();
    changed[0]["Type"] = json!("bind");
    assert!(verify_mounts(&receipts, &changed, &stats).is_err());
    changed = mounts.clone();
    changed[0]["RW"] = json!(false);
    assert!(verify_mounts(&receipts, &changed, &stats).is_err());
    let mut larger = stats.clone();
    larger[0].bytes *= 2;
    assert!(verify_mounts(&receipts, &mounts, &larger).is_err());
    larger = stats.clone();
    larger[0].inodes *= 2;
    assert!(verify_mounts(&receipts, &mounts, &larger).is_err());
    larger = stats.clone();
    larger[1].device = larger[0].device;
    assert!(verify_mounts(&receipts, &mounts, &larger).is_err());
    assert!(verify_mounts(&receipts, &mounts, &stats[..2]).is_err());
    assert!(verify_mounts(&receipts[..2], &mounts, &stats).is_err());
    let mut duplicate = mounts.clone();
    duplicate
        .as_array_mut()
        .ok_or("mounts")?
        .push(mounts[0].clone());
    assert!(verify_mounts(&receipts, &duplicate, &stats).is_err());
    let mut nested = mounts.clone();
    nested.as_array_mut().ok_or("mounts")?.push(json!({
        "Type":"bind", "Destination":format!("{}/escape", intents[0].target()), "RW":true
    }));
    assert!(verify_mounts(&receipts, &nested, &stats).is_err());
    let mut forged = stats;
    forged[0].available_bytes += 1;
    assert!(verify_mounts(&receipts, &mounts, &forged).is_err());
    Ok(())
}

#[test]
fn usage_warning_is_a_soft_observation_for_either_bytes_or_inodes() {
    let mut observation = Filesystem {
        target: "scope".into(),
        device: 1,
        bytes: 100,
        available_bytes: 21,
        inodes: 100,
        available_inodes: 21,
    };
    assert!(!observation.warning());
    observation.available_bytes = 20;
    assert!(observation.warning());
    observation.available_bytes = 100;
    observation.available_inodes = 20;
    assert!(observation.warning());
}
