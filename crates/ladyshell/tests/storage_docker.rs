//! Explicit host qualification; leaves the compact lifecycle journal for review.
use ladyshell::storage::{self, Docker, Driver, Limits, Profile};

#[test]
#[ignore = "requires Docker and explicit LADYSHELL_STORAGE_TEST_ROOT for retained journals"]
fn qualified_owned_volume_lifecycle_retains_receipts_and_reclaims_resources(
) -> Result<(), Box<dyn std::error::Error>> {
    let base = std::env::var_os("LADYSHELL_STORAGE_TEST_ROOT")
        .ok_or("explicit evidence directory required")?;
    let directory = tempfile::Builder::new()
        .prefix("volumes-")
        .tempdir_in(base)?
        .keep();
    let journal = directory.join("journal");
    let owner = ladyshell::files::hash(directory.as_os_str().as_encoded_bytes())[..32].to_owned();
    eprintln!("Storage qualification journal: {}", journal.display());
    let profile = Profile {
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
    };
    let intents = profile.intents(&owner, "default")?;
    let mut driver = Docker;
    let result =
        storage::prepare(&journal, &profile, &owner, "default", &mut driver).and_then(|receipts| {
            for receipt in &receipts {
                let value = driver.observe(&receipt.intent().name())?.ok_or_else(|| {
                    ladyshell::error::Error::InvalidInput {
                        message: "Created volume missing".into(),
                    }
                })?;
                receipt.verify(&value)?;
            }
            Ok(receipts)
        });
    // Attempt owned cleanup even when qualification fails. Never discard its
    // journal: a partial result must remain recoverable by the operator.
    let cleanup = storage::remove(&journal, &mut driver);
    let receipts = result?;
    cleanup?;
    assert_eq!(receipts.len(), 3);
    for intent in intents {
        assert!(driver.observe(&intent.name())?.is_none());
    }
    storage::remove(&journal, &mut driver)?;
    Ok(())
}
