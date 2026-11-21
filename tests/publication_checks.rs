use ladyshell::{
    error::{Error, Result},
    publication_checks::{self, CheckPolicy, Driver},
    snapshot,
};
use serde_json::{json, Value};
use std::path::Path;
struct Verifier {
    root: tempfile::TempDir,
    mutate: bool,
    fail: bool,
    deleted: bool,
}
impl Driver for Verifier {
    fn create(&mut self, _: &Value, _: &Path) -> Result<Value> {
        Ok(
            json!({"sandbox_name":"verifier","sandbox_id":"separate","image_id":"sha256:test","policy_hash":"verified"}),
        )
    }
    fn install(&mut self, source: &Path) -> Result<()> {
        std::fs::copy(source.join("code.py"), self.root.path().join("code.py"))?;
        Ok(())
    }
    fn inventory(&mut self) -> Result<snapshot::Inventory> {
        snapshot::inventory(self.root.path())
    }
    fn check(&mut self, _: &[String], _: u32) -> Result<Vec<u8>> {
        if self.mutate {
            std::fs::write(self.root.path().join("code.py"), b"untested replacement\n")?;
        }
        if self.fail {
            Err(Error::InvalidInput {
                message: "check failed".into(),
            })
        } else {
            Ok(b"passed".to_vec())
        }
    }
    fn delete(&mut self) -> Result<()> {
        self.deleted = true;
        Ok(())
    }
}
fn exercise(
    mutate: bool,
    fail: bool,
) -> std::result::Result<(bool, bool, Value), Box<dyn std::error::Error>> {
    let d = tempfile::tempdir()?;
    let export = d.path().join("export");
    std::fs::create_dir_all(export.join("project"))?;
    std::fs::write(export.join("project/code.py"), b"print(1)\n")?;
    let inv = snapshot::inventory(&export.join("project"))?;
    let records: serde_json::Map<String, Value> = inv
        .iter()
        .map(|(p, e)| {
            (
                p.clone(),
                json!({"sha256":e.sha256,"executable":e.executable}),
            )
        })
        .collect();
    std::fs::write(
        export.join("manifest.json"),
        serde_json::to_vec(&json!({"schema_version":2,"files":records}))?,
    )?;
    let mut driver = Verifier {
        root: tempfile::tempdir()?,
        mutate,
        fail,
        deleted: false,
    };
    let policy = CheckPolicy {
        commands: vec![vec!["python3".into(), "-m".into(), "unittest".into()]],
        timeout: 30,
    };
    let result = publication_checks::verify_with(
        &json!({"sandbox_id":"agent"}),
        d.path(),
        &export,
        &policy,
        &mut driver,
    );
    let receipt: Value = serde_json::from_slice(&std::fs::read(export.join("checks.json"))?)?;
    Ok((result.is_ok(), driver.deleted, receipt))
}
#[test]
fn checks_bind_exact_snapshot_and_delete_verifier(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (ok, deleted, r) = exercise(false, false)?;
    assert!(ok && deleted);
    assert_eq!(r["passed"], true);
    assert!(r["snapshot_sha256"].as_str().is_some_and(|s| s.len() == 64));
    Ok(())
}
#[test]
fn provisioning_state_refuses_verifier_before_effects(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("continuous-staging.json"), b"{}")?;
    let mut driver = Verifier {
        root: tempfile::tempdir()?,
        mutate: false,
        fail: false,
        deleted: false,
    };
    let policy = CheckPolicy {
        commands: vec![vec!["true".into()]],
        timeout: 30,
    };
    let error = publication_checks::verify_with(
        &json!({}),
        directory.path(),
        &directory.path().join("missing-export"),
        &policy,
        &mut driver,
    )
    .err()
    .ok_or("provisioning verifier admitted")?;
    assert!(error.to_string().contains("provisioning state"));
    assert!(!driver.deleted);
    assert!(!directory.path().join("verification").exists());
    Ok(())
}
#[test]
fn source_mutation_during_checks_refuses_publication(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (ok, deleted, r) = exercise(true, false)?;
    assert!(!ok && deleted);
    assert_eq!(r["passed"], false);
    Ok(())
}
#[test]
fn failed_check_retains_evidence_and_deletes_verifier(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let (ok, deleted, r) = exercise(false, true)?;
    assert!(!ok && deleted);
    assert_eq!(r["passed"], false);
    Ok(())
}

struct Cleanup {
    observed: Option<Value>,
    removed: usize,
}
impl publication_checks::CleanupDriver for Cleanup {
    fn observe(&mut self, _: &Value) -> Result<Option<Value>> {
        Ok(self.observed.clone())
    }
    fn remove(&mut self, _: &Value) -> Result<()> {
        self.removed += 1;
        self.observed = None;
        Ok(())
    }
}
#[test]
fn interrupted_verifiers_are_removed_only_with_matching_ownership(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let d = root.path().join("state");
    let lock = ladyshell::state::StateLock::acquire(d.as_path())?;
    let path = d.as_path().join("lady-check-01234567.json");
    let intent = json!({"schema_version":1,"sandbox_name":"lady-check-01234567","sandbox_id":"original","owner":"our-owner","context":{"gateway":"test","workspace":"default"},"deleted":false});
    std::fs::write(&path, serde_json::to_vec(&intent)?)?;
    for (id, owner) in [("original", "other-owner"), ("replacement", "our-owner")] {
        let mut driver = Cleanup {
            observed: Some(json!({"id":id,"labels":{"ladyshell.owner":owner}})),
            removed: 0,
        };
        assert!(publication_checks::cleanup_with(&lock, &mut driver).is_err());
        assert_eq!(driver.removed, 0);
    }
    let mut driver = Cleanup {
        observed: Some(json!({"id":"original","labels":{"ladyshell.owner":"our-owner"}})),
        removed: 0,
    };
    let result = publication_checks::cleanup_with(&lock, &mut driver)?;
    assert_eq!(driver.removed, 1);
    assert_eq!(result["deleted"], 1);
    let receipt: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(receipt["deleted"], true);
    assert_eq!(receipt["sandbox_id"], "original");
    assert_eq!(
        publication_checks::cleanup_with(&lock, &mut driver)?["deleted"],
        0
    );
    assert_eq!(driver.removed, 1);
    Ok(())
}
#[test]
fn cleanup_recovers_create_intent_but_refuses_an_active_session(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let d = root.path().join("state");
    let lock = ladyshell::state::StateLock::acquire(d.as_path())?;
    let path = d.as_path().join("lady-check-01234567.json");
    std::fs::write(
        &path,
        serde_json::to_vec(
            &json!({"schema_version":1,"sandbox_name":"lady-check-01234567","owner":"ours","context":{"gateway":"test","workspace":"default"},"deleted":false}),
        )?,
    )?;
    let mut driver = Cleanup {
        observed: Some(json!({"id":"created-before-crash","labels":{"ladyshell.owner":"ours"}})),
        removed: 0,
    };
    let lease = ladyshell::state::SessionLock::acquire(d.as_path(), false)?;
    assert!(publication_checks::cleanup_with(&lock, &mut driver).is_err());
    assert_eq!(driver.removed, 0);
    drop(lease);
    assert_eq!(
        publication_checks::cleanup_with(&lock, &mut driver)?["deleted"],
        1
    );
    assert_eq!(driver.removed, 1);
    Ok(())
}
