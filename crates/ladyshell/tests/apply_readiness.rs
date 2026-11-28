use ladyshell::{
    apply::{apply_with, Driver},
    environment_lock::atomic_json,
    error::{Error, Result},
    plan,
};
use serde_json::{json, Value};
use std::{path::Path, time::Duration};
#[derive(Default)]
struct Simulated {
    creates: usize,
    resource: Option<Value>,
    timeout_create: bool,
    fail_create: bool,
    fail_preparation: bool,
    fail_spawn: bool,
    pending: usize,
    reads: usize,
}
fn unexpected() -> Error {
    Error::InvalidInput {
        message: "unexpected".into(),
    }
}
impl Driver for Simulated {
    fn prepare_creation(&mut self, _: &str, _: &Value, _: &str, _: &Value) -> Result<()> {
        if self.fail_preparation {
            Err(unexpected())
        } else {
            Ok(())
        }
    }
    fn observe(&mut self, _: Option<&Value>) -> Result<Value> {
        Ok(json!({"sandbox":null,"image_exists":false}))
    }
    fn sandbox(&mut self, _: &str) -> Result<Option<Value>> {
        self.reads += 1;
        let mut value = self.resource.clone();
        if self.pending > 0 && value.is_some() {
            self.pending -= 1;
            if let Some(value) = &mut value {
                value["phase"] = json!("Pending");
            }
        }
        Ok(value)
    }
    fn build(&mut self, _: &Value, _: &Path, _: Option<&Value>) -> Result<Value> {
        Ok(json!({"codex_binary":"binary"}))
    }
    fn capture(&mut self, _: &Value, _: &Path) -> Result<Value> {
        Err(unexpected())
    }
    fn create(&mut self, _: &str, _: &Value, owner: &str, _: &str) -> Result<()> {
        self.creates += 1;
        if self.fail_spawn {
            return Err(Error::ProcessSpawn {
                program: "openshell".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            });
        }
        if self.fail_create {
            return Err(unexpected());
        }
        self.resource = Some(
            json!({"id":"original","phase":"Ready","policy_hash":"policy","labels":{"ladyshell.owner":owner}}),
        );
        if self.timeout_create {
            return Err(Error::ProcessTimeout {
                program: "openshell".into(),
                timeout: Duration::from_secs(120),
            });
        }
        Ok(())
    }
    fn validate(&mut self, _: &str, _: &str) -> Result<Value> {
        Ok(json!({}))
    }
    fn restore(&mut self, _: &Value) -> Result<()> {
        Err(unexpected())
    }
    fn readiness_timeout(&self) -> Duration {
        Duration::from_millis(100)
    }
    fn readiness_poll_interval(&self) -> Duration {
        Duration::from_millis(1)
    }
}
fn prepare(root: &Path) -> Result<Value> {
    let desired = json!({"dependency_scan":{"complete":true,"missing":[]},
        "evaluated":{"config":{"sandbox":{"provider":"p"}}}});
    atomic_json(
        &root.join("plan.json"),
        &plan::plan(
            &desired,
            None,
            &json!({"sandbox":null,"image_exists":false}),
        )?,
    )?;
    Ok(desired)
}
#[test]
fn uncertain_creation_waits_for_the_original_resource_without_resubmission() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        timeout_create: true,
        pending: 4,
        ..Default::default()
    };
    let result = apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(result["sandbox_id"], "original");
    assert_eq!(driver.creates, 1);
    assert!(driver.reads >= 5);
    Ok(())
}
#[test]
fn interrupted_creation_is_never_resubmitted_when_observation_is_absent() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        fail_create: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    driver.fail_create = false;
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert_eq!(driver.creates, 1);
    Ok(())
}
#[test]
fn pending_resume_reuses_identity_and_terminal_or_foreign_resources_fail() -> Result<()> {
    for phase in ["Pending", "Error", "Ready"] {
        let root = tempfile::tempdir()?;
        let desired = prepare(root.path())?;
        let mut driver = Simulated {
            pending: usize::MAX,
            ..Default::default()
        };
        assert!(apply_with(&desired, root.path(), &mut driver).is_err());
        driver.pending = 0;
        let resource = driver.resource.as_mut().ok_or_else(unexpected)?;
        resource["phase"] = json!(phase);
        if phase == "Ready" {
            resource["labels"]["ladyshell.owner"] = json!("foreign");
        }
        assert!(apply_with(&desired, root.path(), &mut driver).is_err());
        assert_eq!(driver.creates, 1);
    }
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        pending: usize::MAX,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    driver.pending = 0;
    assert_eq!(
        apply_with(&desired, root.path(), &mut driver)?["sandbox_id"],
        "original"
    );
    assert_eq!(driver.creates, 1);
    Ok(())
}

#[test]
fn a_replaced_resource_with_the_same_owner_is_refused_after_resume() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        pending: usize::MAX,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    driver.pending = 0;
    driver.resource.as_mut().ok_or_else(unexpected)?["id"] = json!("replacement");
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert_eq!(driver.creates, 1);
    Ok(())
}

#[test]
fn pre_submission_failure_does_not_record_creation_or_prevent_recovery() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        fail_preparation: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    let journal =
        ladyshell::state::read(&root.path().join("operation.json"))?.ok_or_else(unexpected)?;
    assert_eq!(journal["creation_started"], false);
    assert_eq!(driver.creates, 0);
    driver.fail_preparation = false;
    apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(driver.creates, 1);
    Ok(())
}
#[test]
fn terminal_sandboxes_fail_without_consuming_the_readiness_budget() -> Result<()> {
    for phase in ["Error", "Stopped", "Completed", "Deleting", "Stopping"] {
        let root = tempfile::tempdir()?;
        let desired = prepare(root.path())?;
        let mut driver = Simulated {
            pending: usize::MAX,
            ..Default::default()
        };
        let error = apply_with(&desired, root.path(), &mut driver)
            .err()
            .ok_or_else(unexpected)?;
        assert!(matches!(error, Error::SandboxReadinessTimeout { .. }));
        driver.pending = 0;
        driver.resource.as_mut().ok_or_else(unexpected)?["phase"] = json!(phase);
        let reads = driver.reads;
        let error = apply_with(&desired, root.path(), &mut driver)
            .err()
            .ok_or_else(unexpected)?;
        assert!(
            matches!(error, Error::InvalidInput { .. }),
            "{phase}: {error}"
        );
        assert_eq!(driver.reads, reads + 1);
    }
    Ok(())
}

#[test]
fn a_definitive_spawn_failure_can_be_retried_without_an_uncertain_creation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = prepare(root.path())?;
    let mut driver = Simulated {
        fail_spawn: true,
        ..Default::default()
    };
    assert!(matches!(
        apply_with(&desired, root.path(), &mut driver),
        Err(Error::ProcessSpawn { .. })
    ));
    let journal =
        ladyshell::state::read(&root.path().join("operation.json"))?.ok_or_else(unexpected)?;
    assert_eq!(journal["creation_started"], false);
    driver.fail_spawn = false;
    apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(driver.creates, 2);
    Ok(())
}
