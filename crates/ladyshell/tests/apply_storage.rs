use ladyshell::{
    apply::{apply_with, Driver},
    environment_lock::atomic_json,
    error::{Error, Result},
    plan,
};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Default)]
struct Unsupported {
    builds: usize,
    creates: usize,
}
impl Driver for Unsupported {
    fn observe(&mut self, _: Option<&Value>) -> Result<Value> {
        Ok(json!({"sandbox": null, "image_exists": false}))
    }
    fn sandbox(&mut self, _: &str) -> Result<Option<Value>> {
        Ok(None)
    }
    fn build(&mut self, _: &Value, _: &Path, _: Option<&Value>) -> Result<Value> {
        self.builds += 1;
        Err(Error::InvalidInput {
            message: "build must not run".into(),
        })
    }
    fn capture(&mut self, _: &Value, _: &Path) -> Result<Value> {
        Err(Error::InvalidInput {
            message: "unexpected operation".into(),
        })
    }
    fn create(&mut self, _: &str, _: &Value, _: &str, _: &str) -> Result<()> {
        self.creates += 1;
        Ok(())
    }
    fn validate(&mut self, _: &str, _: &str) -> Result<Value> {
        Err(Error::InvalidInput {
            message: "unexpected operation".into(),
        })
    }
    fn restore(&mut self, _: &Value) -> Result<()> {
        Err(Error::InvalidInput {
            message: "unexpected operation".into(),
        })
    }
}
fn desired() -> Value {
    json!({"context":{"gateway":"g","workspace":"w"},
        "dependency_scan":{"complete":true,"missing":[]},
        "evaluated":{"config":{"sandbox":{"provider":"p"},
            "storage":{"control":{"bytes":65536,"inodes":32},
                "artifacts":{"bytes":262144,"inodes":64},
                "incoming":{"bytes":262144,"inodes":64}},
            "sync":{"mode":"files","destination":"exports"}}}})
}
fn save_plan(directory: &Path, desired: &Value) -> Result<()> {
    atomic_json(
        &directory.join("plan.json"),
        &plan::plan(desired, None, &json!({"sandbox":null,"image_exists":false}))?,
    )
}
#[test]
fn unsupported_storage_refuses_before_build_or_any_resource_mutation() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = desired();
    save_plan(root.path(), &desired)?;
    let mut driver = Unsupported::default();
    let error = apply_with(&desired, root.path(), &mut driver)
        .err()
        .ok_or_else(|| Error::InvalidInput {
            message: "unsupported profile accepted".into(),
        })?;
    assert!(error.to_string().contains("storage"), "{error}");
    assert_eq!(driver.builds, 0);
    assert_eq!(driver.creates, 0);
    assert!(!root.path().join("operation.json").exists());
    Ok(())
}

#[derive(Default)]
struct Supported {
    resource: Option<Value>,
    creates: usize,
    fail_validation: bool,
    fail_publication: bool,
    fail_storage: bool,
    prepared: Option<Value>,
    checks: usize,
    broker: bool,
}
impl Driver for Supported {
    fn preflight_storage(&mut self, _: &ladyshell::storage::Profile, _: &Value) -> Result<()> {
        Ok(())
    }
    fn prepare_storage(
        &mut self,
        profile: &ladyshell::storage::Profile,
        directory: &Path,
        owner: &str,
        context: &Value,
    ) -> Result<Value> {
        let operation: Value = serde_json::from_slice(&std::fs::read(
            directory
                .parent()
                .ok_or_else(|| Error::InvalidInput {
                    message: "state parent missing".into(),
                })?
                .join("operation.json"),
        )?)?;
        assert_eq!(operation["owner"], owner);
        assert!(
            operation["phase"] == "built"
                || (self.broker
                    && (operation["phase"] == "validating" || operation["phase"] == "publishing"))
        );
        let evidence =
            json!({"profile":profile,"owner":owner,"context":context,"directory":directory});
        if let Some(original) = &self.prepared {
            assert_eq!(original, &evidence);
        }
        self.prepared = Some(evidence.clone());
        Ok(evidence)
    }
    fn verify_storage(&mut self, _: &str, evidence: &Value) -> Result<()> {
        self.checks += 1;
        assert_eq!(Some(evidence), self.prepared.as_ref());
        if self.fail_storage {
            return Err(Error::InvalidInput {
                message: "storage changed".into(),
            });
        }
        Ok(())
    }
    fn observe(&mut self, _: Option<&Value>) -> Result<Value> {
        Ok(json!({"sandbox": self.resource, "image_exists": self.resource.is_some()}))
    }
    fn sandbox(&mut self, _: &str) -> Result<Option<Value>> {
        Ok(self.resource.clone())
    }
    fn create_profile(
        &mut self,
        name: &str,
        build: &Value,
        owner: &str,
        config: &Value,
    ) -> Result<()> {
        if self.broker {
            assert!(config["sandbox"].get("provider").is_none());
            assert!(build.get("codex_binary").is_none());
        }
        self.create(name, build, owner, "unused by synthetic driver")
    }
    fn validate_profile(&mut self, name: &str, build: &Value) -> Result<Value> {
        let field = if self.broker {
            "broker_binary"
        } else {
            "codex_binary"
        };
        self.validate(name, ladyshell::state::text(build, field)?)
    }
    fn build(&mut self, _: &Value, _: &Path, _: Option<&Value>) -> Result<Value> {
        if self.broker {
            return Ok(
                json!({"image_profile":"openshell-worker-v1", "image_id":"image", "broker_binary":"/fake", "project_snapshot":"/fake", "build_dir":"/fake"}),
            );
        }
        Ok(
            json!({"image_id":"image","codex_binary":"/fake","project_snapshot":"/fake","build_dir":"/fake"}),
        )
    }
    fn capture(&mut self, _: &Value, _: &Path) -> Result<Value> {
        Err(Error::InvalidInput {
            message: "unexpected operation".into(),
        })
    }
    fn create(&mut self, _: &str, build: &Value, owner: &str, _: &str) -> Result<()> {
        assert_eq!(build.get("storage"), self.prepared.as_ref());
        self.creates += 1;
        self.resource = Some(
            json!({"id":"one","phase":"Ready","policy_hash":"policy","labels":{"ladyshell.owner":owner}}),
        );
        Ok(())
    }
    fn validate(&mut self, _: &str, _: &str) -> Result<Value> {
        if self.fail_validation {
            return Err(Error::InvalidInput {
                message: "validation interrupted".into(),
            });
        }
        Ok(json!({}))
    }
    fn restore(&mut self, _: &Value) -> Result<()> {
        Ok(())
    }
    fn published(&mut self, _: &Path) -> Result<()> {
        if self.fail_publication {
            return Err(Error::InvalidInput {
                message: "publication interrupted".into(),
            });
        }
        Ok(())
    }
}
#[test]
fn storage_is_retained_before_creation_and_rechecked_after_partial_publication() -> Result<()> {
    let root = tempfile::tempdir()?;
    let desired = desired();
    save_plan(root.path(), &desired)?;
    let mut driver = Supported {
        fail_validation: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert_eq!(driver.creates, 1);
    let op: Value = serde_json::from_slice(&std::fs::read(root.path().join("operation.json"))?)?;
    assert_eq!(op["build"].get("storage"), driver.prepared.as_ref());
    driver.fail_validation = false;
    driver.fail_publication = true;
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert_eq!(driver.checks, 1);
    driver.fail_publication = false;
    driver.fail_storage = true;
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    let op: Value = serde_json::from_slice(&std::fs::read(root.path().join("operation.json"))?)?;
    assert_eq!(op["phase"], "publishing");
    driver.fail_storage = false;
    let result = apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(result.get("storage"), driver.prepared.as_ref());
    assert_eq!(driver.creates, 1);
    assert_eq!(driver.checks, 3);
    // Even an empty reconciliation plan must freshly verify mounted storage.
    let observed = driver.observe(Some(&result))?;
    atomic_json(
        &root.path().join("plan.json"),
        &plan::plan(&desired, Some(&result), &observed)?,
    )?;
    driver.fail_storage = true;
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert_eq!(driver.checks, 4);
    Ok(())
}

#[test]
fn broker_publication_recovers_without_native_provider_or_codex_fields() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut desired = desired();
    desired["evaluated"]["config"]["sandbox"] = json!({});
    desired["evaluated"]["config"]["image"] =
        serde_json::to_value(ladyshell::config::Image::broker())?;
    save_plan(root.path(), &desired)?;
    let mut driver = Supported {
        broker: true,
        fail_publication: true,
        ..Default::default()
    };
    let error = apply_with(&desired, root.path(), &mut driver)
        .err()
        .ok_or_else(|| Error::InvalidInput {
            message: "publication failure ignored".into(),
        })?;
    assert!(
        error.to_string().contains("publication interrupted"),
        "{error}"
    );
    driver.fail_publication = false;
    let result = apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(driver.creates, 1);
    assert!(result.get("codex_binary").is_none());
    assert_eq!(ladyshell::state::load(root.path())?, Some(result));
    Ok(())
}

#[test]
fn broker_original_inputs_survive_failed_validation_before_state_publication() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut desired = desired();
    desired["evaluated"]["config"]["sandbox"] = json!({});
    desired["evaluated"]["config"]["image"] =
        serde_json::to_value(ladyshell::config::Image::broker())?;
    save_plan(root.path(), &desired)?;
    let mut driver = Supported {
        broker: true,
        fail_validation: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    assert!(ladyshell::state::load(root.path())?.is_none());
    let operation =
        ladyshell::state::read(&root.path().join("operation.json"))?.ok_or_else(|| {
            Error::InvalidInput {
                message: "missing operation".into(),
            }
        })?;
    assert_eq!(
        operation["phase"], "validating",
        "retain validation intent before any possible runtime binding"
    );
    assert_eq!(operation["desired_inputs"], desired);
    assert_eq!(operation["desired_hash"], plan::digest(&desired)?);
    Ok(())
}

#[test]
fn interrupted_publication_keeps_original_result_when_revalidation_fails() -> Result<()> {
    let root = tempfile::tempdir()?;
    let mut desired = desired();
    desired["evaluated"]["config"]["sandbox"] = json!({});
    desired["evaluated"]["config"]["image"] =
        serde_json::to_value(ladyshell::config::Image::broker())?;
    save_plan(root.path(), &desired)?;
    let mut driver = Supported {
        broker: true,
        fail_publication: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    let original =
        ladyshell::state::read(&root.path().join("operation.json"))?.ok_or_else(|| {
            Error::InvalidInput {
                message: "operation".into(),
            }
        })?;
    assert_eq!(original["phase"], "publishing");
    // Model death after retaining the result but before atomic state publication.
    std::fs::remove_file(root.path().join("state.json"))?;
    driver.fail_publication = false;
    driver.fail_validation = true;
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    let retained =
        ladyshell::state::read(&root.path().join("operation.json"))?.ok_or_else(|| {
            Error::InvalidInput {
                message: "operation".into(),
            }
        })?;
    assert_eq!(retained["phase"], "publishing");
    assert_eq!(retained["result"], original["result"]);
    Ok(())
}

#[test]
fn approved_plan_is_required_before_effects_and_during_interrupted_recovery() -> Result<()> {
    for broker in [false, true] {
        let root = project_temp()?;
        let mut desired = desired();
        if broker {
            desired["evaluated"]["config"]["sandbox"] = json!({});
            desired["evaluated"]["config"]["image"] =
                serde_json::to_value(ladyshell::config::Image::broker())?;
        }
        save_plan(root.path(), &desired)?;
        let saved = ladyshell::state::read(&root.path().join("plan.json"))?.ok_or_else(|| {
            Error::InvalidInput {
                message: "plan missing".into(),
            }
        })?;
        let expected = plan::digest(&saved)?;
        let mut driver = Supported {
            broker,
            fail_validation: true,
            ..Default::default()
        };
        let wrong = "0".repeat(64);
        assert!(
            ladyshell::apply::apply_with_expected(&desired, root.path(), &mut driver, &wrong)
                .is_err()
        );
        assert_eq!(driver.creates, 0);
        assert!(!root.path().join("operation.json").exists());
        assert!(ladyshell::apply::apply_with_expected(
            &desired,
            root.path(),
            &mut driver,
            &expected
        )
        .is_err());
        assert_eq!(driver.creates, 1);
        driver.fail_validation = false;
        // Even replacing plan.json cannot redirect an admitted recovery to another plan.
        let mut replacement = saved;
        replacement["review"] = json!("another approval");
        atomic_json(&root.path().join("plan.json"), &replacement)?;
        let replacement_digest = plan::digest(&replacement)?;
        assert!(ladyshell::apply::apply_with_expected(
            &desired,
            root.path(),
            &mut driver,
            &replacement_digest
        )
        .is_err());
        // The original journal is sufficient; a newly written plan cannot change it.
        let result =
            ladyshell::apply::apply_with_expected(&desired, root.path(), &mut driver, &expected)?;
        assert_eq!(result["sandbox_id"], "one");
        assert_eq!(driver.creates, 1);
        // A lost reply after completion observes that same original operation.
        assert_eq!(
            ladyshell::apply::apply_with_expected(&desired, root.path(), &mut driver, &expected)?,
            result
        );
        assert_eq!(driver.creates, 1);
    }
    Ok(())
}

#[test]
fn legacy_interrupted_operation_cannot_acquire_a_new_plan_approval() -> Result<()> {
    let root = project_temp()?;
    let desired = desired();
    save_plan(root.path(), &desired)?;
    let expected = plan::digest(&plan::plan(
        &desired,
        None,
        &json!({"sandbox":null,"image_exists":false}),
    )?)?;
    let mut driver = Supported {
        fail_validation: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, root.path(), &mut driver).is_err());
    driver.fail_validation = false;
    let error =
        ladyshell::apply::apply_with_expected(&desired, root.path(), &mut driver, &expected)
            .err()
            .ok_or_else(|| ladyshell::error::Error::InvalidInput {
                message: "legacy operation rebound".into(),
            })?;
    assert!(error.to_string().contains("reviewed plan"), "{error}");
    assert_eq!(driver.creates, 1);
    apply_with(&desired, root.path(), &mut driver)?;
    assert_eq!(driver.creates, 1);
    Ok(())
}

fn project_temp() -> Result<tempfile::TempDir> {
    let parent = std::path::Path::new("/tmp/lady");
    match std::fs::create_dir(parent) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    use std::os::unix::fs::MetadataExt;
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), std::fs::metadata(".")?.uid());
    Ok(tempfile::Builder::new()
        .prefix("approved-plan-")
        .tempdir_in(parent)?)
}
