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
        assert_eq!(operation["phase"], "built");
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
    fn build(&mut self, _: &Value, _: &Path, _: Option<&Value>) -> Result<Value> {
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
