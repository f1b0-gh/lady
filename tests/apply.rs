use ladyshell::{
    apply::{apply_with, Driver},
    environment_lock::atomic_json,
    error::{Error, Result},
    plan,
};
use serde_json::{json, Value};
use std::path::Path;
#[derive(Default)]
struct Fake {
    sandbox: Option<Value>,
    creates: usize,
    fail_validation: bool,
}
impl Driver for Fake {
    fn observe(&mut self, _: Option<&Value>) -> Result<Value> {
        Ok(json!({"sandbox":null,"image_exists":false}))
    }
    fn sandbox(&mut self, _: &str) -> Result<Option<Value>> {
        Ok(self.sandbox.clone())
    }
    fn build(&mut self, _: &Value, _: &Path, _: Option<&Value>) -> Result<Value> {
        Ok(
            json!({"image_id":"sha256:fake","archive":"/fake","policy_path":"/fake","build_dir":"/fake","project_snapshot":"/fake","host_sources":{},"codex_binary":"/fake"}),
        )
    }
    fn capture(&mut self, _: &Value, _: &Path) -> Result<Value> {
        Err(Error::InvalidInput {
            message: "not expected".into(),
        })
    }
    fn create(&mut self, _: &str, _: &Value, owner: &str, _: &str) -> Result<()> {
        self.creates += 1;
        self.sandbox = Some(
            json!({"id":"one","phase":"Ready","policy_hash":"policy","labels":{"ladyshell.owner":owner}}),
        );
        Ok(())
    }
    fn validate(&mut self, _: &str, _: &str) -> Result<Value> {
        if self.fail_validation {
            Err(Error::InvalidInput {
                message: "simulated interruption".into(),
            })
        } else {
            Ok(json!({}))
        }
    }
    fn restore(&mut self, _: &Value) -> Result<()> {
        Ok(())
    }
}
#[test]
fn resumes_creation_without_duplicates_after_interrupted_validation(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let desired = json!({"context":{"gateway":"g","workspace":"w"},"dependency_scan":{"complete":true,"missing":[]},"evaluated":{"config":{"sandbox":{"provider":"p"},"sync":{"mode":"files","destination":"exports"}}}});
    let observed = json!({"sandbox":null,"image_exists":false});
    atomic_json(
        &temp.path().join("plan.json"),
        &plan::plan(&desired, None, &observed)?,
    )?;
    let mut fake = Fake {
        fail_validation: true,
        ..Default::default()
    };
    assert!(apply_with(&desired, temp.path(), &mut fake).is_err());
    assert_eq!(fake.creates, 1);
    fake.fail_validation = false;
    let result = apply_with(&desired, temp.path(), &mut fake)?;
    assert_eq!(fake.creates, 1);
    assert_eq!(result["schema_version"], 2);
    assert_eq!(result["sandbox_id"], "one");
    Ok(())
}
