use super::*;
use crate::{error::Result, state::StateLock};
use serde_json::{json, Value};

struct Fixture {
    bound: bool,
    exists: bool,
    replacement: bool,
    lose_reply: bool,
    fail_export: bool,
    prepares: usize,
    deletes: usize,
    volumes: usize,
}
impl Fixture {
    fn new() -> Self {
        Self {
            bound: false,
            exists: true,
            replacement: false,
            lose_reply: true,
            fail_export: false,
            prepares: 0,
            deletes: 0,
            volumes: 3,
        }
    }
}
impl Driver for Fixture {
    fn prepare(&mut self, _: &StateLock, _: &Value) -> Result<Disposition> {
        self.prepares += 1;
        Ok(if self.bound {
            Disposition::Bound {
                current: json!({"sandbox_id":"original"}),
            }
        } else {
            Disposition::Unpublished {
                sandbox: Some(json!({"id":"original"})),
            }
        })
    }
    fn remove_unpublished(
        &mut self,
        _: &StateLock,
        _: &Value,
        identity: Option<&Value>,
    ) -> Result<()> {
        assert_eq!(identity, Some(&json!({"id":"original"})));
        if self.replacement {
            return Err(invalid("same-name replacement"));
        }
        if self.exists {
            self.exists = false;
            self.deletes += 1;
            if std::mem::take(&mut self.lose_reply) {
                return Err(invalid("delete reply lost"));
            }
        }
        Ok(())
    }
    fn remove_storage(&mut self, _: &StateLock, _: &Value) -> Result<()> {
        self.volumes = 0;
        Ok(())
    }
    fn destroy_bound(&mut self, _: &StateLock, current: &Value) -> Result<Value> {
        assert_eq!(current["sandbox_id"], "original");
        if self.fail_export {
            return Err(invalid("original export unavailable"));
        }
        Ok(json!({"deleted":true,"export":"verified original archive"}))
    }
}
fn operation() -> Value {
    json!({"owner":"a".repeat(32),"sandbox_name":"pending","desired_hash":"original"})
}
#[test]
fn unpublished_delete_reply_loss_resumes_without_readopting_identity() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = StateLock::acquire(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    assert!(run_with(&lock, &operation(), &mut driver).is_err());
    assert_eq!(driver.volumes, 3);
    assert!(crate::continuous::host::execution_directory(&lock.directory).is_err());
    let receipt = run_with(&lock, &operation(), &mut driver)?;
    assert_eq!(receipt["cancelled"], true);
    assert_eq!(driver.prepares, 1);
    assert_eq!(driver.deletes, 1);
    assert_eq!(driver.volumes, 0);
    assert_eq!(run_with(&lock, &operation(), &mut driver)?, receipt);
    Ok(())
}
#[test]
fn bound_generation_never_falls_back_to_unpublished_cleanup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = StateLock::acquire(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    driver.bound = true;
    driver.fail_export = true;
    assert!(run_with(&lock, &operation(), &mut driver).is_err());
    driver.bound = false;
    assert!(run_with(&lock, &operation(), &mut driver).is_err());
    assert_eq!(driver.prepares, 1);
    assert_eq!(driver.deletes, 0);
    assert_eq!(driver.volumes, 3);
    driver.fail_export = false;
    assert_eq!(
        run_with(&lock, &operation(), &mut driver)?["cancelled"],
        true
    );
    Ok(())
}
#[test]
fn changed_operation_and_replacement_refuse_before_storage_cleanup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let lock = StateLock::acquire(&root.path().join("state"))?;
    let mut driver = Fixture::new();
    assert!(run_with(&lock, &operation(), &mut driver).is_err());
    let mut changed = operation();
    changed["desired_hash"] = json!("changed");
    assert!(run_with(&lock, &changed, &mut driver).is_err());
    driver.replacement = true;
    assert!(run_with(&lock, &operation(), &mut driver).is_err());
    assert_eq!(driver.prepares, 1);
    assert_eq!(driver.volumes, 3);
    Ok(())
}
