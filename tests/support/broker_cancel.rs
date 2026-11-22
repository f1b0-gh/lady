//! Faults exist only in this synthetic caller of the real native provisioning driver.
use ladyshell::{
    apply::{Driver, NativeDriver},
    error::{Error, Result},
    state, storage,
};
use serde_json::{json, Value};
use std::path::Path;
#[derive(Clone, Copy)]
pub enum Boundary {
    Creation,
    Validation,
    SealedInitialization,
}
struct Interrupted {
    native: NativeDriver,
    boundary: Boundary,
}
fn interrupted() -> Error {
    Error::InvalidInput {
        message: "synthetic caller interruption after native effect".into(),
    }
}
impl Driver for Interrupted {
    fn preflight(&mut self, d: &Value) -> Result<()> {
        self.native.preflight(d)
    }
    fn observe(&mut self, s: Option<&Value>) -> Result<Value> {
        self.native.observe(s)
    }
    fn sandbox(&mut self, n: &str) -> Result<Option<Value>> {
        self.native.sandbox(n)
    }
    fn build(&mut self, d: &Value, p: &Path, m: Option<&Value>) -> Result<Value> {
        self.native.build(d, p, m)
    }
    fn capture(&mut self, s: &Value, p: &Path) -> Result<Value> {
        self.native.capture(s, p)
    }
    fn create(&mut self, n: &str, b: &Value, o: &str, p: &str) -> Result<()> {
        self.native.create(n, b, o, p)
    }
    fn validate(&mut self, n: &str, b: &str) -> Result<Value> {
        self.native.validate(n, b)
    }
    fn restore(&mut self, s: &Value) -> Result<()> {
        self.native.restore(s)
    }
    fn prepare_storage(
        &mut self,
        p: &storage::Profile,
        d: &Path,
        o: &str,
        c: &Value,
    ) -> Result<Value> {
        self.native.prepare_storage(p, d, o, c)
    }
    fn verify_storage(&mut self, n: &str, e: &Value) -> Result<()> {
        self.native.verify_storage(n, e)
    }
    fn create_profile(&mut self, n: &str, b: &Value, o: &str, c: &Value) -> Result<()> {
        self.native.create_profile(n, b, o, c)?;
        if matches!(self.boundary, Boundary::Creation) {
            return Err(interrupted());
        }
        Ok(())
    }
    fn validate_profile(&mut self, n: &str, b: &Value) -> Result<Value> {
        let result = self.native.validate_profile(n, b)?;
        if matches!(self.boundary, Boundary::SealedInitialization) {
            let token = "f".repeat(64);
            let mut command = self.native.backend.command();
            command.args([
                "sandbox",
                "exec",
                "--no-tty",
                "--no-login-shell",
                n,
                "--",
                "/usr/local/bin/lo-executor-worker",
                "broker",
                "/var/lib/ladyshell/broker/control",
                "/var/lib/ladyshell/broker/artifacts",
                "/var/lib/ladyshell/broker/incoming",
            ]);
            let reply = ladyshell::process::capture_input(
                command,
                &serde_json::to_vec(
                    &json!({"format":1,"operation":{"kind":"seal","token":token}}),
                )?,
                std::time::Duration::from_secs(30),
                16384,
            )?;
            assert_eq!(
                ladyshell::json::parse(&reply)?,
                json!({"Ok":{"token":token,"accepting":false}})
            );
            let directory = Path::new(state::text(&b["storage"], "directory")?);
            std::fs::rename(
                directory.join("protocol.json"),
                directory.join("test-original-protocol.json"),
            )?;
            ladyshell::files::open_directory(directory)?.sync_all()?;
        }
        if !matches!(self.boundary, Boundary::Creation) {
            return Err(interrupted());
        }
        Ok(result)
    }
}
pub fn apply(desired: &Value, directory: &Path, boundary: Boundary) -> Result<Value> {
    let backend = ladyshell::openshell::Backend::new(&desired["context"])?;
    let lock = state::StateLock::acquire(directory)?;
    let lease = state::SessionLock::acquire(&lock.directory, true)?;
    let mut driver = Interrupted {
        native: NativeDriver {
            backend: backend.clone(),
        },
        boundary,
    };
    let error = ladyshell::apply::apply_with(desired, &lock.directory, &mut driver)
        .err()
        .ok_or_else(interrupted)?;
    assert!(
        error.to_string().contains("synthetic caller interruption"),
        "{error}"
    );
    assert!(state::load(&lock.directory)?.is_none());
    let operation = state::read(&lock.directory.join("operation.json"))?.ok_or_else(interrupted)?;
    let build = operation["build"].clone();
    let identity = backend
        .sandbox_identity(state::text(&operation, "sandbox_name")?)?
        .ok_or_else(interrupted)?;
    let binding =
        state::read(&Path::new(state::text(&build["storage"], "directory")?).join("binding.json"))?;
    assert_eq!(binding.is_some(), !matches!(boundary, Boundary::Creation));
    drop(lease);
    drop(lock);
    let args = ladyshell::request::Existing {
        state: directory.to_owned(),
    };
    let cancelled = ladyshell::destroy::cancel_broker(&args)?;
    assert_eq!(cancelled["cancelled"], true);
    assert!(backend
        .sandbox_identity(state::text(&operation, "sandbox_name")?)?
        .is_none());
    use storage::Driver as _;
    let receipts: Vec<storage::Receipt> =
        serde_json::from_value(build["storage"]["receipts"].clone())?;
    let mut docker = storage::PinnedDocker::from_identity(&build["storage"]["backend"]["docker"])?;
    for receipt in receipts {
        assert!(docker.observe(&receipt.intent().name())?.is_none());
    }
    match boundary {
        Boundary::Creation => assert!(cancelled["export"].is_null()),
        Boundary::Validation | Boundary::SealedInitialization => {
            let receipt: storage::export::Receipt =
                serde_json::from_value(cancelled["export"]["receipt"].clone())?;
            let archive = std::fs::File::open(state::text(&cancelled["export"], "path")?)?;
            assert_eq!(storage::export::verify(&receipt.request, archive)?, receipt);
        }
    }
    assert_eq!(ladyshell::destroy::cancel_broker(&args)?, cancelled);
    assert_eq!(
        state::read(&directory.join("operation.json"))?,
        Some(operation)
    );
    assert!(state::load(directory)?.is_none());
    let lock = state::StateLock::acquire(directory)?;
    let _lease = state::SessionLock::acquire(directory, true)?;
    assert!(ladyshell::apply::apply_with(desired, &lock.directory, &mut driver).is_err());
    ladyshell::environment_lock::atomic_json(
        &directory.join("cancellation-qualification.json"),
        &json!({"original_sandbox":identity,"bound_before_cancellation":binding.is_some(),"receipt":cancelled,"original_volumes_absent":true,"retry_idempotent":true,"operation_preserved":true}),
    )?;
    Ok(build)
}
