//! Required checks on a frozen export in a separate, disposable OpenShell instance.
use crate::{
    environment_lock::atomic_json,
    error::{ensure, Error, Result},
    files, snapshot, state,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckPolicy {
    pub commands: Vec<Vec<String>>,
    pub timeout: u32,
}
impl CheckPolicy {
    pub fn parse(value: &Value) -> Result<Self> {
        let policy: Self = serde_json::from_value(value.clone())?;
        ensure!(
            (1..=86400).contains(&policy.timeout),
            "Check timeout must be between 1 and 86400 seconds"
        );
        ensure!(
            !policy.commands.is_empty() && policy.commands.len() <= 32,
            "Required checks must contain 1 to 32 commands"
        );
        for command in &policy.commands {
            ensure!(
                !command.is_empty()
                    && command.len() <= 128
                    && !command[0].is_empty()
                    && command
                        .iter()
                        .all(|a| a.len() <= 16384 && !a.contains('\0')),
                "Invalid required check command"
            );
        }
        Ok(policy)
    }
}
pub trait Driver {
    fn create(&mut self, current: &Value, directory: &Path) -> Result<Value>;
    fn install(&mut self, source: &Path) -> Result<()>;
    fn inventory(&mut self) -> Result<snapshot::Inventory>;
    fn check(&mut self, arguments: &[String], timeout: u32) -> Result<Vec<u8>>;
    fn delete(&mut self) -> Result<()>;
}
fn records(inventory: &snapshot::Inventory) -> Value {
    Value::Object(
        inventory
            .iter()
            .map(|(p, e)| {
                (
                    p.clone(),
                    json!({"sha256":e.sha256,"executable":e.executable}),
                )
            })
            .collect(),
    )
}
pub fn export_digest(export: &Path) -> Result<String> {
    let manifest = state::read(&export.join("manifest.json"))?
        .ok_or_else(|| invalid("Export manifest is missing".into()))?;
    ensure!(
        manifest["schema_version"] == 2,
        "Unsupported export manifest"
    );
    let actual = records(&snapshot::inventory(&export.join("project"))?);
    ensure!(
        actual == manifest["files"],
        "Export files or modes differ from manifest"
    );
    Ok(files::hash(&serde_json::to_vec(&actual)?))
}
pub fn revalidate(export: &Path, config: &Value) -> Result<()> {
    let policy = CheckPolicy::parse(config)?;
    let receipt = state::read(&export.join("checks.json"))?
        .ok_or_else(|| invalid("Required checks have not run for this export".into()))?;
    ensure!(
        receipt["schema_version"] == 1
            && receipt["passed"] == true
            && receipt["snapshot_sha256"] == export_digest(export)?
            && receipt["policy_sha256"] == files::hash(&serde_json::to_vec(&policy)?),
        "Required checks do not match the exact export and host policy"
    );
    Ok(())
}
pub fn verify(current: &Value, directory: &Path, export: &Path, config: &Value) -> Result<Value> {
    crate::continuous::host::execution_directory(directory)?;
    let policy = CheckPolicy::parse(config)?;
    let _verification = state::StateLock::acquire(&directory.join("verification"))?;
    cleanup_pending(directory, &mut NativeCleanup)?;
    let mut driver = Native::new(current, directory)?;
    verify_with(current, directory, export, &policy, &mut driver)
}
pub fn verify_with(
    current: &Value,
    directory: &Path,
    export: &Path,
    policy: &CheckPolicy,
    driver: &mut impl Driver,
) -> Result<Value> {
    crate::continuous::host::execution_directory(directory)?;
    CheckPolicy::parse(&serde_json::to_value(policy)?)?;
    crate::continuous::host::ensure_ready(current)?;
    if current.get("continuous").is_some() {
        let manifest = state::read(&export.join("manifest.json"))?
            .ok_or_else(|| invalid("Export manifest is missing".into()))?;
        crate::continuous::host::verify_export(current, &manifest)?;
    }
    let digest = export_digest(export)?;
    let frozen = tempfile::Builder::new()
        .prefix("checked-source-")
        .tempdir_in(directory)?;
    let inventory = snapshot::inventory(&export.join("project"))?;
    for (path, expected) in &inventory {
        let (entry, data) = snapshot::local_bytes(&export.join("project"), path)?;
        ensure!(&entry == expected, "Export changed while freezing checks");
        let target = frozen.path().join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, data)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(if entry.executable { 0o700 } else { 0o600 }),
        )?;
    }
    ensure!(
        snapshot::inventory(frozen.path())? == inventory,
        "Frozen source differs from export"
    );
    let mut receipt = json!({"schema_version":1,"export":export,"snapshot_sha256":digest,"policy_sha256":files::hash(&serde_json::to_vec(policy)?),"commands":policy.commands,"passed":false,"cleanup_confirmed":false,"results":[]});
    atomic_json(&export.join("checks.json"), &receipt)?;
    let checked = (|| -> Result<()> {
        let identity = driver.create(current, directory)?;
        ensure!(
            identity["sandbox_id"].is_string() && identity["sandbox_id"] != current["sandbox_id"],
            "Verifier must be a separate sandbox"
        );
        receipt["verifier"] = identity;
        atomic_json(&export.join("checks.json"), &receipt)?;
        driver.install(frozen.path())?;
        ensure!(
            driver.inventory()? == inventory,
            "Verifier did not receive the exact exported source"
        );
        for command in &policy.commands {
            let output = driver.check(command, policy.timeout)?;
            receipt["results"]
                .as_array_mut()
                .ok_or_else(|| invalid("Invalid check receipt".into()))?
                .push(
                    json!({"command":command,"output_sha256":files::hash(&output),"exit_code":0}),
                );
            ensure!(
                driver.inventory()? == inventory,
                "Required check changed the source snapshot"
            );
            atomic_json(&export.join("checks.json"), &receipt)?;
        }
        ensure!(
            export_digest(export)? == digest,
            "Export changed during required checks"
        );
        Ok(())
    })();
    let cleanup = driver.delete();
    receipt["cleanup_confirmed"] = json!(cleanup.is_ok());
    receipt["passed"] = json!(checked.is_ok() && cleanup.is_ok());
    if let Err(e) = &checked {
        receipt["error"] = json!(e.to_string());
    }
    if let Err(e) = &cleanup {
        receipt["cleanup_error"] = json!(e.to_string());
    }
    atomic_json(&export.join("checks.json"), &receipt)?;
    checked?;
    cleanup?;
    Ok(receipt)
}
struct Native {
    backend: crate::openshell::Backend,
    current: Value,
    directory: PathBuf,
    name: String,
    owner: String,
    identity: Option<Value>,
}
impl Native {
    fn new(current: &Value, directory: &Path) -> Result<Self> {
        let entropy = tempfile::Builder::new()
            .prefix("verifier-")
            .tempdir_in(directory)?;
        let owner = files::hash(entropy.path().as_os_str().as_encoded_bytes())[..32].to_owned();
        Ok(Self {
            backend: crate::openshell::Backend::new(&current["context"])?,
            current: current.clone(),
            directory: directory.to_owned(),
            name: format!("lady-check-{}", &owner[..8]),
            owner,
            identity: None,
        })
    }
    fn verified(&self) -> Result<Value> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| invalid("Verifier identity is missing".into()))?;
        self.backend.verify_execution(identity)
    }
    fn command(&self, args: &[String], timeout: u32) -> Result<std::process::Command> {
        self.verified()?;
        let mut command = self.backend.command();
        command.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/sandbox/workspace/project",
            "--timeout",
            &timeout.to_string(),
        ]);
        for variable in crate::openshell::SANDBOX_ENV {
            command.args(["--env", variable]);
        }
        command.arg(&self.name).arg("--").args(args);
        Ok(command)
    }
}
impl Driver for Native {
    fn create(&mut self, _: &Value, _: &Path) -> Result<Value> {
        let policy_path = self.directory.join(format!("{}-policy.json", self.name));
        let offline = self.current["sandbox_mode"] == "offline";
        let policy = if offline {
            crate::policy::offline_policy()
        } else {
            crate::policy::native_policy(state::text(&self.current, "codex_binary")?)?
        };
        atomic_json(&policy_path, &policy)?;
        let intent = json!({"schema_version":1,"sandbox_name":self.name,"owner":self.owner,"context":self.current["context"],"deleted":false});
        let journal = self.directory.join(format!("{}.json", self.name));
        atomic_json(&journal, &intent)?;
        self.backend.call(&[
            "sandbox",
            "create",
            "--name",
            &self.name,
            "--from",
            state::text(&self.current, "image_id")?,
            "--policy",
            policy_path
                .to_str()
                .ok_or_else(|| invalid("Invalid verifier path".into()))?,
            "--no-auto-providers",
            "--label",
            &format!("ladyshell.owner={}", self.owner),
            "--detach",
            "--",
            "/bin/sleep",
            "infinity",
        ])?;
        let observed = self
            .backend
            .sandbox(&self.name)?
            .ok_or_else(|| invalid("Verifier was not created".into()))?;
        let mut identity = json!({"sandbox_name":self.name,"sandbox_id":observed["id"],"owner":self.owner,"context":self.current["context"],"policy_hash":observed["policy_hash"],"codex_binary":self.current["codex_binary"],"image_id":self.current["image_id"],"desired_inputs":{"evaluated":{"config":{"sources":{"exclude":[]}}}}});
        if offline {
            identity["sandbox_mode"] = json!("offline");
            identity["desired_inputs"]["evaluated"]["config"]["sandbox"] =
                json!({"mode":"offline"});
        }
        self.identity = Some(identity.clone());
        self.verified()?;
        atomic_json(&journal, &identity)?;
        Ok(identity)
    }
    fn install(&mut self, source: &Path) -> Result<()> {
        let rm=self.command(&["/bin/sh".into(),"-c".into(),"rm -rf -- /sandbox/workspace/project/* /sandbox/workspace/project/.[!.]* /sandbox/workspace/project/..?*".into()],60)?;
        crate::process::capture(rm, Duration::from_secs(65), 1024 * 1024)
            .map_err(|e| e.context("Resetting verifier project contents"))?;
        let archive_file = tempfile::NamedTempFile::new_in(&self.directory)?;
        let mut archive = tar::Builder::new(archive_file.as_file());
        for (path, entry) in snapshot::inventory(source)? {
            let (_, bytes) = snapshot::local_bytes(source, &path)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(if entry.executable { 0o755 } else { 0o644 });
            header.set_cksum();
            archive.append_data(&mut header, path, bytes.as_slice())?;
        }
        archive.finish()?;
        drop(archive);
        archive_file.as_file().sync_all()?;
        self.verified()?;
        let remote = "/sandbox/workspace/ladyshell-checked-source.tar";
        let mut upload = self.backend.command();
        upload
            .args(["sandbox", "upload", "--no-git-ignore", &self.name])
            .arg(archive_file.path())
            .arg(remote);
        crate::process::capture(upload, Duration::from_secs(300), 1024 * 1024)
            .map_err(|e| e.context("Uploading frozen verifier source"))?;
        let command = self.command(
            &[
                "/bin/tar".into(),
                "-x".into(),
                "-f".into(),
                remote.into(),
                "-C".into(),
                "/sandbox/workspace/project".into(),
            ],
            120,
        )?;
        crate::process::capture(command, Duration::from_secs(125), 1024 * 1024)
            .map_err(|e| e.context("Installing frozen verifier source"))?;
        crate::process::capture(
            self.command(&["/bin/rm".into(), "--".into(), remote.into()], 30)?,
            Duration::from_secs(35),
            1024 * 1024,
        )?;
        Ok(())
    }
    fn inventory(&mut self) -> Result<snapshot::Inventory> {
        self.verified()?;
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| invalid("Verifier identity is missing".into()))?;
        crate::sync::observe_inventory(identity, &self.backend)
    }
    fn check(&mut self, arguments: &[String], timeout: u32) -> Result<Vec<u8>> {
        crate::process::capture(
            self.command(arguments, timeout)?,
            Duration::from_secs(u64::from(timeout) + 5),
            4 * 1024 * 1024,
        )
    }
    fn delete(&mut self) -> Result<()> {
        let observed = self.backend.sandbox_identity(&self.name)?;
        if let Some(observed) = observed {
            ensure!(
                observed["labels"]["ladyshell.owner"] == self.owner,
                "Verifier ownership changed; refusing deletion"
            );
            if let Some(identity) = &self.identity {
                ensure!(
                    observed["id"] == identity["sandbox_id"],
                    "Verifier identity changed; refusing deletion"
                );
            }
            self.backend.call(&["sandbox", "delete", &self.name])?;
            ensure!(
                self.backend.sandbox_identity(&self.name)?.is_none(),
                "Verifier deletion not confirmed"
            );
        }
        atomic_json(
            &self.directory.join(format!("{}.json", self.name)),
            &json!({"schema_version":1,"sandbox_name":self.name,"owner":self.owner,"identity":self.identity,"deleted":true}),
        )?;
        Ok(())
    }
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

/// Identity observations and deletion only; this interface never runs project code.
pub trait CleanupDriver {
    fn observe(&mut self, identity: &Value) -> Result<Option<Value>>;
    fn remove(&mut self, identity: &Value) -> Result<()>;
}
struct NativeCleanup;
impl CleanupDriver for NativeCleanup {
    fn observe(&mut self, identity: &Value) -> Result<Option<Value>> {
        crate::openshell::Backend::new(&identity["context"])?
            .sandbox_identity(state::text(identity, "sandbox_name")?)
    }
    fn remove(&mut self, identity: &Value) -> Result<()> {
        crate::openshell::Backend::new(&identity["context"])?.call(&[
            "sandbox",
            "delete",
            state::text(identity, "sandbox_name")?,
        ])?;
        Ok(())
    }
}
/// Recover verifiers left by a terminated controller, preserving their receipts.
pub fn cleanup(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    cleanup_with(&lock, &mut NativeCleanup)
}
pub fn cleanup_with(lock: &state::StateLock, driver: &mut impl CleanupDriver) -> Result<Value> {
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    let _verification = state::StateLock::acquire(&lock.directory.join("verification"))?;
    cleanup_pending(&lock.directory, driver)
}
fn cleanup_pending(directory: &Path, driver: &mut impl CleanupDriver) -> Result<Value> {
    let mut deleted = 0;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|p| p.to_str()) else {
            continue;
        };
        if !name.starts_with("lady-check-")
            || !name.ends_with(".json")
            || name.ends_with("-policy.json")
        {
            continue;
        }
        let mut intent =
            state::read(&path)?.ok_or_else(|| invalid("Verifier intent disappeared".into()))?;
        if intent["deleted"] == true {
            continue;
        }
        ensure!(
            name == format!("{}.json", state::text(&intent, "sandbox_name")?),
            "Verifier journal name changed"
        );
        let owner = state::text(&intent, "owner")?;
        ensure!(!owner.is_empty(), "Verifier owner is missing");
        if let Some(observed) = driver.observe(&intent)? {
            ensure!(
                observed["labels"]["ladyshell.owner"] == owner,
                "Verifier ownership changed; refusing deletion"
            );
            if let Some(id) = intent.get("sandbox_id") {
                ensure!(
                    id.is_string() && observed["id"] == *id,
                    "Verifier identity changed; refusing deletion"
                );
            }
            driver.remove(&intent)?;
            ensure!(
                driver.observe(&intent)?.is_none(),
                "Verifier deletion not confirmed"
            );
            deleted += 1;
        }
        intent["deleted"] = json!(true);
        intent["cleanup_recovered"] = json!(true);
        atomic_json(&path, &intent)?;
    }
    Ok(json!({"deleted":deleted,"evidence_retained":true}))
}

/// Check a retained export without rerunning its producing agent.
pub fn retained(directory: &Path, export: &Path, policy_path: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let project = Path::new(state::text(&current["desired_inputs"], "project")?);
    let export = files::absolute(export)?;
    ensure!(
        export.starts_with(
            lock.directory
                .join(state::text(&current["sync"], "destination")?)
        ),
        "Select an export retained by this state"
    );
    let manifest = state::read(&export.join("manifest.json"))?
        .ok_or_else(|| invalid("Export is missing".into()))?;
    ensure!(
        manifest["sandbox_id"] == current["sandbox_id"],
        "Export belongs to another sandbox"
    );
    let policy = crate::publication_policy::Policy::load(policy_path, project)?;
    let checks = policy
        .checks
        .as_ref()
        .ok_or_else(|| invalid("Host policy has no required checks".into()))?;
    verify(&current, &lock.directory, &export, checks)
}
