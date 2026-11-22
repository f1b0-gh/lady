use crate::error::{ensure, Error, Result};
use crate::{files, nickel::Evaluated};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, os::unix::fs::MetadataExt, path::Path};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentLock {
    pub schema_version: u32,
    pub platform: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ladybom_sha256: Option<String>,
    pub configuration: Evaluated,
    pub artifacts_sha256: BTreeMap<String, String>,
    pub recipes_sha256: BTreeMap<String, String>,
}
pub fn artifact_hash(path: &Path) -> Result<String> {
    let mut file = files::open_regular(path)?;
    let before = file.metadata()?;
    ensure!(before.len() <= 1024 * 1024 * 1024, "Artifact is too large");
    let mut magic = [0; 4];
    file.read_exact(&mut magic)?;
    ensure!(
        &magic == b"\x7fELF",
        "A native ELF binary is required: {}",
        path.display()
    );
    let mut hash = Sha256::new();
    hash.update(magic);
    let mut buffer = [0; 65536];
    let mut total = 4;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n;
        ensure!(total <= 1024 * 1024 * 1024, "Artifact is too large");
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    ensure!(
        before.len() == after.len()
            && total as u64 == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "Artifact changed while reading"
    );
    Ok(format!("{:x}", hash.finalize()))
}
pub fn create(
    configuration: Evaluated,
    resources: &Path,
    codex: &Path,
    code_mode: &Path,
) -> Result<EnvironmentLock> {
    ensure!(
        configuration.config.image == crate::config::Image::default(),
        "Native Codex artifacts require the native image profile"
    );
    let artifacts_sha256 = BTreeMap::from([
        ("codex".into(), artifact_hash(codex)?),
        ("codex-code-mode-host".into(), artifact_hash(code_mode)?),
    ]);
    let mut recipes_sha256 = BTreeMap::new();
    for name in [
        "flake.nix",
        "flake.lock",
        "build.nix",
        "image.nix",
        "dependencies.nix",
        "openssl.nix",
        "tpm2-tss.nix",
        "network-tools.nix",
    ] {
        recipes_sha256.insert(
            name.into(),
            files::hash(&files::read_limited(
                &resources.join("nix").join(name),
                1024 * 1024,
            )?),
        );
    }
    let audit = crate::sources::snapshot(
        resources,
        &crate::config::Sources {
            include: vec!["crates/ladyshell/resources/audit".into()],
            exclude: vec![],
        },
        None,
    )?;
    ensure!(
        audit.contains_key("crates/ladyshell/resources/audit/security-audit/SKILL.md"),
        "Missing audit distribution"
    );
    for (path, record) in audit {
        recipes_sha256.insert(path, record.sha256);
    }
    if configuration.config.audit.is_some() {
        for name in ["runtime.nix", "audit-build.nix", "audit-image.nix"] {
            recipes_sha256.insert(
                name.into(),
                files::hash(&files::read_limited(
                    &resources.join("nix").join(name),
                    1024 * 1024,
                )?),
            );
        }
        for (path, record) in crate::audit::image::runtime_sources(resources)? {
            recipes_sha256.insert(format!("runtime-source/{path}"), record.sha256);
        }
    }
    Ok(EnvironmentLock {
        schema_version: 1,
        platform: "x86_64-linux".into(),
        ladybom_sha256: None,
        configuration,
        artifacts_sha256,
        recipes_sha256,
    })
}
/// Lock the explicitly selected broker and receiver artifacts. No current-exe
/// inference or Codex artifact substitution is used for an embedding caller.
pub fn create_broker(
    configuration: Evaluated,
    resources: &Path,
    broker: &Path,
    runtime: &Path,
) -> Result<EnvironmentLock> {
    configuration.config.validate_broker()?;
    let artifacts_sha256 = BTreeMap::from([
        ("lo-executor-worker".into(), artifact_hash(broker)?),
        ("ladyshell".into(), artifact_hash(runtime)?),
    ]);
    let mut recipes_sha256 = BTreeMap::new();
    for name in [
        "flake.nix",
        "flake.lock",
        "broker-build.nix",
        "broker-image.nix",
        "openssl.nix",
    ] {
        recipes_sha256.insert(
            name.into(),
            files::hash(&files::read_limited(
                &resources.join("nix").join(name),
                1024 * 1024,
            )?),
        );
    }
    Ok(EnvironmentLock {
        schema_version: 1,
        platform: "x86_64-linux".into(),
        ladybom_sha256: None,
        configuration,
        artifacts_sha256,
        recipes_sha256,
    })
}
pub fn verify(path: &Path, expected: &EnvironmentLock) -> Result<()> {
    let data = files::read_limited(path, 8 * 1024 * 1024)
        .map_err(|e| e.context("Lock is missing or unreadable: run lock explicitly"))?;
    let actual: EnvironmentLock = serde_json::from_value(crate::json::parse(&data)?)?;
    if serde_json::to_value(actual)? != serde_json::to_value(expected)? {
        return Err(Error::LockMismatch { path: path.into() });
    }
    Ok(())
}
pub fn write(path: &Path, receipt: &EnvironmentLock) -> Result<()> {
    atomic_json(path, receipt)
}
pub fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    files::publish_json(path, value, true)
}

fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
