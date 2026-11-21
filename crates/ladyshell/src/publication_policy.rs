//! Explicit host-only publication policy. No project file selects signing authority.
use crate::{
    error::{ensure, Result},
    files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    #[serde(default)]
    pub signing: Option<Signing>,
    #[serde(default)]
    pub checks: Option<Value>,
    #[serde(skip)]
    pub digests: BTreeMap<PathBuf, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signing {
    pub key: PathBuf,
    pub allowed_signers: PathBuf,
    pub principal: String,
    pub program: PathBuf,
    #[serde(default)]
    pub revocation_file: Option<PathBuf>,
}
impl Policy {
    pub fn load(path: &Path, project: &Path) -> Result<Self> {
        let path = std::fs::canonicalize(path)?;
        ensure!(
            !path.starts_with(project),
            "Publication policy must be outside the project"
        );
        let bytes = files::read_limited(&path, 1024 * 1024)?;
        let mut policy: Self = serde_json::from_value(crate::json::parse(&bytes)?)?;
        ensure!(
            policy.schema_version == 1,
            "Unsupported publication policy schema"
        );
        policy.digests.insert(path, files::hash(&bytes));
        if let Some(checks) = &policy.checks {
            crate::publication_checks::CheckPolicy::parse(checks)?;
        }
        if let Some(signing) = &policy.signing {
            ensure!(
                !signing.principal.is_empty()
                    && signing.principal.len() <= 1024
                    && !signing.principal.chars().any(char::is_whitespace),
                "A single signing principal is required"
            );
            for path in [&signing.key, &signing.allowed_signers, &signing.program]
                .into_iter()
                .chain(signing.revocation_file.as_ref())
            {
                ensure!(path.is_absolute(), "Signing paths must be absolute");
                let canonical = std::fs::canonicalize(path)?;
                ensure!(
                    !canonical.starts_with(project),
                    "Signing authority must remain outside the project"
                );
                policy.digests.insert(
                    path.clone(),
                    files::hash(&files::read_limited(path, 32 * 1024 * 1024)?),
                );
            }
            signing.preflight()?;
        }
        policy.verify_inputs()?;
        Ok(policy)
    }
    pub fn verify_inputs(&self) -> Result<()> {
        for (path, expected) in &self.digests {
            ensure!(
                files::hash(&files::read_limited(path, 32 * 1024 * 1024)?) == *expected,
                "Publication policy input changed: {}",
                path.display()
            );
        }
        Ok(())
    }
}
impl Signing {
    fn preflight(&self) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let message = temp.path().join("preflight");
        let bytes = b"Ladyshell explicit host signing preflight\n";
        std::fs::write(&message, bytes)?;
        let mut sign = Command::new(&self.program);
        sign.args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&self.key)
            .arg(&message);
        crate::process::capture(sign, Duration::from_secs(15), 65536)?;
        let mut verify = Command::new(&self.program);
        verify
            .args(["-Y", "verify", "-n", "git", "-f"])
            .arg(&self.allowed_signers)
            .arg("-I")
            .arg(&self.principal)
            .arg("-s")
            .arg(temp.path().join("preflight.sig"));
        if let Some(path) = &self.revocation_file {
            verify.arg("-r").arg(path);
        }
        crate::process::capture_input(verify, bytes, Duration::from_secs(15), 65536)?;
        Ok(())
    }
    pub(crate) fn verify_commit(&self, git: &crate::publish::Git, commit: &str) -> Result<()> {
        git.call(&["verify-commit", commit])?;
        let raw = git.call(&["cat-file", "commit", commit])?;
        let mut unsigned = Vec::new();
        let mut signature = Vec::new();
        let mut headers = true;
        let mut in_signature = false;
        for line in raw.split_inclusive(|b| *b == b'\n') {
            if headers && line.starts_with(b"gpgsig ") {
                ensure!(
                    signature.is_empty(),
                    "Multiple commit signatures are unsupported"
                );
                signature.extend_from_slice(&line[7..]);
                in_signature = true;
            } else if headers && in_signature && line.starts_with(b" ") {
                signature.extend_from_slice(&line[1..]);
            } else {
                in_signature = false;
                if line == b"\n" {
                    headers = false;
                }
                unsigned.extend_from_slice(line);
            }
        }
        ensure!(
            signature.starts_with(b"-----BEGIN SSH SIGNATURE-----\n"),
            "An SSH commit signature is required"
        );
        let temp = tempfile::tempdir()?;
        let signature_path = temp.path().join("commit.sig");
        std::fs::write(&signature_path, signature)?;
        let mut verify = Command::new(&self.program);
        verify
            .args(["-Y", "verify", "-n", "git", "-f"])
            .arg(&self.allowed_signers)
            .arg("-I")
            .arg(&self.principal)
            .arg("-s")
            .arg(signature_path);
        if let Some(path) = &self.revocation_file {
            verify.arg("-r").arg(path);
        }
        crate::process::capture_input(verify, &unsigned, Duration::from_secs(15), 65536)?;
        Ok(())
    }
    pub(crate) fn git_config(&self) -> Vec<String> {
        let mut config = vec![
            "gpg.format=ssh".into(),
            format!("user.signingKey={}", self.key.display()),
            format!("gpg.ssh.program={}", self.program.display()),
            format!(
                "gpg.ssh.allowedSignersFile={}",
                self.allowed_signers.display()
            ),
            "gpg.ssh.revocationFile=".into(),
            "gpg.minTrustLevel=fully".into(),
        ];
        if let Some(path) = &self.revocation_file {
            config.push(format!("gpg.ssh.revocationFile={}", path.display()));
        }
        config
    }
}

fn invalid(message: String) -> crate::error::Error {
    crate::error::Error::InvalidInput { message }
}
