//! Fixed broker storage scopes and retained volume identity checks.
//!
//! These records describe host-selected provisioning. They neither create a
//! volume nor prove that a running sandbox mounted it. Local tmpfs contents do
//! not survive unmount or host reboot; a receipt is not persistence evidence.
use crate::{
    error::{ensure, Error, Result},
    plan,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
mod journal;
pub use journal::{prepare, remove, Driver};
mod mounts;
pub use mounts::{probe, verify_mounts, Filesystem};
mod docker;
pub use docker::{Docker, PinnedDocker};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub bytes: u64,
    pub inodes: u64,
}
impl Limits {
    fn validate(&self) -> Result<()> {
        ensure!(
            (4096..=16 * 1024 * 1024 * 1024).contains(&self.bytes)
                && self.bytes.is_multiple_of(4096)
                && (16..=1_048_576).contains(&self.inodes),
            "Storage requires page-aligned 4 KiB..16 GiB and 16..1048576 inodes"
        );
        Ok(())
    }
}

/// Independently bounded areas; selecting this profile never grants guest I/O.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub control: Limits,
    pub artifacts: Limits,
    pub incoming: Limits,
}
impl Profile {
    pub fn validate(&self) -> Result<()> {
        for limits in [&self.control, &self.artifacts, &self.incoming] {
            limits.validate()?;
        }
        Ok(())
    }
    pub fn intents(&self, owner: &str, workspace: &str) -> Result<Vec<Intent>> {
        self.validate()?;
        let mut intents = Vec::new();
        for (area, limits) in [
            (Area::Control, &self.control),
            (Area::Artifacts, &self.artifacts),
            (Area::Incoming, &self.incoming),
        ] {
            let intent = Intent {
                area,
                owner: owner.into(),
                workspace: workspace.into(),
                limits: limits.clone(),
            };
            intent.validate()?;
            intents.push(intent);
        }
        Ok(intents)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Area {
    Control,
    Artifacts,
    Incoming,
}
impl Area {
    fn name(&self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Artifacts => "artifacts",
            Self::Incoming => "incoming",
        }
    }
}

/// Retain before creating the resource. Reconciliation requires an observation
/// from the trusted host Docker endpoint, never one supplied by a guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    area: Area,
    owner: String,
    workspace: String,
    limits: Limits,
}
impl Intent {
    fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        crate::config::identifier(&self.workspace)?;
        ensure!(
            self.owner.len() == 32
                && self
                    .owner
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Invalid original storage owner"
        );
        Ok(())
    }
    pub fn name(&self) -> String {
        format!("ls-{}-{}", self.owner, self.area.name())
    }
    pub fn target(&self) -> &'static str {
        match self.area {
            Area::Control => "/var/lib/ladyshell/broker/control",
            Area::Artifacts => "/var/lib/ladyshell/broker/artifacts",
            Area::Incoming => "/var/lib/ladyshell/broker/incoming",
        }
    }
    pub fn options(&self) -> Value {
        json!({"type":"tmpfs", "device":"tmpfs", "o": format!(
            "size={},uid=10001,gid=10001,nr_inodes={},mode=0700,nosuid,nodev",
            self.limits.bytes, self.limits.inodes)})
    }
    pub fn labels(&self) -> Value {
        json!({"ladyshell.owner":self.owner,
            "openshell.ai/sandbox-attachable":"true",
            "openshell.ai/sandbox-attachable-workspace":self.workspace})
    }
    pub fn observe(&self, volume: &Value) -> Result<Receipt> {
        self.validate()?;
        ensure!(
            volume["Name"] == self.name()
                && volume["Driver"] == "local"
                && volume["Options"] == self.options()
                && volume["CreatedAt"].as_str().is_some_and(|s| !s.is_empty()
                    && s.len() <= 128
                    && !s.chars().any(char::is_control)),
            "Storage identity or hard-cap options mismatch"
        );
        for (key, expected) in self
            .labels()
            .as_object()
            .ok_or_else(|| invalid("Invalid labels"))?
        {
            ensure!(
                volume["Labels"][key] == *expected,
                "Storage ownership mismatch"
            );
        }
        Ok(Receipt {
            intent: self.clone(),
            identity: plan::digest(
                &json!({"name":volume["Name"], "created":volume["CreatedAt"],
                "driver":volume["Driver"], "options":volume["Options"], "labels":volume["Labels"]}),
            )?,
        })
    }
}

/// Correlation retained in the host journal. Deserializing it grants no authority
/// to create, attach or delete resources; verify the original journal separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    intent: Intent,
    identity: String,
}
impl Receipt {
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    pub fn verify(&self, observed: &Value) -> Result<()> {
        ensure!(
            self.intent.observe(observed)? == *self,
            "Original storage volume was replaced"
        );
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}
