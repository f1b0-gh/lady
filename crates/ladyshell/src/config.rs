use crate::error::{bail, ensure, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<crate::deps::DependencyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<crate::audit::config::AuditConfig>,
    pub schema_version: u32,
    pub name: String,
    pub sources: Sources,
    pub tools: BTreeMap<String, Tool>,
    pub missions: BTreeMap<String, Mission>,
    pub sandbox: Sandbox,
    #[serde(default)]
    pub image: Image,
    #[serde(default)]
    pub sync: Sync,
    #[serde(default)]
    pub permissions: Permissions,
}
pub use nickel_util::sources::Sources;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub version: String,
    #[serde(default = "runtime")]
    pub phase: String,
}
fn runtime() -> String {
    "runtime".into()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mission {
    pub tools: Vec<String>,
    pub include: Vec<String>,
    pub depends_on: Vec<String>,
    pub checks: Vec<Vec<String>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub gateway: String,
    pub workspace: String,
    pub provider: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Image {
    pub backend: String,
    pub profile: String,
    pub platform: String,
}
impl Default for Image {
    fn default() -> Self {
        Self {
            backend: "nix".into(),
            profile: "openshell-native".into(),
            platform: "x86_64-linux".into(),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sync {
    pub mode: String,
    pub destination: String,
}
impl Default for Sync {
    fn default() -> Self {
        Self {
            mode: "files".into(),
            destination: "exports".into(),
        }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub network: Vec<Network>,
    pub filesystem: Vec<Filesystem>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub tool: String,
    pub host: String,
    pub port: u16,
    pub justification: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub path: String,
    pub access: String,
    pub justification: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<crate::deps::DependencyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<crate::audit::config::AuditConfig>,
    pub schema_version: u32,
    pub name: String,
    pub mission: String,
    pub sources: Sources,
    pub tools: BTreeMap<String, Tool>,
    pub checks: Vec<Vec<String>>,
    pub sandbox: Sandbox,
    pub resolved_missions: Vec<String>,
    pub permissions: Permissions,
    pub image: Image,
    pub sync: Sync,
}
pub fn identifier(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()[0].is_ascii_lowercase()
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-'),
        "Invalid identifier: {s}"
    );
    Ok(())
}
pub fn relative_path(s: &str) -> Result<()> {
    nickel_util::sources::relative_path(s).map_err(Into::into)
}
impl Config {
    pub fn from_value(value: Value) -> Result<Self> {
        let config: Self = serde_json::from_value(value)?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(dependencies) = &self.dependencies {
            dependencies.validate()?;
        }
        if let Some(audit) = &self.audit {
            audit.validate()?;
        }
        ensure!(self.schema_version == 1, "schema_version 1 is required");
        identifier(&self.name)?;
        ensure!(
            self.image == Image::default(),
            "Supported image: Nix, openshell-native, x86_64-linux"
        );
        ensure!(self.sync.mode == "files", "Unsupported sync mode");
        relative_path(&self.sync.destination)?;
        ensure!(
            !["state.json", "operation.json", "plan.json", ".lock"].contains(
                &self
                    .sync
                    .destination
                    .split('/')
                    .next()
                    .ok_or_else(|| invalid("Missing destination".into()))?
            ),
            "Reserved destination"
        );
        for path in self.sources.include.iter().chain(&self.sources.exclude) {
            relative_path(path)?;
        }
        for id in [
            &self.sandbox.gateway,
            &self.sandbox.workspace,
            &self.sandbox.provider,
        ] {
            identifier(id)?;
        }
        for (name, tool) in &self.tools {
            identifier(name)?;
            ensure!(tool.phase == "runtime", "The runtime phase is required");
            let parts: Vec<_> = tool.version.split('.').collect();
            ensure!(
                parts.len() == 3
                    && parts
                        .iter()
                        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
                "An exact x.y.z version is required"
            );
        }
        ensure!(
            !self.missions.is_empty(),
            "At least one mission is required"
        );
        ensure!(self.missions.len() <= 1024, "Maximum 1024 missions");
        for (name, mission) in &self.missions {
            identifier(name)?;
            for path in &mission.include {
                relative_path(path)?;
            }
            for tool in &mission.tools {
                ensure!(self.tools.contains_key(tool), "Unknown tool: {tool}");
            }
            for parent in &mission.depends_on {
                ensure!(
                    self.missions.contains_key(parent),
                    "Unknown mission: {parent}"
                );
            }
            for command in &mission.checks {
                ensure!(
                    !command.is_empty()
                        && command.iter().all(|a| !a.is_empty() && !a.contains('\0')),
                    "A list of nonempty arguments is required"
                );
            }
        }
        for request in &self.permissions.network {
            identifier(&request.tool)?;
            ensure!(request.port > 0, "Invalid port");
            ensure!(
                !request.host.is_empty()
                    && request.host.split(['.', '-']).all(|p| !p.is_empty()
                        && p.bytes()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())),
                "An explicit network host is required"
            );
            ensure!(
                !request.justification.trim().is_empty(),
                "A justification is required"
            );
        }
        for request in &self.permissions.filesystem {
            ensure!(
                ["read", "write"].contains(&request.access.as_str()),
                "Invalid access"
            );
            ensure!(
                request.path.starts_with('/'),
                "An absolute path is required"
            );
            if request.path != "/" {
                relative_path(&request.path[1..])?;
            }
            ensure!(
                !request.justification.trim().is_empty(),
                "A justification is required"
            );
        }
        // Validate the entire graph, including missions not selected by this invocation.
        let mut order = Vec::new();
        let mut visiting = BTreeSet::new();
        for name in self.missions.keys() {
            self.visit(name, &mut order, &mut visiting)?;
        }
        Ok(())
    }
    fn visit(
        &self,
        name: &str,
        order: &mut Vec<String>,
        visiting: &mut BTreeSet<String>,
    ) -> Result<()> {
        let mut done: BTreeSet<String> = order.iter().cloned().collect();
        let mut stack = vec![(name, false)];
        while let Some((current, exiting)) = stack.pop() {
            if done.contains(current) {
                continue;
            }
            if exiting {
                visiting.remove(current);
                done.insert(current.into());
                order.push(current.into());
                continue;
            }
            ensure!(visiting.insert(current.into()), "Mission cycle: {current}");
            let Some(mission) = self.missions.get(current) else {
                bail!("Unknown mission: {current}")
            };
            stack.push((current, true));
            for parent in mission.depends_on.iter().rev() {
                stack.push((parent, false));
            }
        }
        Ok(())
    }
    pub fn resolve(&self, mission: &str) -> Result<ResolvedConfig> {
        self.validate()?;
        let mut order = Vec::new();
        self.visit(mission, &mut order, &mut BTreeSet::new())?;
        let mut tools = BTreeMap::new();
        let mut include: BTreeSet<_> = self.sources.include.iter().cloned().collect();
        let mut checks = Vec::new();
        for name in &order {
            let m = self
                .missions
                .get(name)
                .ok_or_else(|| invalid(format!("Unknown mission: {name}")))?;
            for tool in &m.tools {
                tools.insert(
                    tool.clone(),
                    self.tools
                        .get(tool)
                        .ok_or_else(|| invalid(format!("Unknown tool: {tool}")))?
                        .clone(),
                );
            }
            include.extend(m.include.iter().cloned());
            checks.extend(m.checks.iter().cloned());
        }
        Ok(ResolvedConfig {
            dependencies: self.dependencies.clone(),
            audit: self.audit.clone(),
            schema_version: 1,
            name: self.name.clone(),
            mission: mission.into(),
            sources: Sources {
                include: include.into_iter().collect(),
                exclude: self.sources.exclude.clone(),
            },
            tools,
            checks,
            sandbox: self.sandbox.clone(),
            resolved_missions: order,
            permissions: self.permissions.clone(),
            image: self.image.clone(),
            sync: self.sync.clone(),
        })
    }
}
pub fn resolve(value: Value, mission: &str) -> Result<Value> {
    Ok(serde_json::to_value(
        Config::from_value(value)?.resolve(mission)?,
    )?)
}

fn invalid(message: String) -> Error {
    Error::InvalidConfiguration { message }
}
