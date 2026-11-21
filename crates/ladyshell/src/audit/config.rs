use super::{
    model::{Budget, Profile},
    verify::check,
};
use crate::{
    config::{identifier, relative_path, Tool},
    error::Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub profile: Profile,
    pub scope_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub tools: BTreeMap<String, Tool>,
    pub checks: Vec<Vec<String>>,
    pub budget: Budget,
    pub limits: Limits,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub cpu_seconds: u64,
    pub memory_bytes: u64,
    pub processes: u32,
    pub files: u32,
    pub disk_bytes: u64,
}
impl AuditConfig {
    pub fn validate(&self) -> Result<()> {
        check(!self.scope_paths.is_empty(), "Périmètre d’audit vide")?;
        for paths in [&self.scope_paths, &self.exclude_paths] {
            let mut seen = BTreeSet::new();
            for p in paths {
                relative_path(p)?;
                check(seen.insert(p), "Chemin d’audit dupliqué")?;
            }
        }
        check(
            self.budget.invocations > 0 && self.budget.seconds > 0,
            "Budget d’audit nul",
        )?;
        check(
            self.limits.cpu_seconds >= 5
                && self.limits.memory_bytes > 0
                && self.limits.processes > 0
                && self.limits.files > 0
                && self.limits.disk_bytes > 0,
            "Limites d’audit invalides : CPU au moins 5 secondes et autres limites positives",
        )?;
        for (name, tool) in &self.tools {
            identifier(name)?;
            check(
                !tool.version.is_empty()
                    && tool
                        .version
                        .bytes()
                        .next()
                        .is_some_and(|b| b.is_ascii_digit())
                    && tool
                        .version
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b)),
                "Version d’outil d’audit exacte requise",
            )?;
            check(
                tool.phase == "runtime",
                "Phase d’outil d’audit non supportée",
            )?;
        }
        check(self.checks.len() <= 128, "Trop de commandes d’audit")?;
        for command in &self.checks {
            check(
                !command.is_empty()
                    && command.len() <= 128
                    && command
                        .iter()
                        .all(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0')),
                "Commande d’audit invalide",
            )?;
        }
        Ok(())
    }
}
