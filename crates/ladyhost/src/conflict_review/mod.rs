//! Human conflict review context. Agent prose supplies no verification authority.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};
mod native;
pub use native::{inspect, verify_candidate, verify_display};
pub const MARKER: &str = "Ladyhost-Conflict-Review: ";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub path: String,
    pub resolution: String,
    pub preserved: Vec<String>,
    pub changed: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentCheck {
    pub command_index: usize,
    pub covers: Vec<String>,
    pub purpose: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub schema_version: u32,
    pub repository: String,
    pub target: String,
    pub change_id: String,
    pub original_base: String,
    pub previous_head: String,
    pub upstream_head: String,
    pub candidate_tree: String,
    pub task_intent: String,
    pub upstream_intent: String,
    pub conflict_paths: Vec<String>,
    pub decisions: Vec<Decision>,
    pub uncertainties: Vec<String>,
    pub manifest: Artifact,
    pub checks: Artifact,
    pub policy: Artifact,
    pub independent_checks: Vec<IndependentCheck>,
}
pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn prose(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 8192
        && !value
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
}
fn source_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains(['\\', '\0', '\n', '\r', '\t'])
        && value
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && p != ".git" && p != ".jj")
}
impl Artifact {
    pub fn validate(&self, workspace: &std::path::Path) -> Result<()> {
        ensure!(digest(&self.sha256), "Invalid retained artifact digest");
        ensure!(
            self.path.is_absolute()
                && !self
                    .path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir)
                && !crate::resolved(&self.path)?.starts_with(crate::resolved(workspace)?),
            "Conflict review input must stay outside the project"
        );
        Ok(())
    }
}
impl Package {
    pub fn structural(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "Unsupported conflict review schema"
        );
        let (owner, repo) = self
            .repository
            .split_once('/')
            .context("Conflict repository missing")?;
        ensure!(
            crate::identifier(owner, false)
                && crate::identifier(repo, true)
                && crate::integration::branch(&self.target),
            "Invalid conflict repository or target"
        );
        ensure!(
            !self.change_id.is_empty()
                && self.change_id.len() <= 100
                && self
                    .change_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "Invalid logical change identity"
        );
        for oid in [
            &self.original_base,
            &self.previous_head,
            &self.upstream_head,
            &self.candidate_tree,
        ] {
            ensure!(
                crate::integration::full_oid(oid) && oid.len() == self.original_base.len(),
                "Conflict review needs exact object IDs"
            );
        }
        ensure!(
            self.original_base != self.previous_head
                && self.original_base != self.upstream_head
                && self.previous_head != self.upstream_head,
            "Conflict revisions must be distinct"
        );
        ensure!(
            prose(&self.task_intent) && prose(&self.upstream_intent),
            "Both change intents are required"
        );
        ensure!(
            !self.conflict_paths.is_empty()
                && self.conflict_paths.len() <= 64
                && self.conflict_paths.iter().all(|p| source_path(p)),
            "Observed conflict paths missing or invalid"
        );
        let paths = self.conflict_paths.iter().collect::<BTreeSet<_>>();
        ensure!(
            paths.len() == self.conflict_paths.len() && self.decisions.len() == paths.len(),
            "Conflict decisions must cover every observed path once"
        );
        let mut covered = BTreeSet::new();
        for decision in &self.decisions {
            ensure!(
                paths.contains(&decision.path)
                    && covered.insert(&decision.path)
                    && prose(&decision.resolution),
                "Resolution path missing, duplicated or not observed"
            );
            for list in [&decision.preserved, &decision.changed] {
                ensure!(
                    list.len() <= 16 && list.iter().all(|s| prose(s)),
                    "Invalid behavior explanation"
                );
            }
            ensure!(
                !decision.preserved.is_empty() || !decision.changed.is_empty(),
                "Explain preserved or changed behavior"
            );
        }
        ensure!(
            self.uncertainties.len() <= 16 && self.uncertainties.iter().all(|s| prose(s)),
            "Invalid uncertainty list"
        );
        ensure!(
            self.independent_checks.len() <= 32,
            "Too many independent check selections"
        );
        let mut indexes = BTreeSet::new();
        for check in &self.independent_checks {
            ensure!(
                indexes.insert(check.command_index)
                    && check.command_index < 32
                    && prose(&check.purpose)
                    && check.covers.len() <= 3
                    && check
                        .covers
                        .iter()
                        .all(|v| matches!(v.as_str(), "task" | "upstream" | "interaction"))
                    && check.covers.iter().collect::<BTreeSet<_>>().len() == check.covers.len(),
                "Invalid host check coverage"
            );
        }
        for a in [&self.manifest, &self.checks, &self.policy] {
            ensure!(digest(&a.sha256), "Invalid evidence digest");
        }
        Ok(())
    }
    /// Readiness requires host-selected assertions for both changes and their interaction.
    pub fn validate(&self) -> Result<()> {
        self.structural()?;
        let covered = self
            .independent_checks
            .iter()
            .flat_map(|c| c.covers.iter().map(String::as_str))
            .collect::<BTreeSet<_>>();
        ensure!(
            covered == BTreeSet::from(["task", "upstream", "interaction"]),
            "Independent task, upstream and interaction coverage is required"
        );
        Ok(())
    }
}
fn quote(value: &str) -> String {
    let mut safe = String::new();
    for c in value.chars() {
        match c {
            '&' => safe.push_str("&amp;"),
            '<' => safe.push_str("&lt;"),
            '>' => safe.push_str("&gt;"),
            '@' => safe.push_str("@\u{200b}"),
            '\\' | '[' | ']' | '!' | '`' => {
                safe.push('\\');
                safe.push(c);
            }
            _ => safe.push(c),
        }
    }
    safe.lines()
        .map(|line| format!("> {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
pub fn render(package: &Package, sha: &str) -> Result<String> {
    package.structural()?;
    ensure!(digest(sha), "Invalid package digest");
    let mut lines=vec!["## Conflict resolution review".into(),"Human review required. Agent explanations and host-selected checks support review; they do not prove semantic correctness.".into(),
        format!("Original base: `{}`\n\nPrevious task: `{}`\n\nUpstream: `{}`\n\nResolved tree: `{}`",package.original_base,package.previous_head,package.upstream_head,package.candidate_tree),
        "### Intent of each change (retained by the host)".into(),"Task:".into(),quote(&package.task_intent),"Upstream:".into(),quote(&package.upstream_intent),"### Agent-reported resolution".into()];
    for d in &package.decisions {
        lines.push(quote(&format!(
            "File: {}\nResolution: {}\nPreserved: {}\nChanged: {}",
            d.path,
            d.resolution,
            d.preserved.join("; "),
            d.changed.join("; ")
        )));
    }
    lines.push("### Host-selected independent checks".into());
    for c in &package.independent_checks {
        lines.push(quote(&format!(
            "Command {}: {}\nCoverage selected by host: {}",
            c.command_index + 1,
            c.purpose,
            c.covers.join(", ")
        )));
    }
    if package.validate().is_err() {
        lines.push("INCOMPLETE independent coverage: integration is blocked. Review may still identify the missing checks.".into());
    }
    lines.push(format!("Retained evidence digests:\n\n- Export manifest: `{}`\n- Native check receipt: `{}`\n- Host check policy: `{}`",package.manifest.sha256,package.checks.sha256,package.policy.sha256));
    lines.push("Check selection is host metadata. The native gate verifies the retained receipt against the resolved bytes; agent-reported test claims cannot satisfy it. CI and fresh human approval are evaluated separately at integration.".into());
    lines.push("### Remaining uncertainty (agent-reported)".into());
    lines.push(quote(&if package.uncertainties.is_empty() {
        "None reported; this does not establish absence of uncertainty.".into()
    } else {
        package.uncertainties.join("\n")
    }));
    lines.push(format!("{MARKER}{sha}"));
    let text = lines.join("\n\n") + "\n";
    ensure!(
        text.len() <= 48 * 1024,
        "Conflict review display exceeds bound"
    );
    Ok(text)
}
