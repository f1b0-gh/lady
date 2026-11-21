use crate::{
    config::ResolvedConfig,
    error::{Error, Result},
    sources::Snapshot,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub tool: String,
    pub toolchain: String,
    pub file: String,
    pub line: Option<usize>,
    pub basis: String,
    pub phase: String,
    pub status: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema_version: u32,
    pub mission: String,
    pub complete: bool,
    pub issues: Vec<String>,
    pub observations: Vec<Observation>,
    pub missing: Vec<Observation>,
}
pub fn scan(root: &Path, files: &Snapshot, config: &ResolvedConfig) -> Result<Report> {
    use std::collections::BTreeSet;
    let expression=regex::Regex::new(r"(?i)\b(node(?:\.js|js)?|npx|npm|pnpm|yarn|pip|pip3|uv|cargo|go|git|curl|wget|docker|make|pytest|zig|python3|python|rustc|rustup|lean|lake|elan|kani|hax|creusot|nix|fstar\.exe|z3|bash|awk|cmp|grep|sed|find)\b").map_err(|e|Error::InvalidInput{message:format!("Scanner : {e}")})?;
    let mut supplied: BTreeSet<String> = [
        "bash", "git", "curl", "python", "python3", "awk", "cmp", "grep", "sed", "find", "env",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    supplied.extend(config.tools.keys().cloned());
    if config.tools.contains_key("rust") {
        supplied.extend(["cargo", "rustc", "rustfmt", "clippy-driver", "cc"].map(String::from));
    }
    if config.tools.contains_key("node") {
        supplied.extend(["npm".into(), "npx".into()]);
    }
    let mut observations = Vec::new();
    let mut issues = Vec::new();
    let mut scanned = 0;
    for (name, record) in files {
        let path = Path::new(name);
        let suffix = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if ![
            "md", "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "rs", "go", "sh", "json", "toml",
            "yaml", "yml", "ini", "cfg", "zig", "zon", "ziggy", "lean", "fst", "fsti", "nix",
            "opam", "ncl",
        ]
        .contains(&suffix)
        {
            continue;
        }
        let data = crate::files::read_limited(&root.join(name), 16 * 1024 * 1024)?;
        if crate::files::hash(&data) != record.sha256 {
            return Err(Error::InvalidInput {
                message: format!("Source modifiée pendant scan : {name}"),
            });
        }
        if data.len() > 1024 * 1024 {
            issues.push(format!("{name}: scan_file_limit"));
            continue;
        }
        let Ok(content) = std::str::from_utf8(&data) else {
            issues.push(format!("{name}: invalid_utf8"));
            continue;
        };
        scanned += 1;
        if path.file_name().is_some_and(|n| n == "package.json")
            && serde_json::from_str::<serde_json::Value>(content).is_err()
        {
            issues.push(format!("{name}: invalid_manifest"));
        }
        let mut section = String::new();
        for (index, line) in content.lines().enumerate() {
            if suffix == "md" && line.starts_with('#') {
                section = line.trim_matches('#').trim().to_lowercase();
            }
            for matched in expression.find_iter(line) {
                let tool = match matched.as_str().to_ascii_lowercase().as_str() {
                    "node.js" | "nodejs" => "node".into(),
                    other => other.to_string(),
                };
                let mut basis = if suffix == "md" {
                    "documentation_mention"
                } else {
                    "text_match_to_confirm"
                };
                let mut phase = if suffix == "md" {
                    match section.as_str() {
                        "installation" | "install" | "setup" => "installation",
                        "requirements" | "prerequisites" | "prérequis" => "execution",
                        _ => "unknown",
                    }
                } else {
                    "unknown"
                };
                if index == 0 && line.starts_with("#!") {
                    basis = "shebang";
                    phase = "execution";
                }
                if suffix == "md"
                    && phase == "execution"
                    && path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.to_ascii_lowercase().starts_with("readme"))
                {
                    let prefix = line[..matched.start()].trim_start();
                    if prefix.starts_with(['-', '*', '+'])
                        && prefix.get(1..).is_some_and(|p| {
                            p.trim_start()
                                .chars()
                                .all(|c| c == '`' || c == '*' || c == '_')
                        })
                    {
                        basis = "documentation_requirement";
                    }
                }
                observations.push(observation(
                    tool,
                    name,
                    Some(index + 1),
                    basis,
                    phase,
                    &supplied,
                ));
            }
        }
    }
    for check in &config.checks {
        let Some(first) = check.first() else {
            continue;
        };
        if files.contains_key(first.strip_prefix("./").unwrap_or(first)) {
            continue;
        }
        let tool = Path::new(first)
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::InvalidInput {
                message: "Commande check invalide".into(),
            })?;
        observations.push(observation(
            tool.into(),
            "<mission.checks>",
            None,
            "declared_command",
            "execution",
            &supplied,
        ));
    }
    if scanned == 0 {
        issues.push("no_supported_files".into());
    }
    let missing = observations
        .iter()
        .filter(|o| o.status == "missing")
        .cloned()
        .collect();
    Ok(Report {
        schema_version: 1,
        mission: config.mission.clone(),
        complete: issues.is_empty(),
        issues,
        observations,
        missing,
    })
}
fn observation(
    tool: String,
    file: &str,
    line: Option<usize>,
    basis: &str,
    phase: &str,
    supplied: &std::collections::BTreeSet<String>,
) -> Observation {
    let required = ["documentation_requirement", "shebang", "declared_command"].contains(&basis);
    let status = if supplied.contains(&tool) {
        "provided"
    } else if required {
        "missing"
    } else {
        "not_provisioned_to_confirm"
    };
    let toolchain = if ["node", "npm", "npx"].contains(&tool.as_str()) {
        "node".into()
    } else if ["cargo", "rustc", "rustfmt", "clippy-driver", "cc"].contains(&tool.as_str()) {
        "rust".into()
    } else {
        tool.clone()
    };
    Observation {
        tool,
        toolchain,
        file: file.into(),
        line,
        basis: basis.into(),
        phase: phase.into(),
        status: status.into(),
    }
}
