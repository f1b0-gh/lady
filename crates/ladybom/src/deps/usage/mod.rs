//! Conservative source evidence; a candidate is never removal authorization.
use super::graph;
use crate::{error::Result, sources::Snapshot};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub manifest: String,
    pub name: String,
    pub kind: String,
    pub marker: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageStatus {
    Referenced,
    Candidate,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub declaration: Declaration,
    pub status: UsageStatus,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
    pub targets: Vec<graph::NodeRef>,
    pub root_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageReport {
    pub schema_version: u32,
    pub graph_sha256: String,
    pub inputs: Snapshot,
    pub findings: Vec<Finding>,
    pub complete: bool,
}

mod lex;
mod native;
mod source;
use super::{invalid, Project, Requirement};
use crate::{error::ensure, files};
pub use native::enrich;
use serde_json::Value;
use source::{parent, resolve, SourcesRead};
use std::collections::{BTreeMap, BTreeSet};

/// Read-only analysis. All selected inputs are pinned in the returned snapshot.
/// `complete` stays false: lexical absence is not proof of unusedness.
pub fn analyze(root: &Path, graph: &graph::Graph, manifests: &[String]) -> Result<UsageReport> {
    graph.validate()?;
    ensure!(
        !manifests.is_empty() && manifests.len() <= 64,
        "Between 1 and 64 usage manifests required"
    );
    let mut sources = SourcesRead::collect(root, graph, manifests)?;
    for (path, hash) in &graph.inventory.inputs {
        crate::config::relative_path(path)?;
        ensure!(
            sources
                .snapshot
                .get(path)
                .is_some_and(|r| r.sha256 == *hash),
            "Stale inventory or missing source: {path}"
        );
    }
    let mut selected = BTreeSet::new();
    let mut findings = Vec::new();
    for manifest in manifests {
        crate::config::relative_path(manifest)?;
        ensure!(
            selected.insert(manifest),
            "Duplicate usage manifest: {manifest}"
        );
        let projects: Vec<_> = graph
            .inventory
            .projects
            .iter()
            .filter(|p| p.manifest == *manifest)
            .collect();
        ensure!(
            projects.len() == 1,
            "Missing or ambiguous project: {manifest}"
        );
        let project = projects[0];
        let text = sources
            .text(manifest)
            .ok_or_else(|| invalid(format!("Missing or non-UTF-8 manifest: {manifest}")))?;
        let document = match project.ecosystem.as_str() {
            "npm" => crate::json::parse(text.as_bytes())?,
            "rust" | "python" => serde_json::to_value(super::parse_toml(text)?)?,
            _ => Value::Null,
        };
        let coverage = coverage(project, &document, &mut sources)?;
        for (declaration, requirement) in declarations(project, &document, &sources)? {
            let mut limitations = coverage.limitations.clone();
            limitations.push(
                "Partial lexical analysis; absence of references does not authorize removal".into(),
            );
            let mut uncertain = !coverage.limitations.is_empty() || !graph.inventory.complete;
            if !graph.inventory.complete {
                limitations
                    .push("Incomplete inventory; declarations or metadata not covered".into());
            }
            let mut evidence = Vec::new();
            let name = if project.ecosystem == "rust" {
                declaration.name.replace('-', "_")
            } else {
                declaration.name.clone()
            };
            let module_mapping = document
                .pointer("/tool/deptry/package_module_name_map")
                .and_then(|m| m.get(&declaration.name));
            let mapping_valid = module_mapping.is_some_and(|m| match m {
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => {
                    !a.is_empty() && a.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                }
                _ => false,
            });
            let modules: Vec<String> = if project.ecosystem == "python" {
                match module_mapping {
                    Some(Value::String(s)) => vec![s.clone()],
                    Some(Value::Array(a)) if a.iter().all(Value::is_string) => a
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect(),
                    _ => vec![name.replace('-', "_")],
                }
            } else {
                vec![name.clone()]
            };
            for module in &modules {
                let module = module.split('.').next().unwrap_or(module);
                if let Some(paths) = coverage.references.get(module) {
                    evidence.extend(paths.iter().map(|p| {
                        format!(
                            "Lexical reference {module}: {p} (sha256 {})",
                            sources.snapshot[p].sha256
                        )
                    }));
                }
            }
            if requirement.marker.is_some()
                || !requirement.extras.is_empty()
                || requirement.kind == "build"
                || requirement.kind.starts_with("extra:")
                || requirement.kind.ends_with(":include")
            {
                uncertain = true;
                limitations
                    .push("Conditions, features, group or build dependency not evaluated".into());
            }
            match project.ecosystem.as_str() {
                "rust" => {
                    if requirement.source.get("optional") == Some(&Value::Bool(true))
                        || coverage.features.contains(&declaration.name)
                    {
                        uncertain = true;
                        limitations.push(
                            "Cargo activation through a feature or optional dependency".into(),
                        );
                    }
                }
                "npm" => {
                    if declaration.kind != "runtime"
                        || declaration.name.starts_with("@types/")
                        || declaration.name.contains("plugin")
                        || graph.inventory.components_for(project)?.iter().any(|c| {
                            (c.name == declaration.name
                                || c.context == format!("node_modules/{}", declaration.name))
                                && ["hasInstallScript", "gypfile", "os", "cpu", "libc", "bin"]
                                    .iter()
                                    .any(|field| {
                                        c.metadata.get(*field).is_some_and(|v| {
                                            !v.is_null() && v != &Value::Bool(false)
                                        })
                                    })
                        })
                    {
                        uncertain = true;
                        limitations.push("Unresolved npm usage through tools, types, peers, plugins or native loading".into());
                    }
                }
                "python" => {
                    if !mapping_valid || modules.is_empty() {
                        uncertain = true;
                        limitations.push("Python distribution/module correspondence is not attested; only positive references are retained".into());
                    }
                    if declaration.kind != "runtime" {
                        uncertain = true;
                        limitations.push(
                            "Python development or build dependency may be used outside imports"
                                .into(),
                        );
                    }
                }
                _ => {
                    uncertain = true;
                    limitations.push("Unsupported ecosystem".into());
                }
            }
            let status = if !evidence.is_empty() {
                UsageStatus::Referenced
            } else if uncertain {
                UsageStatus::Unknown
            } else {
                UsageStatus::Candidate
            };
            if evidence.is_empty() {
                evidence.push("No lexical reference in the covered sources".into());
            }
            let (targets, root_ids) = roots(graph, project, &requirement)?;
            if root_ids.is_empty() {
                limitations
                    .push("Missing or ambiguous graph root; simulation is not qualified".into());
            }
            findings.push(Finding {
                declaration,
                status,
                evidence,
                limitations,
                targets,
                root_ids,
            });
        }
    }
    findings.sort_by(|a, b| a.declaration.cmp(&b.declaration));
    findings.dedup_by(|a, b| a.declaration == b.declaration);
    Ok(UsageReport {
        schema_version: 1,
        graph_sha256: files::hash(&serde_json::to_vec(graph)?),
        inputs: sources.snapshot,
        findings,
        complete: false,
    })
}

fn declarations(
    project: &Project,
    document: &Value,
    sources: &SourcesRead,
) -> Result<Vec<(Declaration, Requirement)>> {
    let mut result = Vec::new();
    for requirement in &project.requirements {
        let mut names = vec![requirement.name.clone()];
        if project.ecosystem == "rust" {
            let table = requirement
                .marker
                .as_ref()
                .and_then(|m| document.get("target").and_then(|t| t.get(m)))
                .unwrap_or(document);
            let field = match requirement.kind.as_str() {
                "build" => "build-dependencies",
                "dev" => "dev-dependencies",
                _ => "dependencies",
            };
            names.clear();
            if let Some(entries) = table.get(field).and_then(Value::as_object) {
                for (alias, spec) in entries {
                    let effective = if spec.get("workspace") == Some(&Value::Bool(true)) {
                        let inherited =
                            workspace_spec(project, alias, sources)?.ok_or_else(|| {
                                invalid(format!("Missing workspace dependency: {alias}"))
                            })?;
                        let mut merged = match inherited {
                            Value::String(version) => serde_json::json!({"version": version}),
                            value => value,
                        };
                        if let Some(extra) = spec.get("features").and_then(Value::as_array) {
                            let mut features = merged
                                .get("features")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            features.extend(extra.iter().cloned());
                            merged["features"] = Value::Array(features);
                        }
                        if let Some(optional) = spec.get("optional") {
                            merged["optional"] = optional.clone();
                        }
                        merged
                    } else {
                        spec.clone()
                    };
                    if effective
                        .get("package")
                        .and_then(Value::as_str)
                        .unwrap_or(alias)
                        == requirement.name
                        && effective == requirement.source
                        && requirement
                            .declared_name
                            .as_deref()
                            .unwrap_or(&requirement.name)
                            == alias
                    {
                        names.push(alias.clone());
                    }
                }
            }
            ensure!(
                !names.is_empty(),
                "Unmatched Cargo declaration: {}",
                requirement.name
            );
        }
        for name in names {
            result.push((
                Declaration {
                    manifest: project.manifest.clone(),
                    name,
                    kind: requirement.kind.clone(),
                    marker: requirement.marker.clone(),
                },
                requirement.clone(),
            ));
        }
    }
    Ok(result)
}
fn workspace_spec(project: &Project, alias: &str, sources: &SourcesRead) -> Result<Option<Value>> {
    for candidate in super::ancestors(&project.manifest, "Cargo.toml") {
        if let Some(text) = sources.text(&candidate) {
            let value = serde_json::to_value(super::parse_toml(text)?)?;
            if let Some(spec) = value
                .get("workspace")
                .and_then(|v| v.get("dependencies"))
                .and_then(|v| v.get(alias))
            {
                return Ok(Some(spec.clone()));
            }
        }
    }
    Ok(None)
}
fn roots(
    graph: &graph::Graph,
    project: &Project,
    requirement: &Requirement,
) -> Result<(Vec<graph::NodeRef>, Vec<String>)> {
    let condition = serde_json::to_value(requirement)?;
    let candidates: Vec<_> = graph
        .roots
        .iter()
        .filter(|r| r.manifest == project.manifest && r.kind == requirement.kind)
        .filter(|r| {
            if r.condition.get("name").is_some() {
                return r.condition == condition;
            }
            graph
                .components
                .iter()
                .find(|n| n.key == r.to)
                .is_some_and(|n| {
                    if project.ecosystem == "npm" {
                        n.component.context == format!("node_modules/{}", requirement.name)
                    } else {
                        n.component.name == requirement.name
                    }
                })
        })
        .collect();
    if candidates.len() != 1 {
        return Ok((vec![], vec![]));
    }
    let root = candidates[0];
    Ok((
        vec![root.to.clone()],
        vec![files::hash(&serde_json::to_vec(root)?)],
    ))
}

#[derive(Default)]
struct Coverage {
    references: BTreeMap<String, BTreeSet<String>>,
    limitations: Vec<String>,
    features: BTreeSet<String>,
}
impl Coverage {
    fn reference(&mut self, name: &str, path: &str) {
        self.references
            .entry(name.into())
            .or_default()
            .insert(path.into());
    }
    fn uncertain(&mut self, message: impl Into<String>) {
        self.limitations.push(message.into());
    }
}
fn coverage(project: &Project, document: &Value, sources: &mut SourcesRead) -> Result<Coverage> {
    let mut result = Coverage::default();
    let base = parent(&project.manifest);
    let mut queue: BTreeSet<String> = sources
        .data
        .keys()
        .filter(|p| sources.owns(base, p))
        .filter(|p| match project.ecosystem.as_str() {
            "rust" => p.ends_with(".rs"),
            "npm" => [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"]
                .iter()
                .any(|e| p.ends_with(e)),
            "python" => p.ends_with(".py") || p.ends_with(".pyi"),
            _ => false,
        })
        .cloned()
        .collect();
    if project.ecosystem == "rust" {
        for kind in ["lib", "bin", "test", "example", "bench"] {
            let entries: Vec<&Value> = match document.get(kind) {
                Some(Value::Array(a)) => a.iter().collect(),
                Some(v) => vec![v],
                None => vec![],
            };
            for target in entries {
                if let Some(path) = target.get("path") {
                    let Some(path) = path.as_str() else {
                        result.uncertain("Cargo target path is not a string");
                        continue;
                    };
                    let path = resolve(base, path)?;
                    sources.rust_target(&path)?;
                    // Include siblings because an external target may declare regular modules.
                    queue.extend(
                        sources
                            .data
                            .keys()
                            .filter(|p| p.ends_with(".rs") && sources.owns(parent(&path), p))
                            .cloned(),
                    );
                    queue.insert(path);
                }
            }
        }
        if let Some(features) = document.get("features").and_then(Value::as_object) {
            for values in features.values().filter_map(Value::as_array) {
                for value in values.iter().filter_map(Value::as_str) {
                    let name = value
                        .strip_prefix("dep:")
                        .unwrap_or(value)
                        .split('/')
                        .next()
                        .unwrap_or(value)
                        .trim_end_matches('?');
                    result.features.insert(name.into());
                }
            }
        }
        let build = document.pointer("/package/build");
        if build.is_some_and(|v| v != &Value::Bool(false))
            || sources.data.contains_key(&resolve(base, "build.rs")?)
        {
            result.uncertain("Cargo build.rs script or code generation not executed");
            if let Some(path) = build.and_then(Value::as_str) {
                queue.insert(resolve(base, path)?);
            }
        }
    }
    if project.ecosystem == "npm" {
        for field in [
            "scripts",
            "bin",
            "gypfile",
            "knip",
            "eslintConfig",
            "babel",
            "imports",
            "browser",
            "types",
            "typings",
        ] {
            if document.get(field).is_some() {
                result.uncertain(format!(
                    "Npm configuration {field} neither executed nor resolved"
                ));
            }
        }
    }
    for path in sources
        .data
        .keys()
        .filter(|p| sources.owns(base, p) && source::relevant(p, &project.ecosystem))
    {
        let unsupported = match project.ecosystem.as_str() {
            "npm" => {
                [".vue", ".svelte", ".astro", ".node", ".gyp"]
                    .iter()
                    .any(|e| path.ends_with(e))
                    || [
                        "tsconfig",
                        "webpack",
                        "vite.config",
                        "knip.",
                        "eslint",
                        "babel",
                    ]
                    .iter()
                    .any(|s| super::basename(path).contains(s))
            }
            "python" => [".ipynb", ".pyx", ".so", ".pyd"]
                .iter()
                .any(|e| path.ends_with(e)),
            _ => false,
        };
        if unsupported {
            result.uncertain(format!(
                "Uncovered configuration, native or language input: {path}"
            ));
        }
    }
    if queue.is_empty() {
        result.uncertain("No supported source in the project");
    }
    let mut visited = BTreeSet::new();
    while let Some(path) = queue.pop_first() {
        if !visited.insert(path.clone()) {
            continue;
        }
        if project.ecosystem == "rust" {
            sources.rust_target(&path)?;
        }
        let Some(text) = sources.text(&path) else {
            result.uncertain(format!("Missing, excluded or non-UTF-8 source: {path}"));
            continue;
        };
        let (tokens, uncertain) = lex::tokens(text, &project.ecosystem);
        if uncertain {
            result.uncertain(format!(
                "Unresolved lexical syntax or dynamic string: {path}"
            ));
        }
        match project.ecosystem.as_str() {
            "rust" => {
                queue.extend(
                    sources
                        .data
                        .keys()
                        .filter(|p| p.ends_with(".rs") && sources.owns(parent(&path), p))
                        .cloned(),
                );
                rust_tokens(&tokens, &path, &mut queue, &mut result, sources)?;
            }
            "npm" => npm_tokens(&tokens, &path, &mut result),
            "python" => python_tokens(&tokens, &path, &mut result),
            _ => (),
        }
    }
    result.limitations.sort();
    result.limitations.dedup();
    Ok(result)
}
fn rust_tokens(
    tokens: &[lex::Token],
    path: &str,
    queue: &mut BTreeSet<String>,
    coverage: &mut Coverage,
    sources: &SourcesRead,
) -> Result<()> {
    for (i, token) in tokens.iter().enumerate() {
        if let Some(word) = token.word() {
            coverage.reference(word, path);
        }
        if token.is("mod") && tokens.get(i + 2).is_some_and(|t| t.punct(b';')) {
            if let Some(name) = tokens.get(i + 1).and_then(lex::Token::word) {
                let has_path = tokens[..i].iter().rev().take(12).any(|t| t.is("path"));
                let stem = super::basename(path).strip_suffix(".rs").unwrap_or("");
                let candidates = [
                    format!("{name}.rs"),
                    format!("{name}/mod.rs"),
                    format!("{stem}/{name}.rs"),
                    format!("{stem}/{name}/mod.rs"),
                ];
                let exists = candidates
                    .iter()
                    .map(|p| resolve(parent(path), p))
                    .collect::<Result<Vec<_>>>()?
                    .iter()
                    .any(|p| sources.data.contains_key(p));
                if !has_path && !exists {
                    coverage.uncertain(format!(
                        "Missing Rust module or unresolved path: {path}: {name}"
                    ));
                }
            }
        }
        if token.is("macro_rules") {
            coverage.uncertain(format!("Macro expansion not evaluated: {path}"));
        }
        if token.is("path") && tokens.get(i + 1).is_some_and(|t| t.punct(b'=')) {
            if let Some(target) = tokens.get(i + 2).and_then(lex::Token::string) {
                queue.insert(resolve(parent(path), target)?);
            } else {
                coverage.uncertain(format!("Attribut path dynamique : {path}"));
            }
        }
        if token.is("include") && tokens.get(i + 1).is_some_and(|t| t.punct(b'!')) {
            if let Some(target) = tokens
                .get(i + 3)
                .and_then(lex::Token::string)
                .filter(|_| tokens.get(i + 4).is_some_and(|t| t.punct(b')')))
            {
                queue.insert(resolve(parent(path), target)?);
            } else {
                coverage.uncertain(format!("Generated or dynamic include!: {path}"));
            }
        }
    }
    Ok(())
}
fn npm_tokens(tokens: &[lex::Token], path: &str, coverage: &mut Coverage) {
    for (i, token) in tokens.iter().enumerate() {
        let import = token.is("import") || token.is("require");
        if import || token.is("from") {
            let resolve_call = token.is("require")
                && tokens.get(i + 1).is_some_and(|t| t.punct(b'.'))
                && tokens.get(i + 2).is_some_and(|t| t.is("resolve"));
            let offset = if resolve_call { 3 } else { 1 };
            let call = tokens.get(i + offset).is_some_and(|t| t.punct(b'('));
            let next = tokens.get(i + offset + usize::from(call));
            if let Some(module) = next.and_then(lex::Token::string) {
                let parts: Vec<_> = module.split('/').collect();
                let name = if module.starts_with('@') && parts.len() >= 2 {
                    format!("{}/{}", parts[0], parts[1])
                } else {
                    parts[0].into()
                };
                coverage.reference(&name, path);
            } else if call {
                coverage.uncertain(format!("Chargement npm dynamique : {path}"));
            }
        }
        if token.is("eval") || token.is("createRequire") || token.is("process") {
            coverage.uncertain(format!(
                "Dynamic or environment-dependent npm input: {path}"
            ));
        }
    }
}
fn python_tokens(tokens: &[lex::Token], path: &str, coverage: &mut Coverage) {
    for (i, token) in tokens.iter().enumerate() {
        if token.is("import") || token.is("from") {
            if let Some(module) = tokens.get(i + 1).and_then(lex::Token::word) {
                coverage.reference(module, path);
            }
            if token.is("import") {
                for pair in tokens[i + 1..]
                    .split(|t| t.punct(b'\n') || t.punct(b';'))
                    .next()
                    .unwrap_or_default()
                    .windows(2)
                {
                    if pair[0].punct(b',') {
                        if let Some(module) = pair[1].word() {
                            coverage.reference(module, path);
                        }
                    }
                }
            }
        }
        if token.is("importlib")
            || token.is("__import__")
            || token.is("exec")
            || token.is("eval")
            || token.is("entry_points")
        {
            coverage.uncertain(format!("Dynamic Python loading or plugin: {path}"));
        }
    }
}
