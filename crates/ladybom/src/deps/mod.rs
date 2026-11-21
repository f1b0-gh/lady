//! Static dependency inventory. No package manager, project code or network I/O.
pub mod constraints;
pub mod cyclonedx;
pub mod declarations;
mod go;
pub mod graph;
pub mod interop;
mod local_identity;
mod model;
mod npm;
pub mod prune_validation;
mod python;
mod rust;
pub use local_identity::LocalIdentities;
pub mod vuln;

pub use model::*;

use crate::{
    config::{relative_path, Sources},
    error::{ensure, Error, Result},
    files,
    sources::{self, Snapshot},
};
use packageurl::PackageUrl;
use std::{collections::BTreeMap, fs, os::fd::AsRawFd, path::Path};

type Inputs = BTreeMap<String, String>;
const MANIFEST_LIMIT: usize = 8 * 1024 * 1024;

/// Enumerate only through the verified directory descriptor, honoring source exclusions.
pub fn project_sources(root: &Path) -> Result<Sources> {
    let directory = files::open_directory(root)?;
    let mut spec = Sources {
        include: Vec::new(),
        exclude: Vec::new(),
    };
    for entry in fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid("Non-UTF-8 source name".into()))?;
        relative_path(&name)?;
        let is_directory = entry.file_type()?.is_dir();
        let excluded = if is_directory {
            sources::excluded_directory(&name, &spec)
        } else {
            sources::excluded(&name, &spec)
        };
        if !excluded {
            if is_directory {
                files::open_child(&directory, &entry.file_name(), true)?;
            }
            spec.include.push(name);
        }
    }
    spec.include.sort();
    Ok(spec)
}

pub fn scan_project(root: &Path) -> Result<Report> {
    let spec = project_sources(root)?;
    let snapshot = sources::snapshot(root, &spec, None)?;
    scan_snapshot(root, &snapshot)
}

pub fn scan_snapshot(root: &Path, snapshot: &Snapshot) -> Result<Report> {
    let mut report = Report {
        schema_version: 2,
        complete: true,
        inputs: BTreeMap::new(),
        projects: Vec::new(),
        diagnostics: Vec::new(),
    };
    let mut inputs = Inputs::new();
    let mut cargo_locks = BTreeMap::new();
    for (name, record) in snapshot {
        relative_path(name)?;
        if !is_input(name) {
            continue;
        }
        let bytes = files::read_limited(&root.join(name), 16 * 1024 * 1024)?;
        ensure!(
            files::hash(&bytes) == record.sha256,
            "Source changed during scan: {name}"
        );
        report.inputs.insert(name.clone(), record.sha256.clone());
        if bytes.len() > MANIFEST_LIMIT {
            diagnostic(
                &mut report.diagnostics,
                "file_limit",
                name,
                "Manifest or lockfile exceeds 8 MiB",
                true,
            );
            continue;
        }
        match String::from_utf8(bytes) {
            Ok(content) => {
                inputs.insert(name.clone(), content);
            }
            Err(_) => diagnostic(
                &mut report.diagnostics,
                "invalid_utf8",
                name,
                "Non-UTF-8 input",
                true,
            ),
        }
    }
    go::scan(&inputs, &mut report);
    for (name, content) in &inputs {
        let result = match basename(name) {
            "Cargo.toml" => rust::parse(
                name,
                content,
                &inputs,
                &mut report.diagnostics,
                &mut cargo_locks,
            ),
            "pyproject.toml" => python::parse(name, content, &inputs, &mut report.diagnostics),
            "package.json" => npm::parse(name, content, &inputs, &mut report.diagnostics),
            _ if python::is_requirements_file(name) => {
                python::requirements(name, content, &mut report.diagnostics)
            }
            "setup.py" | "setup.cfg" if !inputs.contains_key(&sibling(name, "pyproject.toml")) => {
                diagnostic(
                    &mut report.diagnostics,
                    "unsupported_manifest",
                    name,
                    "Legacy Python project: static pyproject.toml metadata required",
                    true,
                );
                continue;
            }
            _ => continue,
        };
        match result {
            Ok(project) => report.projects.push(project),
            Err(error) => diagnostic(
                &mut report.diagnostics,
                "invalid_manifest",
                name,
                error.to_string(),
                true,
            ),
        }
    }
    report.complete = !report.diagnostics.iter().any(|d| d.blocking);
    npm::local::enrich(&mut report);
    report.compact_components()?;
    Ok(report)
}

fn is_input(name: &str) -> bool {
    go::is_vendor(name)
        || python::is_requirements_file(name)
        || matches!(
            basename(name),
            "Cargo.toml"
                | "Cargo.lock"
                | "go.mod"
                | "go.sum"
                | "go.work"
                | "go.work.sum"
                | "rust-toolchain.toml"
                | "rust-toolchain"
                | "pyproject.toml"
                | "uv.lock"
                | "poetry.lock"
                | "pylock.toml"
                | "setup.py"
                | "setup.cfg"
                | ".python-version"
                | "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "bun.lock"
                | "bun.lockb"
                | ".nvmrc"
                | ".node-version"
        )
}

pub fn basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}
fn sibling(name: &str, file: &str) -> String {
    name.rsplit_once('/')
        .map_or_else(|| file.into(), |(parent, _)| format!("{parent}/{file}"))
}

/// Candidate paths from the file's directory through the source root, nearest first.
pub fn ancestors(name: &str, file: &str) -> Vec<String> {
    let mut result = vec![sibling(name, file)];
    let mut parent = name.rsplit_once('/').map(|(parent, _)| parent);
    while let Some(path) = parent {
        result.push(sibling(path, file));
        parent = path.rsplit_once('/').map(|(parent, _)| parent);
    }
    result
}
pub fn parse_toml(content: &str) -> Result<toml::Value> {
    toml::from_str(content).map_err(|e| invalid(format!("Invalid TOML: {e}")))
}
fn purl(kind: &str, name: &str, version: &str) -> Result<String> {
    let (namespace, name) = if kind == "npm" && name.starts_with('@') {
        let (namespace, name) = name
            .split_once('/')
            .ok_or_else(|| invalid("Invalid scoped npm name".into()))?;
        (Some(namespace), name)
    } else {
        (None, name)
    };
    let mut purl = PackageUrl::new(kind, name).map_err(|e| invalid(e.to_string()))?;
    if let Some(namespace) = namespace {
        purl.with_namespace(namespace)
            .map_err(|e| invalid(e.to_string()))?;
    }
    purl.with_version(version)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(purl.to_string())
}
fn missing_lock(project: &Project, diagnostics: &mut Vec<Diagnostic>) {
    diagnostic(
        diagnostics,
        "missing_lockfile",
        &project.manifest,
        format!(
            "Dependencies declared without lockfile {}; explicit resolution required",
            project.manager
        ),
        false,
    );
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
