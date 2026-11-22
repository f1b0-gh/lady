//! Trusted Nix image inputs; project files are copied as data and never evaluated.
use super::invalid;
use crate::{
    config::Sources,
    environment_lock::{self, EnvironmentLock},
    error::{ensure, Result},
    files, image,
    nickel::Evaluated,
    process::capture,
    sources::{self, Snapshot},
    state::text,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Component, Path},
    process::Command,
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltImage {
    pub image_id: String,
    pub archive: String,
    pub runtime_binary: String,
    pub codex_binary: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    archive: String,
    runtime_binary: String,
    codex_binary: String,
}

const RECIPES: [&str; 11] = [
    "flake.nix",
    "flake.lock",
    "build.nix",
    "image.nix",
    "dependencies.nix",
    "openssl.nix",
    "tpm2-tss.nix",
    "network-tools.nix",
    "runtime.nix",
    "audit-build.nix",
    "audit-image.nix",
];

pub fn build(current: &Value, run_dir: &Path, expected_sources: &Snapshot) -> Result<BuiltImage> {
    let desired = &current["desired_inputs"];
    let evaluated: Evaluated = serde_json::from_value(desired["evaluated"].clone())?;
    let audit = evaluated
        .config
        .audit
        .as_ref()
        .ok_or_else(|| invalid("Missing audit configuration"))?;
    audit.validate()?;
    let resources = files::absolute(Path::new(text(desired, "resources")?))?;
    let project = files::absolute(Path::new(text(desired, "project")?))?;
    let run_dir = files::absolute(run_dir)?;
    files::open_directory(&run_dir)?;
    ensure!(
        !run_dir.starts_with(&project) && !run_dir.starts_with(&resources),
        "Audit staging must be outside the project and distribution"
    );
    let codex = Path::new(text(&desired["artifacts"]["codex"], "path")?);
    let codex_host = Path::new(text(&desired["artifacts"]["codex-code-mode-host"], "path")?);
    let locked: EnvironmentLock = serde_json::from_value(desired["environment_lock"].clone())?;
    let mut actual = environment_lock::create(evaluated.clone(), &resources, codex, codex_host)
        .map_err(|error| {
            error.context("Cannot read audit lock inputs: run lock and apply explicitly")
        })?;
    if let Some(digest) = &locked.ladybom_sha256 {
        crate::deps::input::verify_digest(&project, &evaluated.config.sources, digest)?;
        actual.ladybom_sha256 = Some(digest.clone());
    }
    same_lock(&actual, &locked)?;
    for name in ["codex", "codex-code-mode-host"] {
        ensure!(
            locked.artifacts_sha256.get(name).map(String::as_str)
                == Some(text(&desired["artifacts"][name], "sha256")?),
            "Artifact differs from audit lock: {name}"
        );
    }
    let mut config = evaluated.config.clone();
    for (name, tool) in &audit.tools {
        if let Some(existing) = config.tools.get(name) {
            ensure!(
                existing.version == tool.version && existing.phase == tool.phase,
                "Project/audit toolchain conflict: {name}"
            );
        } else {
            config.tools.insert(name.clone(), tool.clone());
        }
    }
    for (name, tool) in &config.tools {
        ensure!(
            ["rust", "node", "zig"].contains(&name.as_str()) && tool.phase == "runtime",
            "Unsupported audit toolchain: {name}"
        );
    }
    let staging = tempfile::Builder::new()
        .prefix("audit-build-")
        .tempdir_in(&run_dir)?;
    let out = staging.path();
    let source = out.join("project");
    fs::create_dir(&source)?;
    let actual_sources = sources::snapshot(&project, &config.sources, Some(&source))?;
    ensure!(
        &actual_sources == expected_sources,
        "Sources changed since the audit plan"
    );
    ensure!(!actual_sources.is_empty(), "Empty audit sources");
    let trusted = out.join("runtime");
    fs::create_dir(&trusted)?;
    let frozen = freeze_runtime(&resources, Some(&trusted))?;
    let pinned: std::collections::BTreeMap<_, _> = locked
        .recipes_sha256
        .iter()
        .filter_map(|(path, hash)| {
            path.strip_prefix("runtime-source/")
                .map(|path| (path, hash.as_str()))
        })
        .collect();
    ensure!(
        frozen.len() == pinned.len()
            && frozen
                .iter()
                .all(|(path, record)| pinned.get(path.as_str()) == Some(&record.sha256.as_str())),
        "Runtime sources changed since the audit lock"
    );
    files::read_limited(
        &trusted.join("crates/ladyshell/resources/audit/agent-response-schema.json"),
        1024 * 1024,
    )?;
    for name in RECIPES {
        let data = files::read_limited(&resources.join("nix").join(name), 1024 * 1024)?;
        ensure!(
            locked.recipes_sha256.get(name) == Some(&files::hash(&data)),
            "Recipe changed since the audit lock: {name}"
        );
        image::write_source(&trusted, &format!("nix/{name}"), &data, false)?;
    }
    for (name, path) in [("codex", codex), ("codex-code-mode-host", codex_host)] {
        let target = out.join(name);
        let mut input = files::open_regular(path)?.take(1024 * 1024 * 1024 + 1);
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        ensure!(
            std::io::copy(&mut input, &mut output)? <= 1024 * 1024 * 1024,
            "Artifact too large"
        );
        output.sync_all()?;
        ensure!(
            locked.artifacts_sha256.get(name) == Some(&environment_lock::artifact_hash(&target)?),
            "Artifact changed since the audit lock: {name}"
        );
    }
    let mut staged_lock = environment_lock::create(
        evaluated.clone(),
        &trusted,
        &out.join("codex"),
        &out.join("codex-code-mode-host"),
    )?;
    if let Some(digest) = &locked.ladybom_sha256 {
        crate::deps::input::verify_digest(&source, &evaluated.config.sources, digest)?;
        staged_lock.ladybom_sha256 = Some(digest.clone());
    }
    same_lock(&staged_lock, &locked)?;
    environment_lock::atomic_json(&out.join("config.json"), &config)?;
    let image_name = format!(
        "ladyshell-audit-{}",
        files::hash(&serde_json::to_vec(
            &json!({"config": config, "sources": actual_sources, "runtime_sources": frozen, "lock": locked})
        )?)
    );
    let mut command = Command::new("nix");
    command.env_clear();
    for name in ["PATH", "HOME", "NIX_SSL_CERT_FILE", "SSL_CERT_FILE"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .current_dir(out)
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--impure",
            "--no-link",
            "--no-write-lock-file",
            "--print-out-paths",
            "--file",
        ])
        .arg(trusted.join("nix/audit-build.nix"));
    for (name, value) in [
        ("flakePath", trusted.join("nix")),
        ("configPath", out.join("config.json")),
        ("sourcePath", source),
        ("codexPath", out.join("codex")),
        ("codexHostPath", out.join("codex-code-mode-host")),
        ("runtimeSourcePath", trusted),
    ] {
        command.arg("--argstr").arg(name).arg(value);
    }
    command.args(["--argstr", "imageName", &image_name]);
    let result = String::from_utf8(capture(
        command,
        Duration::from_secs(1800),
        8 * 1024 * 1024,
    )?)?;
    let result = result.trim();
    store_path(result, false)?;
    let metadata: Metadata = serde_json::from_value(crate::json::parse(&files::read_limited(
        &Path::new(result).join("metadata.json"),
        1024 * 1024,
    )?)?)?;
    store_path(&metadata.archive, false)?;
    store_path(&metadata.runtime_binary, true)?;
    store_path(&metadata.codex_binary, true)?;
    ensure!(
        metadata.runtime_binary.ends_with("/bin/ladyshell")
            && metadata
                .codex_binary
                .ends_with("-ladyshell-codex/bin/codex"),
        "Invalid audit Nix binary identity"
    );
    let image_id = image::archive_image_id(Path::new(&metadata.archive))?;
    image::load_archive(&metadata.archive, &image_id)?;
    Ok(BuiltImage {
        image_id,
        archive: metadata.archive,
        runtime_binary: metadata.runtime_binary,
        codex_binary: metadata.codex_binary,
    })
}

fn same_lock(actual: &EnvironmentLock, expected: &EnvironmentLock) -> Result<()> {
    ensure!(
        serde_json::to_value(actual)? == serde_json::to_value(expected)?,
        "Audit lock input mismatch: run lock and apply explicitly"
    );
    Ok(())
}

fn store_path(value: &str, binary: bool) -> Result<()> {
    let path = Path::new(value);
    ensure!(
        value.starts_with("/nix/store/")
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != "..")
            && path.components().count() == if binary { 6 } else { 4 }
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "Invalid Nix output path"
    );
    let name = value
        .strip_prefix("/nix/store/")
        .and_then(|value| value.split('/').next())
        .ok_or_else(|| invalid("Missing Nix object"))?;
    let (hash, suffix) = name
        .split_once('-')
        .ok_or_else(|| invalid("Missing Nix object identity"))?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && !suffix.is_empty(),
        "Invalid Nix object identity"
    );
    Ok(())
}

fn runtime_spec() -> Sources {
    Sources {
        include: ["Cargo.toml", "Cargo.lock", "LICENSE", "src", "crates"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        exclude: Vec::new(),
    }
}

pub fn runtime_sources(resources: &Path) -> Result<Snapshot> {
    freeze_runtime(resources, None)
}

/// Bind the Lady workspace and its Cargo lock before Nix builds the runtime.
fn freeze_runtime(resources: &Path, destination: Option<&Path>) -> Result<Snapshot> {
    sources::snapshot(resources, &runtime_spec(), destination)
}
