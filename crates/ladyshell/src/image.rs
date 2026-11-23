use crate::{
    config::{relative_path, ResolvedConfig},
    environment_lock,
    error::{ensure, Error, Result},
    files, policy,
    process::capture,
    sources::{self, Snapshot},
    state::text,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::Path,
    process::Command,
    time::Duration,
};
mod broker;
fn archive_reader(path: &Path) -> Result<Box<dyn Read>> {
    let mut file = BufReader::new(files::open_regular(path)?);
    let gzip = file.fill_buf()?.starts_with(&[0x1f, 0x8b]);
    if gzip {
        Ok(Box::new(flate2::read::GzDecoder::new(file)))
    } else {
        Ok(Box::new(file))
    }
}
fn member(path: &Path, name: &str) -> Result<Vec<u8>> {
    relative_path(name)?;
    let mut archive = tar::Archive::new(archive_reader(path)?.take(8 * 1024 * 1024 * 1024));
    let mut result = None;
    for (index, entry) in archive.entries()?.enumerate() {
        ensure!(index < 100000, "Image archive has too many members");
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new(name) {
            ensure!(result.is_none(), "Duplicate image member");
            ensure!(
                entry.header().entry_type().is_file() && entry.size() <= 16 * 1024 * 1024,
                "Invalid image metadata"
            );
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            result = Some(bytes);
        }
    }
    result.ok_or_else(|| invalid(format!("Missing image member: {name}")))
}
pub fn archive_image_id(path: &Path) -> Result<String> {
    let manifest: Value = serde_json::from_slice(&member(path, "manifest.json")?)?;
    let rows = manifest
        .as_array()
        .ok_or_else(|| invalid("Invalid image manifest".into()))?;
    ensure!(rows.len() == 1, "Exactly one image is required");
    let row = rows
        .first()
        .ok_or_else(|| invalid("Empty image manifest".into()))?;
    let name = text(row, "Config")?;
    Ok(format!("sha256:{}", files::hash(&member(path, name)?)))
}
fn run(args: &[&str], timeout: u64) -> Result<String> {
    let (name, rest) = args
        .split_first()
        .ok_or_else(|| invalid("Empty command".into()))?;
    let mut command = Command::new(name);
    command.args(rest);
    Ok(String::from_utf8(capture(
        command,
        Duration::from_secs(timeout),
        8 * 1024 * 1024,
    )?)?
    .trim()
    .into())
}
pub fn load_archive(archive: &str, image_id: &str) -> Result<()> {
    run(&["docker", "load", "-i", archive], 180)?;
    ensure!(
        run(
            &["docker", "image", "inspect", image_id, "--format", "{{.Id}}"],
            30
        )? == image_id,
        "Loaded image identity mismatch"
    );
    Ok(())
}
pub fn build(desired: &Value, directory: &Path, migration: Option<&Value>) -> Result<Value> {
    let selected: ResolvedConfig = serde_json::from_value(desired["evaluated"]["config"].clone())?;
    if selected.image == crate::config::Image::broker() {
        return broker::build(desired, directory, migration);
    }
    ensure!(
        selected.image == crate::config::Image::default(),
        "Unsupported image profile"
    );
    let out = tempfile::Builder::new()
        .prefix("build-")
        .tempdir_in(directory)?
        .keep();
    let mut source = out.join("project");
    fs::create_dir(&source)?;
    let config: ResolvedConfig = serde_json::from_value(desired["evaluated"]["config"].clone())?;
    let actual = sources::snapshot(
        Path::new(text(desired, "project")?),
        &config.sources,
        Some(&source),
    )?;
    ensure!(
        serde_json::to_value(&actual)? == desired["sources"],
        "Sources changed since plan"
    );
    if let Some(migration) = migration {
        let base: Snapshot = serde_json::from_value(migration["base"].clone())?;
        let remote: Snapshot = serde_json::from_value(migration["remote"].clone())?;
        let chosen = crate::merge::merge_files(&base, &actual, &remote)?;
        let merged = out.join("merged-project");
        fs::create_dir(&merged)?;
        for (name, record) in chosen {
            relative_path(&name)?;
            let origin = if record.origin == "remote" {
                Path::new(text(migration, "directory")?)
            } else {
                &source
            };
            let data = files::read_limited(&origin.join(&name), 16 * 1024 * 1024)?;
            ensure!(
                files::hash(&data) == record.sha256,
                "Merge source changed: {name}"
            );
            write_source(&merged, &name, &data, record.executable)?;
        }
        source = merged;
    }
    for name in ["codex", "codex-code-mode-host", "ladyshell"] {
        let record = &desired["artifacts"][name];
        let original = Path::new(text(record, "path")?);
        let mut input = files::open_regular(original)?.take(1024 * 1024 * 1024 + 1);
        let target = out.join(name);
        let mut output = File::create(&target)?;
        let size = std::io::copy(&mut input, &mut output)?;
        ensure!(size <= 1024 * 1024 * 1024, "Artifact is too large");
        drop(output);
        ensure!(
            environment_lock::artifact_hash(&target)? == text(record, "sha256")?,
            "Artifact changed since plan: {name}"
        );
    }
    environment_lock::atomic_json(&out.join("config.json"), &config)?;
    let dependencies = if let Some(dependencies) = &config.dependencies {
        let staged = sources::snapshot(&source, &config.sources, None)?;
        let inventory = crate::deps::scan_snapshot(&source, &staged)?;
        ensure!(
            serde_json::to_value(&inventory.inputs)? == desired["dependency_inventory"]["inputs"],
            "Dependency manifests changed since plan; explicitly replan"
        );
        let preparation =
            crate::deps::prepare::plan(&source, &staged, dependencies, &config.tools)?;
        files::publish_json(&out.join("preparation.json"), &preparation, false)?;
        Some(json!({"schema_version":1,
            "preparation_sha256":files::hash(&files::read_limited(&out.join("preparation.json"), 16 * 1024 * 1024)?),
            "manifest_inputs":inventory.inputs,"tools":config.tools,
            "projects":dependencies.projects,"allowed_hosts":dependencies.allowed_hosts}))
    } else {
        None
    };
    let resources = Path::new(text(desired, "resources")?);
    let nix = resources.join("nix");
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--impure",
            "--no-link",
            "--print-out-paths",
            "--file",
        ])
        .arg(nix.join("build.nix"));
    for (name, value) in [
        ("flakePath", nix),
        ("configPath", out.join("config.json")),
        ("sourcePath", source.clone()),
        ("codexPath", out.join("codex")),
        ("codexHostPath", out.join("codex-code-mode-host")),
        ("runtimePath", out.join("ladyshell")),
    ] {
        command.arg("--argstr").arg(name).arg(value);
    }
    if dependencies.is_some() {
        command
            .arg("--argstr")
            .arg("preparationPath")
            .arg(out.join("preparation.json"))
            .args(["--option", "sandbox", "true"]);
    }
    let archive = String::from_utf8(capture(command, Duration::from_secs(900), 8 * 1024 * 1024)?)?;
    let archive = archive.trim();
    ensure!(
        archive.starts_with("/nix/store/") && !archive.contains('\n'),
        "Unexpected Nix output"
    );
    let image_id = archive_image_id(Path::new(archive))?;
    load_archive(archive, &image_id)?;
    let uid = run(
        &[
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            &image_id,
            "/bin/id",
            "-u",
        ],
        30,
    )?;
    ensure!(uid == "10001", "Incorrect image identity");
    run(
        &[
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            &image_id,
            "/bin/test",
            "-w",
            ".",
        ],
        30,
    )?;
    for (tool, spec) in &config.tools {
        let executable = if tool == "rust" { "rustc" } else { tool };
        let binary = format!("/bin/{executable}");
        let probe: Vec<&str> = match tool.as_str() {
            "zig" | "openssl" => vec![&binary, "version"],
            "perl" => vec![&binary, "-e", "printf '%vd', $^V"],
            "pydantic" | "jsonschema" | "setuptools" => vec![
                "/bin/python3",
                "-P",
                "-c",
                "import importlib.metadata, sys; print(importlib.metadata.version(sys.argv[1]))",
                tool,
            ],
            "tpm2-tss" => vec!["/bin/pkg-config", "--modversion", "tss2-esys"],
            _ => vec![&binary, "--version"],
        };
        // Trusted version probes must not import Python modules from project sources.
        let mut command = vec![
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--workdir",
            "/tmp",
            &image_id,
        ];
        command.extend(probe);
        let version = run(&command, 30)?;
        ensure!(
            tool_version_matches(executable, &version, &spec.version),
            "Incorrect effective version: {tool}"
        );
        if tool == "rust" {
            let cargo = run(
                &[
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    &image_id,
                    "/bin/cargo",
                    "--version",
                ],
                30,
            )?;
            // Cargo is pinned by the same Nix closure. Its patch release need not
            // equal rustc's (e.g. Rust 1.98.1 ships Cargo 1.98.0).
            ensure!(
                cargo.split_whitespace().next() == Some("cargo"),
                "Cargo is unavailable in the Rust toolchain"
            );
        }
    }
    let binary = run(
        &[
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            &image_id,
            "/bin/readlink",
            "-f",
            "/usr/local/bin/codex",
        ],
        30,
    )?;
    run(
        &[
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            &image_id,
            "/usr/local/bin/ladyshell",
            "--version",
        ],
        30,
    )?;
    let policy_path = out.join("policy.yaml");
    environment_lock::atomic_json(&policy_path, &policy::native_policy(&binary)?)?;
    Ok(
        json!({"image_id":image_id,"archive":archive,"policy_path":policy_path,"build_dir":out,"project_snapshot":source,"host_sources":actual,"codex_binary":binary,"dependencies":dependencies}),
    )
}
pub fn tool_version_matches(tool: &str, output: &str, expected: &str) -> bool {
    if tool == "python" || tool == "python3" {
        output.trim() == format!("Python {expected}")
    } else if matches!(tool, "rustc" | "cargo") {
        let mut parts = output.split_whitespace();
        parts.next() == Some(tool) && parts.next() == Some(expected)
    } else if matches!(tool, "cmake" | "make" | "openssl" | "maturin" | "uv") {
        let prefix = match tool {
            "cmake" => "cmake version ",
            "make" => "GNU Make ",
            "openssl" => "OpenSSL ",
            "uv" => "uv ",
            _ => "maturin ",
        };
        output
            .strip_prefix(prefix)
            .and_then(|rest| rest.split_whitespace().next())
            == Some(expected)
    } else {
        output.trim().trim_start_matches('v') == expected
    }
}
pub fn write_source(root: &Path, name: &str, data: &[u8], executable: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    relative_path(name)?;
    let target = root.join(name);
    let parent = target
        .parent()
        .ok_or_else(|| invalid("Missing export parent".into()))?;
    fs::create_dir_all(parent)?;
    files::open_directory(parent)?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&target)?;
    std::io::Write::write_all(&mut file, data)?;
    file.set_permissions(fs::Permissions::from_mode(if executable {
        0o755
    } else {
        0o644
    }))?;
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
