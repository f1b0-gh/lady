use ladyshell::{environment_lock, files, nickel::Evaluated};
use serde_json::{json, Value};
use std::{error::Error, fs, path::Path, process::Command};

const REGISTRY_LOCK: &str = "\
version = 3

[[package]]
name = \"nickel-util\"
version = \"0.1.0\"
source = \"registry+https://github.com/rust-lang/crates.io-index\"
checksum = \"0000000000000000000000000000000000000000000000000000000000000000\"
";

fn evaluated() -> Result<Evaluated, Box<dyn Error>> {
    Ok(serde_json::from_value(json!({
        "config": {
            "schema_version": 1, "name": "audit-fixture", "mission": "dev",
            "sources": {"include": ["src", "Cargo.toml"], "exclude": []},
            "tools": {"rust": {"version": "1.99.1", "phase": "runtime"}},
            "checks": [], "resolved_missions": ["dev"],
            "sandbox": {"gateway": "test", "workspace": "default", "provider": "test"},
            "permissions": {"network": [], "filesystem": []},
            "image": {"backend": "nix", "profile": "openshell-native", "platform": "x86_64-linux"},
            "sync": {"mode": "files", "destination": "exports"},
            "audit": {
                "profile": "quick", "scope_paths": ["src"], "exclude_paths": [],
                "tools": {}, "checks": [["cargo", "test", "--offline"]],
                "budget": {"invocations": 8, "seconds": 300},
                "limits": {"cpu_seconds": 30, "memory_bytes": 268435456,
                    "processes": 32, "files": 128, "disk_bytes": 67108864}
            }
        },
        "modules_sha256": {}, "schema_sha256": "fixture", "flake_lock_sha256": "fixture",
        "evaluator": "/nix/store/fixture/bin/nickel"
    }))?)
}

fn resources(root: &Path) -> Result<(), Box<dyn Error>> {
    for (name, content) in [
        (
            "Cargo.toml",
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        ),
        ("Cargo.lock", REGISTRY_LOCK),
        ("LICENSE", "Synthetic project license\n"),
        ("src/main.rs", "fn main() {}\n"),
        (
            "crates/helper/Cargo.toml",
            "[package]\nname = \"helper\"\nversion = \"0.1.0\"\n",
        ),
        ("crates/helper/src/lib.rs", "pub fn helper() {}\n"),
        (
            "crates/ladyshell/resources/audit/security-audit/SKILL.md",
            "Fixture instructions\n",
        ),
        (
            "crates/ladyshell/resources/audit/agent-response-schema.json",
            "{}\n",
        ),
        ("nix/flake.nix", "{}\n"),
        ("nix/flake.lock", "{}\n"),
        ("nix/build.nix", "{}\n"),
        ("nix/image.nix", "{}\n"),
        ("nix/dependencies.nix", "{}\n"),
        ("nix/openssl.nix", "{}\n"),
        ("nix/tpm2-tss.nix", "{}\n"),
        ("nix/network-tools.nix", "{}\n"),
        ("nix/runtime.nix", "{}\n"),
        ("nix/audit-build.nix", "{}\n"),
        ("nix/audit-image.nix", "{}\n"),
    ] {
        let path = root.join(name);
        fs::create_dir_all(path.parent().ok_or("parent")?)?;
        fs::write(path, content)?;
    }
    Ok(())
}

#[test]
fn audit_lock_binds_target_runtime_sources_and_audit_recipes() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    resources(dir.path())?;
    let artifact = dir.path().join("codex");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let receipt = environment_lock::create(evaluated()?, dir.path(), &artifact, &artifact)?;
    for (key, file) in [
        ("openssl.nix", "nix/openssl.nix"),
        ("tpm2-tss.nix", "nix/tpm2-tss.nix"),
        ("network-tools.nix", "nix/network-tools.nix"),
        ("runtime.nix", "nix/runtime.nix"),
        ("audit-build.nix", "nix/audit-build.nix"),
        ("audit-image.nix", "nix/audit-image.nix"),
        ("runtime-source/Cargo.toml", "Cargo.toml"),
        ("runtime-source/Cargo.lock", "Cargo.lock"),
        ("runtime-source/LICENSE", "LICENSE"),
        ("runtime-source/src/main.rs", "src/main.rs"),
        (
            "runtime-source/crates/helper/Cargo.toml",
            "crates/helper/Cargo.toml",
        ),
        (
            "runtime-source/crates/helper/src/lib.rs",
            "crates/helper/src/lib.rs",
        ),
        (
            "runtime-source/crates/ladyshell/resources/audit/agent-response-schema.json",
            "crates/ladyshell/resources/audit/agent-response-schema.json",
        ),
    ] {
        assert_eq!(
            receipt.recipes_sha256.get(key),
            Some(&files::hash(&fs::read(dir.path().join(file))?)),
            "unlocked input: {key}"
        );
    }
    Ok(())
}

#[test]
fn changed_native_tpm_recipe_invalidates_development_and_audit_locks() -> Result<(), Box<dyn Error>>
{
    for auditing in [false, true] {
        let dir = tempfile::tempdir()?;
        resources(dir.path())?;
        let artifact = dir.path().join("codex");
        fs::write(&artifact, b"\x7fELFfixture")?;
        let mut config = evaluated()?;
        if !auditing {
            config.config.audit = None;
        }
        let original = environment_lock::create(config.clone(), dir.path(), &artifact, &artifact)?;
        let lock_path = dir.path().join("environment.lock.json");
        environment_lock::write(&lock_path, &original)?;
        fs::write(
            dir.path().join("nix/tpm2-tss.nix"),
            b"changed native library source\n",
        )?;
        let changed = environment_lock::create(config, dir.path(), &artifact, &artifact)?;
        assert!(environment_lock::verify(&lock_path, &changed).is_err());
    }
    Ok(())
}

#[test]
fn changed_runtime_or_recipe_invalidates_only_audit_locks() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    resources(dir.path())?;
    let artifact = dir.path().join("codex");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let audit = evaluated()?;
    let mut development = audit.clone();
    development.config.audit = None;
    let original = environment_lock::create(audit.clone(), dir.path(), &artifact, &artifact)?;
    let development_lock = serde_json::to_value(environment_lock::create(
        development.clone(),
        dir.path(),
        &artifact,
        &artifact,
    )?)?;
    let lock_path = dir.path().join("environment.lock.json");
    environment_lock::write(&lock_path, &original)?;
    for name in ["src/main.rs", "LICENSE", "nix/audit-image.nix"] {
        let path = dir.path().join(name);
        let previous = fs::read(&path)?;
        fs::write(&path, b"changed trusted input\n")?;
        let changed = environment_lock::create(audit.clone(), dir.path(), &artifact, &artifact)?;
        assert!(
            environment_lock::verify(&lock_path, &changed).is_err(),
            "unbound input: {name}"
        );
        let after: Value = serde_json::to_value(environment_lock::create(
            development.clone(),
            dir.path(),
            &artifact,
            &artifact,
        )?)?;
        assert_eq!(development_lock, after);
        fs::write(path, previous)?;
    }
    Ok(())
}

#[test]
fn changed_network_recipe_invalidates_development_and_audit_locks() -> Result<(), Box<dyn Error>> {
    for auditing in [false, true] {
        let dir = tempfile::tempdir()?;
        resources(dir.path())?;
        let artifact = dir.path().join("codex");
        fs::write(&artifact, b"\x7fELFfixture")?;
        let mut config = evaluated()?;
        if !auditing {
            config.config.audit = None;
        }
        let original = environment_lock::create(config.clone(), dir.path(), &artifact, &artifact)?;
        let lock_path = dir.path().join("environment.lock.json");
        environment_lock::write(&lock_path, &original)?;
        let locked_bytes = fs::read(&lock_path)?;
        fs::write(
            dir.path().join("nix/network-tools.nix"),
            b"changed curl input\n",
        )?;
        let changed = environment_lock::create(config, dir.path(), &artifact, &artifact)?;
        assert!(environment_lock::verify(&lock_path, &changed).is_err());
        assert_eq!(fs::read(&lock_path)?, locked_bytes);
    }
    Ok(())
}

#[test]
fn network_recipe_must_be_regular_and_present() -> Result<(), Box<dyn Error>> {
    for auditing in [false, true] {
        for symlink in [false, true] {
            let dir = tempfile::tempdir()?;
            resources(dir.path())?;
            let artifact = dir.path().join("codex");
            fs::write(&artifact, b"\x7fELFfixture")?;
            let mut config = evaluated()?;
            if !auditing {
                config.config.audit = None;
            }
            let recipe = dir.path().join("nix/network-tools.nix");
            fs::remove_file(&recipe)?;
            if symlink {
                let target = dir.path().join("same-bytes.nix");
                fs::write(&target, b"{}\n")?;
                std::os::unix::fs::symlink(target, recipe)?;
            }
            assert!(environment_lock::create(config, dir.path(), &artifact, &artifact).is_err());
        }
    }
    Ok(())
}

fn current(root: &Path) -> Result<(Value, ladyshell::sources::Snapshot), Box<dyn Error>> {
    let distribution = root.join("distribution");
    resources(&distribution)?;
    let project = root.join("project");
    fs::create_dir_all(project.join("src"))?;
    fs::write(project.join("src/main.rs"), "project data, never execute\n")?;
    fs::write(project.join("Cargo.toml"), "manifest is source data\n")?;
    let artifact = root.join("codex");
    fs::write(&artifact, b"\x7fELFfixture")?;
    let evaluated = evaluated()?;
    let lock = environment_lock::create(evaluated.clone(), &distribution, &artifact, &artifact)?;
    let snapshot = ladyshell::sources::snapshot(&project, &evaluated.config.sources, None)?;
    fs::create_dir(root.join("run"))?;
    Ok((
        json!({"desired_inputs": {
            "project": project, "resources": distribution, "evaluated": evaluated,
            "environment_lock": lock,
            "artifacts": {
                "codex": {"path": artifact, "sha256": files::hash(b"\x7fELFfixture")},
                "codex-code-mode-host": {"path": artifact, "sha256": files::hash(b"\x7fELFfixture")},
                "ladyshell": {"path": "/host/runtime/must/not/be/copied", "sha256": "unused"}
            }
        }}),
        snapshot,
    ))
}

// A child with an empty PATH cannot accidentally invoke a native builder if a
// rejection regresses. Its source fixtures are data, never host commands.
fn rejected(
    root: &Path,
    current: &Value,
    snapshot: &ladyshell::sources::Snapshot,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    run_probe(root, current, snapshot, reason, Path::new("/nonexistent"))
}

fn run_probe(
    root: &Path,
    current: &Value,
    snapshot: &ladyshell::sources::Snapshot,
    reason: &str,
    search_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let input = root.join("probe.json");
    fs::write(
        &input,
        serde_json::to_vec(
            &json!({"current": current, "snapshot": snapshot, "run": root.join("run")}),
        )?,
    )?;
    let result = Command::new(std::env::current_exe()?)
        .args(["--exact", "rejection_probe", "--nocapture"])
        .env_clear()
        .env("PATH", search_path)
        .env("LADYSHELL_IMAGE_PROBE", input)
        .env("LADYSHELL_IMAGE_REASON", reason)
        .output()?;
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read_dir(root.join("run"))?.count(), 0);
    Ok(())
}

#[test]
fn rejection_probe() -> Result<(), Box<dyn Error>> {
    let Some(path) = std::env::var_os("LADYSHELL_IMAGE_PROBE") else {
        return Ok(());
    };
    let input: Value = serde_json::from_slice(&fs::read(path)?)?;
    let expected = serde_json::from_value(input["snapshot"].clone())?;
    let error = ladyshell::audit::image::build(
        &input["current"],
        Path::new(input["run"].as_str().ok_or("run")?),
        &expected,
    )
    .err()
    .ok_or("build unexpectedly accepted invalid inputs")?;
    let reason = std::env::var("LADYSHELL_IMAGE_REASON")?;
    assert!(
        error.to_string().contains(&reason),
        "expected {reason:?}, got {error}"
    );
    Ok(())
}

#[test]
fn image_rejects_changed_runtime_recipe_or_codex_before_builder() -> Result<(), Box<dyn Error>> {
    for name in [
        "distribution/Cargo.toml",
        "distribution/crates/helper/Cargo.toml",
        "distribution/src/main.rs",
        "distribution/nix/audit-image.nix",
        "distribution/nix/openssl.nix",
        "distribution/nix/tpm2-tss.nix",
        "distribution/nix/network-tools.nix",
        "codex",
    ] {
        let dir = tempfile::tempdir()?;
        let (current, expected) = current(dir.path())?;
        fs::write(dir.path().join(name), b"\x7fELFmodified input\n")?;
        rejected(dir.path(), &current, &expected, "lock")?;
    }
    Ok(())
}

#[test]
fn image_rejects_source_bytes_changed_after_plan() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let (current, expected) = current(dir.path())?;
    fs::write(
        dir.path().join("project/src/main.rs"),
        "changed since audit plan\n",
    )?;
    rejected(dir.path(), &current, &expected, "Sources changed")
}

#[test]
fn image_rejects_audit_tool_version_conflict_before_builder() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let (mut current, expected) = current(dir.path())?;
    let desired = &mut current["desired_inputs"];
    desired["evaluated"]["config"]["audit"]["tools"]["rust"] =
        json!({"version": "1.97.0", "phase": "runtime"});
    let evaluated = serde_json::from_value(desired["evaluated"].clone())?;
    desired["environment_lock"] = serde_json::to_value(environment_lock::create(
        evaluated,
        &dir.path().join("distribution"),
        &dir.path().join("codex"),
        &dir.path().join("codex"),
    )?)?;
    rejected(dir.path(), &current, &expected, "toolchain conflict")
}

#[test]
fn image_rejects_legacy_audit_lock_before_builder() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let (mut current, expected) = current(dir.path())?;
    current["desired_inputs"]["environment_lock"]["recipes_sha256"]
        .as_object_mut()
        .ok_or("recipes")?
        .retain(|key, _| {
            !key.starts_with("runtime-source/")
                && key != "audit-build.nix"
                && key != "audit-image.nix"
                && key != "runtime.nix"
        });
    rejected(dir.path(), &current, &expected, "lock")
}

#[test]
fn builder_receives_frozen_complete_sources_union_tools_and_target_runtime(
) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir()?;
    let (mut current, _) = current(dir.path())?;
    let script = dir.path().join("project/src/check.sh");
    fs::write(&script, "project source, must not execute on host\n")?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
    let desired = &mut current["desired_inputs"];
    desired["sources"] = json!({"old-applied-snapshot": {"sha256": "different"}});
    desired["evaluated"]["config"]["audit"]["tools"]["node"] =
        json!({"version": "24.22.2", "phase": "runtime"});
    let evaluated: Evaluated = serde_json::from_value(desired["evaluated"].clone())?;
    let expected =
        ladyshell::sources::snapshot(&dir.path().join("project"), &evaluated.config.sources, None)?;
    desired["environment_lock"] = serde_json::to_value(environment_lock::create(
        evaluated,
        &dir.path().join("distribution"),
        &dir.path().join("codex"),
        &dir.path().join("codex"),
    )?)?;
    let capture = dir.path().join("capture");
    let mockbin = dir.path().join("mockbin");
    fs::create_dir(&capture)?;
    fs::create_dir(&mockbin)?;
    let capture_quote = format!("'{}'", capture.display().to_string().replace('\'', "'\\''"));
    fs::write(mockbin.join("nix"), format!("#!/bin/sh\nrecord={capture_quote}\nprintf '%s\\n' \"$@\" > \"$record/argv\"\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --argstr ]; then\n    case \"$2\" in\n      sourcePath) /bin/cp -a -- \"$3\" \"$record/source\" ;;\n      configPath) /bin/cp -- \"$3\" \"$record/config.json\" ;;\n      runtimeSourcePath) /bin/cp -a -- \"$3\" \"$record/runtime\" ;;\n    esac\n    shift 3\n  else\n    shift\n  fi\ndone\nprintf 'controlled audit build stop\\n' >&2\nexit 37\n"))?;
    fs::set_permissions(mockbin.join("nix"), fs::Permissions::from_mode(0o755))?;
    run_probe(
        dir.path(),
        &current,
        &expected,
        "controlled audit build stop",
        &mockbin,
    )?;
    assert_eq!(
        fs::read(capture.join("source/Cargo.toml"))?,
        b"manifest is source data\n"
    );
    assert_ne!(
        fs::metadata(capture.join("source/src/check.sh"))?
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        fs::read(capture.join("runtime/src/main.rs"))?,
        b"fn main() {}\n"
    );
    assert_eq!(
        fs::read_to_string(capture.join("runtime/Cargo.lock"))?,
        REGISTRY_LOCK
    );
    assert!(capture.join("runtime/nix/runtime.nix").is_file());
    assert_eq!(
        fs::read(capture.join("runtime/nix/network-tools.nix"))?,
        b"{}\n"
    );
    assert!(!capture.join("runtime/ladyshell").exists());
    let config: Value = serde_json::from_slice(&fs::read(capture.join("config.json"))?)?;
    assert_eq!(config["tools"]["rust"]["version"], "1.99.1");
    assert_eq!(config["tools"]["node"]["version"], "24.22.2");
    let argv = fs::read_to_string(capture.join("argv"))?;
    assert!(argv.contains("--no-write-lock-file\n"));
    assert!(!argv.contains("\nruntimePath\n"));
    Ok(())
}

#[test]
fn native_nix_evaluation_preserves_image_identity_and_refuses_wrong_toolchain(
) -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Production evaluates an immutable runtime snapshot. Keep this identity
    // test independent of edits in the live checkout during the two evaluations.
    let runtime = dir.path().join("runtime");
    resources(&runtime)?;
    fs::write(
        runtime.join("Cargo.lock"),
        "version = 3\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )?;
    let config = dir.path().join("config.json");
    fs::write(
        &config,
        br#"{"name":"catalogue-fixture","tools":{"rust":{"version":"1.99.1"},"node":{"version":"24.22.2"}}}"#,
    )?;
    let codex = dir.path().join("codex");
    fs::write(&codex, b"\x7fELFfixture")?;
    let expression = dir.path().join("evaluate.nix");
    fs::write(
        &expression,
        r#"let
  root = builtins.getEnv "LADYSHELL_NIX_TEST_ROOT";
  config = builtins.getEnv "LADYSHELL_NIX_TEST_CONFIG";
  source = builtins.getEnv "LADYSHELL_NIX_TEST_SOURCE";
  codex = builtins.getEnv "LADYSHELL_NIX_TEST_CODEX";
  runtime = builtins.getEnv "LADYSHELL_NIX_TEST_RUNTIME";
  flake = builtins.getFlake ("path:" + root + "/nix");
  pkgs = import flake.inputs.nixpkgs { system = "x86_64-linux"; };
  built = import (root + "/nix/audit-image.nix") {
    inherit pkgs;
    configPath = builtins.toPath config;
    sourcePath = builtins.toPath source;
    codexPath = builtins.toPath codex;
    codexHostPath = builtins.toPath codex;
    runtimeSourcePath = builtins.toPath runtime;
    imageName = "ladyshell-audit-test";
  };
  development = flake.lib.mkImage {
    configPath = builtins.toPath config;
    sourcePath = builtins.toPath source;
    codexPath = builtins.toPath codex;
    codexHostPath = builtins.toPath codex;
    runtimePath = builtins.toPath codex;
    auditPath = builtins.toPath (root + "/crates/ladyshell/resources/audit");
  };
in { inherit (built) config;
  developmentArchive = toString development;
  archive = toString built.archive;
  runtime = toString built.runtime;
  codex = toString built.codex;
  metadata = (import (root + "/nix/audit-build.nix") {
    flakePath = root + "/nix";
    configPath = config;
    sourcePath = source;
    codexPath = codex;
    codexHostPath = codex;
    runtimeSourcePath = runtime;
    imageName = "ladyshell-audit-test";
  }).metadata;
}
"#,
    )?;
    let eval = || -> Result<std::process::Output, Box<dyn Error>> {
        Ok(Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command flakes",
                "eval",
                "--impure",
                "--json",
                "--offline",
                "--file",
            ])
            .arg(&expression)
            .env("LADYSHELL_NIX_TEST_ROOT", root)
            .env("LADYSHELL_NIX_TEST_CONFIG", &config)
            .env("LADYSHELL_NIX_TEST_SOURCE", dir.path())
            .env("LADYSHELL_NIX_TEST_CODEX", &codex)
            .env("LADYSHELL_NIX_TEST_RUNTIME", &runtime)
            .output()?)
    };
    let result = eval()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(value["config"]["User"], "10001:10001");
    assert_eq!(value["config"]["WorkingDir"], "/workspace");
    assert_eq!(value["config"]["Cmd"], json!(["/bin/sleep", "infinity"]));
    assert!(value["developmentArchive"]
        .as_str()
        .ok_or("development archive")?
        .contains("ladyshell-catalogue-fixture"));
    assert!(value["runtime"]
        .as_str()
        .ok_or("runtime")?
        .ends_with("-ladyshell-0.1.0"));
    assert!(value["codex"]
        .as_str()
        .ok_or("codex")?
        .ends_with("-ladyshell-codex"));
    assert_eq!(value["metadata"]["archive"], value["archive"]);
    assert_eq!(
        value["metadata"]["runtime_binary"],
        format!(
            "{}/bin/ladyshell",
            value["runtime"].as_str().ok_or("runtime")?
        )
    );
    assert_eq!(
        value["metadata"]["codex_binary"],
        format!("{}/bin/codex", value["codex"].as_str().ok_or("codex")?)
    );
    fs::write(&config, br#"{"tools":{"rust":{"version":"0.0.1"}}}"#)?;
    let failure = eval()?;
    assert!(!failure.status.success());
    assert!(
        String::from_utf8_lossy(&failure.stderr).contains("Exact toolchain version unavailable")
    );
    Ok(())
}

#[test]
fn image_rejects_registry_checksum_or_source_drift_before_builder() -> Result<(), Box<dyn Error>> {
    for (original, changed) in [
        ("crates.io-index", "other-index"),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let dir = tempfile::tempdir()?;
        let (current, expected) = current(dir.path())?;
        let lock_path = dir.path().join("distribution/Cargo.lock");
        let modified = REGISTRY_LOCK.replace(original, changed);
        fs::write(&lock_path, &modified)?;
        rejected(dir.path(), &current, &expected, "lock")?;
        assert_eq!(fs::read_to_string(lock_path)?, modified);
    }
    Ok(())
}

#[test]
fn audit_lock_refuses_sibling_copy_of_missing_workspace_lock() -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let distribution = temp.path().join("lady");
    resources(&distribution)?;
    let sibling = temp.path().join("nickeling");
    resources(&sibling)?;
    let artifact = temp.path().join("codex");
    fs::write(&artifact, b"\x7fELFfixture")?;
    environment_lock::create(evaluated()?, &distribution, &artifact, &artifact)?;
    fs::remove_file(distribution.join("Cargo.lock"))?;
    assert!(environment_lock::create(evaluated()?, &distribution, &artifact, &artifact).is_err());
    Ok(())
}
