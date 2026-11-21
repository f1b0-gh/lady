use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn write(root: &Path, name: &str, content: &str) -> std::io::Result<()> {
    let file = root.join(name);
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(file, content)
}

fn scan(root: &Path) -> Result<(bool, Value), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["scan", "--project"])
        .arg(root)
        .arg("--json")
        .output()?;
    assert!(
        !output.stdout.is_empty(),
        "scan must produce a report: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((
        output.status.success(),
        serde_json::from_slice(&output.stdout)?,
    ))
}

fn scan_sources(root: &Path, sources: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["scan", "--project"])
        .arg(root)
        .arg("--sources")
        .arg(sources)
        .arg("--json")
        .output()
}

#[test]
fn selected_sources_ignore_excluded_links_and_match_the_library_deterministically(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    write(
        root.path(),
        "app/package.json",
        r#"{"name":"selected","version":"1.0.0"}"#,
    )?;
    write(root.path(), "unselected/Cargo.toml", "invalid manifest")?;
    write(config.path(), "private", "PRIVATE_SENTINEL")?;
    std::os::unix::fs::symlink(
        config.path().join("private"),
        root.path().join("app/runtime"),
    )?;
    std::os::unix::fs::symlink(
        config.path().join("private"),
        root.path().join("unselected-link"),
    )?;
    let spec = json!({"include":["app"],"exclude":["app/runtime"]});
    write(config.path(), "sources.json", &spec.to_string())?;
    let sources_path = config.path().join("sources.json");
    let output = scan_sources(root.path(), &sources_path)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["complete"], true);
    assert_eq!(
        report["projects"]
            .as_array()
            .ok_or("projects missing")?
            .len(),
        1
    );
    assert_eq!(report["projects"][0]["root"], "app");
    assert_eq!(
        report["inputs"]
            .as_object()
            .ok_or("inputs missing")?
            .keys()
            .collect::<Vec<_>>(),
        vec!["app/package.json"]
    );
    let spec: ladybom::sources::Sources = serde_json::from_value(spec)?;
    let snapshot = ladybom::sources::snapshot(root.path(), &spec, None)?;
    assert_eq!(
        report,
        serde_json::to_value(ladybom::deps::scan_snapshot(root.path(), &snapshot)?)?
    );
    let again = scan_sources(root.path(), &sources_path)?;
    assert!(again.status.success());
    assert_eq!(output.stdout, again.stdout);
    Ok(())
}

#[test]
fn selected_source_links_are_rejected_without_reading_the_target(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    write(config.path(), "private", "PRIVATE_SENTINEL")?;
    std::os::unix::fs::symlink(
        config.path().join("private"),
        root.path().join("Cargo.toml"),
    )?;
    write(
        config.path(),
        "sources.json",
        r#"{"include":["Cargo.toml"],"exclude":[]}"#,
    )?;
    let output = scan_sources(root.path(), &config.path().join("sources.json"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("Cargo.toml"), "{stderr}");
    assert!(!stderr.contains("PRIVATE_SENTINEL"));
    Ok(())
}

#[test]
fn selected_sources_reject_unnormalized_include_and_exclude_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    for field in ["include", "exclude"] {
        for path in ["../outside", "app/../outside", "/absolute", ".", ""] {
            let mut spec = json!({"include":[],"exclude":[]});
            spec[field] = json!([path]);
            write(config.path(), "sources.json", &spec.to_string())?;
            let output = scan_sources(root.path(), &config.path().join("sources.json"))?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            assert!(
                stderr.contains("Normalized relative path required"),
                "{field}={path}: {stderr}"
            );
        }
    }
    Ok(())
}

#[test]
fn sources_schema_rejects_unknown_fields() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    write(
        config.path(),
        "sources.json",
        r#"{"include":[],"exclude":[],"allow_network":true}"#,
    )?;
    let output = scan_sources(root.path(), &config.path().join("sources.json"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("unknown field") && stderr.contains("allow_network"),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn sources_file_is_bounded_to_one_mib() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    let mut content = r#"{"include":[],"exclude":[]}"#.to_string();
    content.push_str(&" ".repeat(1024 * 1024 - content.len()));
    write(config.path(), "sources.json", &content)?;
    let output = scan_sources(root.path(), &config.path().join("sources.json"))?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["projects"], json!([]));
    content.push(' ');
    write(config.path(), "sources.json", &content)?;
    let output = scan_sources(root.path(), &config.path().join("sources.json"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(stderr.contains("File is too large"), "{stderr}");
    Ok(())
}

#[test]
fn sources_file_rejects_symlinks_in_every_path_component() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    write(
        config.path(),
        "actual/sources.json",
        r#"{"include":[],"exclude":[]}"#,
    )?;
    std::os::unix::fs::symlink(
        config.path().join("actual/sources.json"),
        config.path().join("linked.json"),
    )?;
    std::os::unix::fs::symlink(
        config.path().join("actual"),
        config.path().join("linked-dir"),
    )?;
    for (path, component) in [
        ("linked.json", "linked.json"),
        ("linked-dir/sources.json", "linked-dir"),
    ] {
        let output = scan_sources(root.path(), &config.path().join(path))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(stderr.contains(component), "{stderr}");
    }
    Ok(())
}

#[test]
fn scans_python_rust_and_typescript_with_exact_locked_components_without_running_scripts(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "python/pyproject.toml",
        r#"
[project]
name = "py-demo"
version = "0.1.0"
requires-python = ">=3.11,<3.14"
dependencies = ["requests[socks]>=2.32; python_version >= '3.11'"]
[dependency-groups]
dev = ["pytest>=8"]
[build-system]
requires = ["hatchling>=1"]
build-backend = "hatchling.build"
"#,
    )?;
    write(
        root.path(),
        "python/uv.lock",
        r#"
version = 1
revision = 3
requires-python = ">=3.11,<3.14"
[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/requests.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]
[[package]]
name = "pytest"
version = "8.3.5"
source = { registry = "https://pypi.org/simple" }
"#,
    )?;
    write(
        root.path(),
        "rust/Cargo.toml",
        r#"
[package]
name = "rust-demo"
version = "0.1.0"
rust-version = "1.85"
[dependencies]
itoa = "1"
[build-dependencies]
cc = "1"
"#,
    )?;
    write(
        root.path(),
        "rust/rust-toolchain.toml",
        "[toolchain]\nchannel = '1.98.1'\n",
    )?;
    write(
        root.path(),
        "rust/Cargo.lock",
        r#"
version = 4
[[package]]
name = "itoa"
version = "1.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[[package]]
name = "rust-demo"
version = "0.1.0"
dependencies = ["itoa"]
"#,
    )?;
    write(
        root.path(),
        "web/package.json",
        &json!({
            "name": "web-demo", "version": "1.0.0", "engines": {"node": ">=22"},
            "packageManager": "npm@11.6.2", "dependencies": {"is-number": "^7.0.0"},
            "devDependencies": {"typescript": "~5.9.0"},
            "scripts": {"preinstall": "touch ../SHOULD_NOT_EXIST"}
        })
        .to_string(),
    )?;
    write(root.path(), "web/package-lock.json", &json!({
        "name": "web-demo", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "web-demo", "version": "1.0.0"},
            "node_modules/is-number": {"version": "7.0.0", "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", "integrity": "sha512-YQ=="},
            "node_modules/typescript": {"version": "5.9.3", "dev": true, "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.9.3.tgz", "integrity": "sha512-Yg=="}
        }
    }).to_string())?;
    write(
        root.path(),
        "python/setup.py",
        "raise RuntimeError('must not run')\n",
    )?;
    let (success, report) = scan(root.path())?;
    assert!(success, "{report}");
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["complete"], true);
    let projects = report["projects"].as_array().ok_or("projects missing")?;
    assert_eq!(projects.len(), 3);
    for (ecosystem, purl) in [
        ("python", "pkg:pypi/requests@2.32.3"),
        ("rust", "pkg:cargo/itoa@1.0.15"),
        ("npm", "pkg:npm/typescript@5.9.3"),
    ] {
        let project = projects
            .iter()
            .find(|p| p["ecosystem"] == ecosystem)
            .ok_or("ecosystem missing")?;
        assert_eq!(project["locked"], true);
        assert!(
            project["components"]
                .as_array()
                .ok_or("components missing")?
                .iter()
                .any(|c| c["purl"] == purl),
            "{project}"
        );
    }
    let python = projects
        .iter()
        .find(|p| p["ecosystem"] == "python")
        .ok_or("python missing")?;
    assert!(python["requirements"]
        .as_array()
        .ok_or("requirements missing")?
        .iter()
        .any(|r| r["name"] == "requests"
            && r["extras"] == json!(["socks"])
            && r["marker"] == "python_full_version >= '3.11'"));
    assert!(python["requirements"]
        .as_array()
        .ok_or("requirements missing")?
        .iter()
        .any(|r| r["name"] == "pytest" && r["kind"] == "group:dev"));
    assert!(!root.path().join("SHOULD_NOT_EXIST").exists());
    Ok(())
}

#[test]
fn missing_locks_preserve_declared_requirements_and_report_unresolved_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "pyproject.toml",
        "[project]\nname='demo'\nversion='1.0'\ndependencies=['idna>=3']\n",
    )?;
    let (success, report) = scan(root.path())?;
    assert!(success, "{report}");
    assert_eq!(report["projects"][0]["locked"], false);
    assert_eq!(report["projects"][0]["requirements"][0]["name"], "idna");
    assert!(report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?
        .iter()
        .any(|d| d["code"] == "missing_lockfile"));
    Ok(())
}

#[test]
fn malformed_manifest_returns_partial_report_and_failure() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    write(root.path(), "Cargo.toml", "[package\nname='broken'\n")?;
    let (success, report) = scan(root.path())?;
    assert!(!success);
    assert_eq!(report["complete"], false);
    assert!(report["diagnostics"]
        .as_array()
        .ok_or("diagnostics missing")?
        .iter()
        .any(|d| d["code"] == "invalid_manifest" && d["file"] == "Cargo.toml"));
    Ok(())
}

#[test]
fn npm_occurrences_with_same_purl_keep_distinct_contexts() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        "{\"name\":\"demo\",\"version\":\"1.0.0\"}",
    )?;
    write(
        root.path(),
        "package-lock.json",
        &json!({"lockfileVersion": 3, "packages": {
            "": {"name":"demo", "version":"1.0.0"},
            "node_modules/@scope/lib": {"version":"1.2.3"},
            "node_modules/parent/node_modules/@scope/lib": {"version":"1.2.3"}
        }})
        .to_string(),
    )?;
    let (success, report) = scan(root.path())?;
    assert!(success, "{report}");
    let components = report["projects"][0]["components"]
        .as_array()
        .ok_or("components missing")?;
    let variants: Vec<_> = components
        .iter()
        .filter(|c| c["purl"] == "pkg:npm/%40scope/lib@1.2.3")
        .collect();
    assert_eq!(variants.len(), 2);
    assert_ne!(variants[0]["context"], variants[1]["context"]);
    Ok(())
}

#[test]
fn manifest_symlink_is_rejected_without_reading_the_target(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let other = tempfile::tempdir()?;
    write(other.path(), "outside", "PRIVATE_SENTINEL")?;
    std::os::unix::fs::symlink(other.path().join("outside"), root.path().join("Cargo.toml"))?;
    let output = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["scan", "--project"])
        .arg(root.path())
        .arg("--json")
        .output()?;
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Cargo.toml"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_SENTINEL"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("PRIVATE_SENTINEL"));
    Ok(())
}

#[test]
fn unsupported_or_malformed_inputs_are_never_reported_complete(
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, content) in [
        ("setup.py", "raise RuntimeError('never run')"),
        ("package.json", r#"{"engines":{"node":22}}"#),
        (
            "Cargo.toml",
            "[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\nfoo=true\n",
        ),
        (
            "pyproject.toml",
            "[project]\nname='demo'\noptional-dependencies='invalid'\n",
        ),
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), name, content)?;
        let (success, report) = scan(root.path())?;
        assert!(!success, "{name}: {report}");
        assert_eq!(report["complete"], false);
    }
    Ok(())
}

#[test]
fn cargo_workspace_members_inherit_lock_requirements_and_toolchain(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    write(root.path(), "Cargo.toml", "[workspace]\nmembers=['crates/demo']\n[workspace.package]\nrust-version='1.85'\n[workspace.dependencies]\nitoa='1'\n")?;
    write(
        root.path(),
        "rust-toolchain.toml",
        "[toolchain]\nchannel='1.98.1'\n",
    )?;
    write(root.path(), "Cargo.lock", "version=4\n[[package]]\nname='itoa'\nversion='1.0.15'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n")?;
    write(root.path(), "crates/demo/Cargo.toml", "[package]\nname='demo'\nversion='1.0.0'\nrust-version.workspace=true\n[dependencies]\nitoa.workspace=true\n")?;
    let (success, report) = scan(root.path())?;
    assert!(success, "{report}");
    let member = report["projects"]
        .as_array()
        .ok_or("projects")?
        .iter()
        .find(|p| p["root"] == "crates/demo")
        .ok_or("member")?;
    assert_eq!(member["lockfile"], "Cargo.lock");
    assert_eq!(member["requirements"][0]["constraint"], "1");
    assert!(member["tools"]
        .as_array()
        .ok_or("tools")?
        .iter()
        .any(|t| t["constraint"] == "1.98.1"));
    assert!(member["tools"]
        .as_array()
        .ok_or("tools")?
        .iter()
        .any(|t| t["constraint"] == ">=1.85"));
    Ok(())
}

#[test]
fn oversize_manifest_and_unknown_lock_version_produce_explicit_diagnostics(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        &" ".repeat(8 * 1024 * 1024 + 1),
    )?;
    let (success, report) = scan(root.path())?;
    assert!(!success);
    assert_eq!(report["diagnostics"][0]["code"], "file_limit");
    write(root.path(), "package.json", "{}")?;
    write(
        root.path(),
        "package-lock.json",
        r#"{"lockfileVersion":99,"packages":{}}"#,
    )?;
    let (success, report) = scan(root.path())?;
    assert!(!success);
    assert_eq!(report["diagnostics"][0]["code"], "invalid_manifest");
    Ok(())
}
