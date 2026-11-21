use serde_json::{json, Value};
use std::{path::Path, process::Command};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn scan(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
    command
        .env_clear()
        .env("PATH", root)
        .args(["scan", "--cyclonedx", "--project"])
        .arg(root);
    command
}

fn property<'a>(bom: &'a Value, name: &str) -> Option<&'a str> {
    bom["properties"]
        .as_array()?
        .iter()
        .find(|property| property["name"] == name)?["value"]
        .as_str()
}

#[test]
fn exports_all_ecosystems_without_external_tools_deterministically() -> Result {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ladybom/tests/fixtures/project")
        .canonicalize()?;
    let output = scan(&root).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bom: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(bom["specVersion"], "1.5");
    assert_eq!(bom["version"], 1);
    assert_eq!(property(&bom, "ladybom:complete"), Some("true"));
    let components = bom["components"].as_array().ok_or("missing components")?;
    for purl in [
        "pkg:cargo/itoa@1.0.15",
        "pkg:pypi/idna@3.10",
        "pkg:npm/is-number@7.0.0",
    ] {
        assert!(
            components.iter().any(|component| component["purl"] == purl),
            "{purl}"
        );
    }
    let report = ladybom::scan_project(&root)?;
    assert_eq!(
        components.len(),
        report
            .projects
            .iter()
            .map(|p| p.components.len())
            .sum::<usize>()
    );
    let again = scan(&root).output()?;
    assert!(again.status.success());
    assert_eq!(output.stdout, again.stdout);
    Ok(())
}

#[test]
fn partial_scan_keeps_diagnostics_and_exit_status() -> Result {
    let root = tempfile::tempdir()?;
    std::fs::write(root.path().join("Cargo.toml"), "[invalid")?;
    let output = scan(root.path()).output()?;
    assert_eq!(output.status.code(), Some(2));
    let bom: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(bom["bomFormat"], "CycloneDX");
    assert_eq!(property(&bom, "ladybom:complete"), Some("false"));
    assert!(property(&bom, "ladybom:diagnostics").is_none());
    let private = scan(root.path())
        .args(["--export-profile", "private-detailed"])
        .output()?;
    assert_eq!(private.status.code(), Some(2));
    let bom: Value = serde_json::from_slice(&private.stdout)?;
    let diagnostics: Value =
        serde_json::from_str(property(&bom, "ladybom:diagnostics").ok_or("missing diagnostics")?)?;
    assert_eq!(diagnostics[0]["file"], "Cargo.toml");
    assert_eq!(diagnostics[0]["blocking"], true);
    Ok(())
}

#[test]
fn selected_sources_control_the_export_and_reject_selected_links() -> Result {
    let root = tempfile::tempdir()?;
    let config = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"selected","version":"1.0.0"}"#,
    )?;
    std::fs::write(root.path().join("Cargo.toml"), "invalid")?;
    let sources = config.path().join("sources.json");
    std::fs::write(
        &sources,
        json!({"include":["package.json"],"exclude":[]}).to_string(),
    )?;
    let output = scan(root.path())
        .args(["--export-profile", "private-detailed"])
        .arg("--sources")
        .arg(&sources)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bom: Value = serde_json::from_slice(&output.stdout)?;
    let inputs: Value =
        serde_json::from_str(property(&bom, "ladybom:inputs").ok_or("missing inputs")?)?;
    assert!(inputs.get("package.json").is_some());
    assert!(inputs.get("Cargo.toml").is_none());
    let private = config.path().join("private");
    std::fs::write(&private, "PRIVATE_SENTINEL")?;
    std::os::unix::fs::symlink(&private, root.path().join("linked.json"))?;
    std::fs::write(
        &sources,
        json!({"include":["linked.json"],"exclude":[]}).to_string(),
    )?;
    let denied = scan(root.path()).arg("--sources").arg(&sources).output()?;
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains("PRIVATE_SENTINEL"));
    Ok(())
}

#[test]
fn cyclonedx_and_native_json_are_mutually_exclusive() -> Result {
    let root = tempfile::tempdir()?;
    let output = scan(root.path()).arg("--json").output()?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    Ok(())
}

#[test]
fn public_is_default_and_private_profile_is_explicit() -> Result {
    let root = tempfile::tempdir()?;
    std::fs::write(
        root.path().join("package.json"),
        r#"{"name":"app","dependencies":{"pkg":"1.0.0"}}"#,
    )?;
    std::fs::write(root.path().join("package-lock.json"),json!({"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/pkg":{"version":"1.0.0","resolved":"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz","privateNote":"CLI_PRIVATE_SECRET"}}}).to_string())?;
    let public = scan(root.path()).output()?;
    let private = scan(root.path())
        .args(["--export-profile", "private-detailed"])
        .output()?;
    assert!(
        public.status.success(),
        "{}",
        String::from_utf8_lossy(&public.stderr)
    );
    assert!(
        private.status.success(),
        "{}",
        String::from_utf8_lossy(&private.stderr)
    );
    assert!(!String::from_utf8_lossy(&public.stdout).contains("CLI_PRIVATE_SECRET"));
    assert!(String::from_utf8_lossy(&private.stdout).contains("CLI_PRIVATE_SECRET"));
    let public: Value = serde_json::from_slice(&public.stdout)?;
    let private: Value = serde_json::from_slice(&private.stdout)?;
    assert_ne!(public["serialNumber"], private["serialNumber"]);
    assert_eq!(property(&public, "ladybom:export_profile"), Some("public"));
    assert_eq!(
        property(&private, "ladybom:export_profile"),
        Some("private-detailed")
    );
    let component = &public["components"][0];
    assert_eq!(
        property(component, "ladybom:coverage:composition"),
        Some("unknown")
    );
    Ok(())
}
