use ladyshell::{
    config::{Config, Sources},
    scan::scan,
    sources::snapshot,
};
use serde_json::json;
use std::fs;
fn configuration() -> ladyshell::error::Result<ladyshell::config::ResolvedConfig> {
    Config::from_value(json!({"schema_version":1,"name":"test","sources":{"include":["audit"],"exclude":[]},"tools":{},"missions":{"dev":{"tools":[],"include":[],"depends_on":[],"checks":[]}},"sandbox":{"gateway":"g","workspace":"w","provider":"p"}}))?.resolve("dev")
}
#[test]
fn nested_evidence_module_is_preserved_but_root_reports_and_secrets_are_excluded(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let module = "crates/core/src/evidence/tests.rs";
    fs::create_dir_all(root.path().join("crates/core/src/evidence"))?;
    fs::create_dir(root.path().join("evidence"))?;
    fs::write(root.path().join(module), "// module\n")?;
    fs::write(
        root.path().join("crates/core/src/evidence/auth.json"),
        "secret",
    )?;
    fs::write(root.path().join("evidence/run.json"), "report")?;
    let spec = Sources {
        include: vec!["crates".into()],
        exclude: vec![],
    };
    let files = snapshot(root.path(), &spec, None)?;
    assert_eq!(
        files.keys().map(String::as_str).collect::<Vec<_>>(),
        [module]
    );
    let inventory = ladyshell::snapshot::inventory(root.path())?;
    assert_eq!(inventory.len(), 1);
    ladyshell::snapshot::validate(&inventory)?;
    assert!(ladyshell::snapshot::local_bytes(root.path(), module).is_ok());
    assert!(ladyshell::sources::excluded("evidence/run.json", &spec));
    let excluded = Sources {
        include: spec.include,
        exclude: vec!["crates/core/src/evidence".into()],
    };
    assert!(snapshot(root.path(), &excluded, None)?.is_empty());
    Ok(())
}
#[test]
fn excludes_cache_and_secrets_and_rejects_selected_symlinks(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir_all(dir.path().join("src/.cache"))?;
    fs::write(dir.path().join("src/code.rs"), "code")?;
    fs::write(dir.path().join("src/.cache/junk"), "cache")?;
    fs::write(dir.path().join("src/auth.json"), "secret")?;
    let spec = Sources {
        include: vec!["src".into()],
        exclude: vec![],
    };
    let files = snapshot(dir.path(), &spec, None)?;
    assert_eq!(files.len(), 1);
    assert!(files.contains_key("src/code.rs"));
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("src/link"))?;
    assert!(snapshot(dir.path(), &spec, None).is_err());
    Ok(())
}
#[test]
fn readme_requirement_blocks_missing_node_but_installation_mention_is_only_hint(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("audit"))?;
    fs::write(
        dir.path().join("audit/README.md"),
        "# Installation\nnpx audit\n# Requirements\n- **Node.js** 20+\n",
    )?;
    let cfg = configuration()?;
    let files = snapshot(dir.path(), &cfg.sources, None)?;
    let report = scan(dir.path(), &files, &cfg)?;
    assert!(report.complete);
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.missing[0].tool, "node");
    assert_eq!(report.missing[0].line, Some(4));
    assert_eq!(report.missing[0].phase, "execution");
    assert!(report.observations.iter().any(|o| o.tool == "npx"
        && o.phase == "installation"
        && o.status == "not_provisioned_to_confirm"));
    let mut cfg = cfg;
    cfg.tools.insert(
        "node".into(),
        ladyshell::config::Tool {
            version: "24.21.0".into(),
            phase: "runtime".into(),
        },
    );
    assert!(scan(dir.path(), &files, &cfg)?.missing.is_empty());
    Ok(())
}
#[test]
fn base_image_supplies_env_for_declared_checks() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("audit"))?;
    fs::write(dir.path().join("audit/README.md"), "Synthetic input.\n")?;
    let mut cfg = configuration()?;
    cfg.checks = vec![
        vec!["env".into(), "QUALIFICATION=1".into(), "python3".into()],
        vec!["/usr/bin/env".into(), "--version".into()],
    ];
    let files = snapshot(dir.path(), &cfg.sources, None)?;
    let report = scan(dir.path(), &files, &cfg)?;
    assert!(report.complete);
    assert!(report.missing.is_empty());
    assert_eq!(report.observations.len(), 2);
    assert!(report.observations.iter().all(|observation| {
        observation.tool == "env"
            && observation.status == "provided"
            && observation.basis == "declared_command"
    }));
    cfg.checks.push(vec!["missing-env".into()]);
    let report = scan(dir.path(), &files, &cfg)?;
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.missing[0].tool, "missing-env");
    Ok(())
}

#[test]
fn rust_supplies_cargo_and_rustc_but_not_rustup() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("audit"))?;
    let mut cfg = configuration()?;
    cfg.checks = vec![
        vec!["cargo".into(), "test".into()],
        vec!["rustc".into(), "--version".into()],
    ];
    let files = snapshot(dir.path(), &cfg.sources, None)?;
    assert_eq!(scan(dir.path(), &files, &cfg)?.missing.len(), 2);
    cfg.tools.insert(
        "rust".into(),
        ladyshell::config::Tool {
            version: "1.98.1".into(),
            phase: "runtime".into(),
        },
    );
    cfg.checks.push(vec!["rustfmt".into(), "--check".into()]);
    cfg.checks.push(vec!["cc".into(), "--version".into()]);
    let report = scan(dir.path(), &files, &cfg)?;
    assert!(report.missing.is_empty());
    assert!(report.observations.iter().all(|o| o.toolchain == "rust"));
    cfg.checks.push(vec!["rustup".into(), "update".into()]);
    assert_eq!(scan(dir.path(), &files, &cfg)?.missing[0].tool, "rustup");
    Ok(())
}
#[test]
fn explicit_vendor_sources_survive_snapshot_and_transfer_filters(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir_all(root.path().join("vendor/slh-dsa/src"))?;
    fs::create_dir_all(root.path().join("vendor/slh-dsa/target"))?;
    fs::write(
        root.path().join("vendor/slh-dsa/src/lib.rs"),
        "pub fn verify() {}\n",
    )?;
    fs::write(root.path().join("vendor/slh-dsa/auth.json"), "secret")?;
    fs::write(root.path().join("vendor/slh-dsa/target/cache"), "cache")?;
    for selected in ["vendor", "vendor/slh-dsa"] {
        let spec = Sources {
            include: vec![selected.into()],
            exclude: vec![],
        };
        let staging = tempfile::tempdir()?;
        let files = snapshot(root.path(), &spec, Some(staging.path()))?;
        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["vendor/slh-dsa/src/lib.rs"]
        );
        assert_eq!(
            fs::read(staging.path().join("vendor/slh-dsa/src/lib.rs"))?,
            b"pub fn verify() {}\n"
        );
    }
    let inventory = ladyshell::snapshot::inventory(root.path())?;
    assert_eq!(inventory.len(), 1);
    ladyshell::snapshot::validate(&inventory)?;
    assert!(ladyshell::snapshot::local_bytes(root.path(), "vendor/slh-dsa/src/lib.rs").is_ok());
    let spec = Sources {
        include: vec!["vendor".into()],
        exclude: vec!["vendor/slh-dsa".into()],
    };
    assert!(snapshot(root.path(), &spec, None)?.is_empty());
    assert!(ladyshell::snapshot::inventory_filtered(root.path(), &spec.exclude)?.is_empty());
    let spec = Sources {
        include: vec!["vendor/slh-dsa".into()],
        exclude: vec!["vendor".into()],
    };
    assert!(snapshot(root.path(), &spec, None).is_err());
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("vendor/slh-dsa/src/link"))?;
    let spec = Sources {
        include: vec!["vendor/slh-dsa".into()],
        exclude: vec![],
    };
    assert!(snapshot(root.path(), &spec, None).is_err());
    Ok(())
}
