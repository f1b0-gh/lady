use ladyshell::{config::Tool, deps, sources};
use serde_json::json;
use std::{collections::BTreeMap, fs};

fn tools() -> BTreeMap<String, Tool> {
    BTreeMap::from([(
        "node".into(),
        Tool {
            version: "24.21.0".into(),
            phase: "runtime".into(),
        },
    )])
}

fn fixture() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("package.json"), json!({"name":"fixture", "version":"1.0.0", "engines":{"node": ">=22"}, "dependencies":{"is-number":"^7"}}).to_string())?;
    fs::write(root.path().join("package-lock.json"), json!({"lockfileVersion":3,"packages":{
        "":{"name":"fixture","version":"1.0.0","dependencies":{"is-number":"^7"}},
        "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":format!("sha512-{}", "A".repeat(86)+"==")}
    }}).to_string())?;
    Ok(root)
}

fn config() -> deps::DependencyConfig {
    deps::DependencyConfig {
        projects: vec!["package.json".into()],
        allowed_hosts: vec!["registry.npmjs.org".into()],
    }
}

fn write_json(
    root: &std::path::Path,
    name: &str,
    value: &serde_json::Value,
) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, value.to_string())
}

fn workspace_fixture(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = json!({"name":"fixture", "version":"1.0.0", "workspaces":["packages/member"],
        "dependencies":{"is-number":"^7", "@fixture/member":"*"},
        "scripts":{"preinstall":"touch ROOT_SCRIPT_EXECUTED"}});
    let member = json!({"name":"@fixture/member", "version":"1.0.0", "dependencies":{"is-number":"^6"},
        "engines":{"node":">=22","npm":">=9"}, "scripts":{"install":"touch MEMBER_SCRIPT_EXECUTED"}});
    let integrity = format!("sha512-{}==", "A".repeat(86));
    let mut locked_member = member.clone();
    locked_member
        .as_object_mut()
        .ok_or("member")?
        .remove("scripts");
    locked_member["hasInstallScript"] = json!(true);
    let lock = json!({"lockfileVersion":3,"packages":{
        "":{"name":"fixture","version":"1.0.0","workspaces":["packages/member"],"dependencies":{"is-number":"^7","@fixture/member":"*"}},
        "packages/member":locked_member,
        "node_modules/@fixture/member":{"resolved":"packages/member","link":true},
        "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":integrity},
        "packages/member/node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz","integrity":integrity}
    }});
    write_json(root, "package.json", &manifest)?;
    write_json(root, "packages/member/package.json", &member)?;
    write_json(root, "package-lock.json", &lock)?;
    Ok(())
}

#[test]
fn npm_workspaces_prepare_root_and_explicit_members_without_running_scripts(
) -> Result<(), Box<dyn std::error::Error>> {
    for prefix in ["", "web/"] {
        let root = tempfile::tempdir()?;
        workspace_fixture(&root.path().join(prefix))?;
        let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
        let mut config = config();
        config.projects = vec![format!("{prefix}package.json")];
        let prepared = deps::prepare::plan(root.path(), &snapshot, &config, &tools())?;
        assert_eq!(prepared.projects.len(), 1);
        assert_eq!(prepared.projects[0].components.len(), 4);
        assert!(prepared.projects[0]
            .tools
            .iter()
            .any(|t| t.name == "npm" && t.constraint == ">=9"));
        assert!(!root
            .path()
            .join(format!("{prefix}ROOT_SCRIPT_EXECUTED"))
            .exists());
        assert!(!root
            .path()
            .join(format!("{prefix}packages/member/MEMBER_SCRIPT_EXECUTED"))
            .exists());
        assert_eq!(
            snapshot,
            sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?
        );
    }
    Ok(())
}

#[test]
fn npm_workspace_members_must_be_selected_and_unchanged() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    workspace_fixture(root.path())?;
    let mut snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    snapshot.remove("packages/member/package.json");
    assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    fs::write(root.path().join("packages/member/package.json"), "{}")?;
    assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    Ok(())
}

#[test]
fn npm_workspace_member_engines_constrain_the_pinned_node_tool(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    workspace_fixture(root.path())?;
    for (file, pointer) in [
        ("packages/member/package.json", "/engines/node"),
        (
            "package-lock.json",
            "/packages/packages~1member/engines/node",
        ),
    ] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(file))?)?;
        *value.pointer_mut(pointer).ok_or("engine constraint")? = json!(">=99");
        write_json(root.path(), file, &value)?;
    }
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let error = deps::prepare::plan(root.path(), &snapshot, &config(), &tools())
        .err()
        .ok_or("member tool constraint ignored")?;
    assert!(error.to_string().contains("incompatible"), "{error}");
    Ok(())
}

#[test]
fn npm_workspaces_reject_ambiguous_paths_links_and_member_drift(
) -> Result<(), Box<dyn std::error::Error>> {
    for (file, pointer, replacement) in [
        ("package.json", "/workspaces", json!(["packages/*"])),
        ("package.json", "/workspaces", json!(["../outside"])),
        ("package.json", "/workspaces", json!(["/absolute"])),
        (
            "package.json",
            "/workspaces",
            json!(["packages/member", "packages/member"]),
        ),
        (
            "package.json",
            "/workspaces",
            json!({"packages":["packages/member"]}),
        ),
        ("package-lock.json", "/packages//workspaces", json!([])),
        (
            "package-lock.json",
            "/packages/node_modules~1@fixture~1member/resolved",
            json!("../../outside"),
        ),
        (
            "package-lock.json",
            "/packages/node_modules~1@fixture~1member/resolved",
            json!("file:packages/member"),
        ),
        (
            "package-lock.json",
            "/packages/packages~1member/name",
            json!("other"),
        ),
        (
            "package-lock.json",
            "/packages/packages~1member/version",
            json!("2.0.0"),
        ),
        (
            "package-lock.json",
            "/packages/packages~1member/dependencies/is-number",
            json!("^8"),
        ),
        (
            "package-lock.json",
            "/packages/packages~1member~1node_modules~1is-number/version",
            json!("5.0.0"),
        ),
        (
            "package-lock.json",
            "/packages/node_modules~1is-number/resolved",
            json!("https://unapproved.example/is-number.tgz"),
        ),
        (
            "package-lock.json",
            "/packages/node_modules~1is-number/integrity",
            json!("sha512-YQ=="),
        ),
        (
            "packages/member/package.json",
            "/engines/node",
            json!(">=99"),
        ),
    ] {
        let root = tempfile::tempdir()?;
        workspace_fixture(root.path())?;
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join(file))?)?;
        *value.pointer_mut(pointer).ok_or(pointer.to_string())? = replacement;
        write_json(root.path(), file, &value)?;
        let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
        assert!(
            deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err(),
            "{file} {pointer}"
        );
    }
    for (file, value) in [
        (
            "packages/member/package-lock.json",
            json!({"lockfileVersion":3,"packages":{"":{}}}),
        ),
        (
            "packages/member/package.json",
            json!({"name":"@fixture/member","version":"1.0.0","workspaces":["nested"],"dependencies":{"is-number":"^6"}}),
        ),
    ] {
        let root = tempfile::tempdir()?;
        workspace_fixture(root.path())?;
        write_json(root.path(), file, &value)?;
        let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
        assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    }
    Ok(())
}

#[test]
fn npm_workspace_cannot_add_undeclared_local_packages_or_duplicate_install_roots(
) -> Result<(), Box<dyn std::error::Error>> {
    for (path, value) in [
        (
            "packages/undeclared",
            json!({"name":"undeclared","version":"1.0.0"}),
        ),
        (
            "node_modules/undeclared",
            json!({"link":true,"resolved":"packages/member"}),
        ),
        (
            "node_modules/local-file",
            json!({"version":"1.0.0","resolved":"file:packages/member"}),
        ),
    ] {
        let root = tempfile::tempdir()?;
        workspace_fixture(root.path())?;
        let mut lock: serde_json::Value =
            serde_json::from_slice(&fs::read(root.path().join("package-lock.json"))?)?;
        lock["packages"][path] = value;
        write_json(root.path(), "package-lock.json", &lock)?;
        let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
        assert!(
            deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err(),
            "{path}"
        );
    }
    let root = tempfile::tempdir()?;
    workspace_fixture(root.path())?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let mut config = config();
    config.projects.push("packages/member/package.json".into());
    assert!(deps::prepare::plan(root.path(), &snapshot, &config, &tools()).is_err());
    Ok(())
}

#[test]
fn npm_workspace_rejects_installation_trees_outside_the_declared_package_roots(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    workspace_fixture(root.path())?;
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(root.path().join("package-lock.json"))?)?;
    let nested = lock["packages"]
        .as_object_mut()
        .ok_or("packages")?
        .remove("packages/member/node_modules/is-number")
        .ok_or("nested dependency")?;
    lock["packages"]["packages/node_modules/is-number"] = nested;
    write_json(root.path(), "package-lock.json", &lock)?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    assert!(
        deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err(),
        "an artifact outside exported root/member node_modules trees must not be accepted"
    );
    Ok(())
}

#[test]
fn preparation_is_pure_explicit_and_bound_to_verified_inputs(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture()?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let prepared = deps::prepare::plan(root.path(), &snapshot, &config(), &tools())?;
    assert_eq!(prepared.projects.len(), 1);
    assert_eq!(prepared.inputs, snapshot);
    assert_eq!(
        prepared.projects[0].components[0].purl.as_deref(),
        Some("pkg:npm/is-number@7.0.0")
    );
    fs::write(root.path().join("package.json"), "{}")?;
    assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    Ok(())
}

#[test]
fn preparation_rejects_unapproved_hosts_missing_integrity_and_local_sources(
) -> Result<(), Box<dyn std::error::Error>> {
    for replacement in [
        json!({"version":"7.0.0","resolved":"https://evil.example/p.tgz","integrity":"sha512-YQ=="}),
        json!({"version":"7.0.0","resolved":"https://registry.npmjs.org/p.tgz"}),
        json!({"version":"7.0.0","resolved":"https://registry.npmjs.org/p.tgz","integrity":"sha512-YQ=="}),
        json!({"version":"7.0.0","resolved":"../../outside","link":true}),
        json!({"version":"7.0.0","resolved":"git+https://registry.npmjs.org/p.git#head"}),
        json!({"version":"7.0.0","resolved":"https://registry.npmjs.org/p.tgz","integrity":format!("sha512-{}", "A".repeat(86)+"=="),"hasInstallScript":true}),
        json!({"version":"7.0.0","resolved":"https://user:secret@registry.npmjs.org/p.tgz","integrity":"sha512-YQ=="}),
    ] {
        let root = fixture()?;
        let path = root.path().join("package-lock.json");
        let mut lock: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        lock["packages"]["node_modules/is-number"] = replacement;
        fs::write(path, lock.to_string())?;
        let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
        assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    }
    Ok(())
}

#[test]
fn preparation_rejects_manifest_lock_drift_and_incompatible_tools(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture()?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let mut old = tools();
    old.get_mut("node").ok_or("node")?.version = "18.0.0".into();
    assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &old).is_err());
    let mut unauthorized = config();
    unauthorized.allowed_hosts.clear();
    assert!(deps::prepare::plan(root.path(), &snapshot, &unauthorized, &tools()).is_err());
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"is-number":"^8"}}"#,
    )?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    assert!(deps::prepare::plan(root.path(), &snapshot, &config(), &tools()).is_err());
    Ok(())
}

#[test]
fn config_refuses_duplicate_or_escaping_project_paths() {
    for projects in [
        vec!["../package.json".into()],
        vec!["package.json".into(), "package.json".into()],
        vec![],
    ] {
        let config = deps::DependencyConfig {
            projects,
            allowed_hosts: vec![],
        };
        assert!(config.validate().is_err());
    }
}

#[test]
fn workspace_root_cannot_hide_incompatible_member_toolchains(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("member"))?;
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=['member']\n",
    )?;
    fs::write(
        root.path().join("member/Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\nrust-version='1.999'\n",
    )?;
    fs::write(
        root.path().join("Cargo.lock"),
        "version=4\n[[package]]\nname='member'\nversion='0.1.0'\n",
    )?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let config = deps::DependencyConfig {
        projects: vec!["Cargo.toml".into()],
        allowed_hosts: vec![],
    };
    let tools = BTreeMap::from([(
        "rust".into(),
        Tool {
            version: "1.98.1".into(),
            phase: "runtime".into(),
        },
    )]);
    let result = deps::prepare::plan(root.path(), &snapshot, &config, &tools);
    assert!(
        result.is_err(),
        "workspace member rust-version must constrain the image"
    );
    Ok(())
}

#[test]
fn preparation_materializes_components_referenced_by_a_selected_workspace_member(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("member"))?;
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=['member']\n",
    )?;
    fs::write(
        root.path().join("member/Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\n",
    )?;
    fs::write(
        root.path().join("Cargo.lock"),
        "version=4\n[[package]]\nname='member'\nversion='0.1.0'\n",
    )?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let report = serde_json::to_value(deps::scan_snapshot(root.path(), &snapshot)?)?;
    let member = report["projects"]
        .as_array()
        .ok_or("projects")?
        .iter()
        .find(|p| p["manifest"] == "member/Cargo.toml")
        .ok_or("member")?;
    assert_eq!(member["components"], json!([]));
    assert_eq!(member["components_from"], "Cargo.toml");
    let config = deps::DependencyConfig {
        projects: vec!["member/Cargo.toml".into()],
        allowed_hosts: vec![],
    };
    let tools = BTreeMap::from([(
        "rust".into(),
        Tool {
            version: "1.98.1".into(),
            phase: "runtime".into(),
        },
    )]);
    let preparation = deps::prepare::plan(root.path(), &snapshot, &config, &tools)?;
    assert_eq!(preparation.schema_version, 1);
    assert_eq!(preparation.projects[0].components.len(), 1);
    assert_eq!(preparation.projects[0].components[0].name, "member");
    assert!(serde_json::to_value(preparation)?["projects"][0]["components_from"].is_null());
    Ok(())
}

#[test]
fn python_markers_excluded_by_the_selected_interpreter_do_not_require_a_locked_package(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("pyproject.toml"), "[project]\nname='marker-demo'\nversion='0.1.0'\nrequires-python='>=3.11'\ndependencies=[\"idna; python_version < '3.10'\"]\n")?;
    fs::write(root.path().join("uv.lock"), "version=1\nrevision=3\nrequires-python='>=3.11'\n[[package]]\nname='marker-demo'\nversion='0.1.0'\nsource={virtual='.'}\n[package.metadata]\nrequires-dist=[{name='idna',marker=\"python_full_version < '3.10'\"}]\n")?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    let config = deps::DependencyConfig {
        projects: vec!["pyproject.toml".into()],
        allowed_hosts: vec![],
    };
    let tools = BTreeMap::from([(
        "python".into(),
        Tool {
            version: "3.13.15".into(),
            phase: "runtime".into(),
        },
    )]);
    let prepared = deps::prepare::plan(root.path(), &snapshot, &config, &tools)?;
    assert_eq!(
        prepared.projects[0].requirements[0].marker.as_deref(),
        Some("python_full_version < '3.10'")
    );
    // A live requirement cannot silently disappear from the lock.
    fs::write(root.path().join("pyproject.toml"), "[project]\nname='marker-demo'\nversion='0.1.0'\ndependencies=[\"idna; python_version >= '3.10'\"]\n")?;
    let snapshot = sources::snapshot(root.path(), &deps::project_sources(root.path())?, None)?;
    assert!(deps::prepare::plan(root.path(), &snapshot, &config, &tools).is_err());
    Ok(())
}
