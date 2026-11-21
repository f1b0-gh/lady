#![cfg(feature = "graph")]

use ladybom::deps::{self, graph};
use serde_json::Value;
use std::{fs, path::Path};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn write(root: &Path, path: &str, content: &str) -> Result {
    let path = root.join(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)?;
    Ok(())
}

fn fixture(root: &Path, dependency: &str, local_package: &str) -> Result {
    write(root, "Cargo.toml", "[workspace]\nmembers=['app','local']\n[workspace.package]\nversion='1.2.3'\n[workspace.dependencies]\nrenamed={package='actual',path='local',version='=1.2.3'}\n")?;
    write(
        root,
        "app/Cargo.toml",
        &format!("[package]\nname='app'\nversion='1.0.0'\n[dependencies]\n{dependency}\n"),
    )?;
    write(root, "local/Cargo.toml", local_package)?;
    write(root, "Cargo.lock", "version=4\n[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['actual 1.2.3','actual 1.2.3 (registry+https://github.com/rust-lang/crates.io-index)']\n[[package]]\nname='actual'\nversion='1.2.3'\n[[package]]\nname='actual'\nversion='1.2.3'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n")?;
    Ok(())
}

const LOCAL_PACKAGE: &str = "[package]\nname='actual'\nversion.workspace=true\n";
const LOCAL_DEPENDENCY: &str = "renamed={package='actual',path='../local/./',version='=1.2.3'}";

#[test]
fn local_and_registry_packages_remain_distinct_and_bind_their_own_aliases() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(
        dir.path(),
        &format!("{LOCAL_DEPENDENCY}\nexternal={{package='actual',version='=1.2.3'}}"),
        LOCAL_PACKAGE,
    )?;
    let report = deps::scan_project(dir.path())?;
    let original = serde_json::to_value(&report)?;
    let graph = graph::project(report)?;
    assert_eq!(graph.components.len(), 3);
    assert_eq!(serde_json::to_value(&graph.inventory)?, original);
    assert!(graph
        .components
        .iter()
        .any(|n| n.key.purl == "pkg:generic/cargo-local/actual@1.2.3"));
    assert!(graph
        .components
        .iter()
        .any(|n| n.key.purl == "pkg:cargo/actual@1.2.3"));
    let roots: Vec<_> = graph
        .roots
        .iter()
        .filter(|r| r.manifest == "app/Cargo.toml")
        .collect();
    assert_eq!(roots.len(), 2);
    assert!(roots
        .iter()
        .any(|r| r.to.purl == "pkg:generic/cargo-local/actual@1.2.3"
            && r.condition["declared_name"] == "renamed"));
    assert!(roots.iter().any(
        |r| r.to.purl == "pkg:cargo/actual@1.2.3" && r.condition["declared_name"] == "external"
    ));
    assert_eq!(graph.dependencies.len(), 2);
    assert!(graph
        .dependencies
        .iter()
        .all(|e| e.kind == "unknown" && !e.condition.is_null()));
    assert!(!graph.complete());
    Ok(())
}

#[test]
fn inherited_paths_use_workspace_origin_and_inherited_package_version() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(
        dir.path(),
        "renamed={workspace=true,optional=true,features=['extra']}",
        LOCAL_PACKAGE,
    )?;
    let report = deps::scan_project(dir.path())?;
    let value = serde_json::to_value(&report)?;
    let projects = value["projects"].as_array().ok_or("projects")?;
    let local = projects
        .iter()
        .find(|p| p["manifest"] == "local/Cargo.toml")
        .ok_or("local")?;
    assert_eq!(
        local["manifest_package"],
        serde_json::json!({"name":"actual","version":"1.2.3"})
    );
    let graph = graph::project(report)?;
    assert_eq!(graph.roots.len(), 1);
    assert_eq!(
        graph.roots[0].to.purl,
        "pkg:generic/cargo-local/actual@1.2.3"
    );
    assert_eq!(graph.roots[0].condition["source"]["optional"], true);
    assert_eq!(
        graph.roots[0].condition["extras"],
        serde_json::json!(["extra"])
    );
    Ok(())
}

#[test]
fn path_without_version_binds_only_the_manifest_package_identity() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(
        dir.path(),
        "renamed={package='actual',path='../local'}",
        LOCAL_PACKAGE,
    )?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(graph.roots.len(), 1);
    assert_eq!(
        graph.roots[0].to.purl,
        "pkg:generic/cargo-local/actual@1.2.3"
    );
    Ok(())
}

#[test]
fn missing_wrong_or_escaped_local_paths_never_fall_back_to_registry() -> Result {
    for (dependency, package) in [
        (
            "renamed={package='actual',path='../missing'}",
            LOCAL_PACKAGE,
        ),
        (
            "renamed={package='actual',path='../../local'}",
            LOCAL_PACKAGE,
        ),
        ("renamed={package='actual',path='/local'}", LOCAL_PACKAGE),
        (
            LOCAL_DEPENDENCY,
            "[package]\nname='other'\nversion='1.2.3'\n",
        ),
        (
            LOCAL_DEPENDENCY,
            "[package]\nname='actual'\nversion='9.0.0'\n",
        ),
        (
            "renamed={package='actual',path='../local',version='=9.0.0'}",
            LOCAL_PACKAGE,
        ),
    ] {
        let dir = tempfile::tempdir()?;
        fixture(dir.path(), dependency, package)?;
        let graph = graph::project(deps::scan_project(dir.path())?)?;
        assert!(graph.roots.is_empty(), "{dependency}");
        assert!(!graph.limitations.is_empty());
    }
    Ok(())
}

#[test]
fn omitted_manifest_and_legacy_identity_evidence_keep_local_roots_unresolved() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), LOCAL_DEPENDENCY, LOCAL_PACKAGE)?;
    let report = deps::scan_project(dir.path())?;
    for legacy in [false, true] {
        let mut value = serde_json::to_value(&report)?;
        let projects = value["projects"].as_array_mut().ok_or("projects")?;
        if legacy {
            for project in projects.iter_mut() {
                project
                    .as_object_mut()
                    .ok_or("project")?
                    .remove("manifest_package");
                for requirement in project["requirements"]
                    .as_array_mut()
                    .ok_or("requirements")?
                {
                    if let Some(source) = requirement["source"].as_object_mut() {
                        source.remove("_ladybom_declaration_manifest");
                    }
                }
            }
        } else {
            projects.retain(|p| p["manifest"] != "local/Cargo.toml");
        }
        let older: deps::Report = serde_json::from_value(value)?;
        older.validate()?;
        let graph = graph::project(older)?;
        assert!(graph.roots.is_empty());
        assert!(graph
            .components
            .iter()
            .any(|n| n.key.purl == "pkg:generic/cargo-local/actual@1.2.3"));
    }
    Ok(())
}

#[test]
fn identical_local_identities_at_multiple_selected_paths_are_ambiguous() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), LOCAL_DEPENDENCY, LOCAL_PACKAGE)?;
    write(
        dir.path(),
        "Cargo.toml",
        "[workspace]\nmembers=['app','local','duplicate']\n[workspace.package]\nversion='1.2.3'\n",
    )?;
    write(dir.path(), "duplicate/Cargo.toml", LOCAL_PACKAGE)?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert!(graph.roots.is_empty());
    assert!(graph.limitations.iter().any(|l| l.contains("ambigu")));
    Ok(())
}

#[test]
fn shared_lock_projection_is_once_per_lock_and_preserves_member_roots() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), LOCAL_DEPENDENCY, LOCAL_PACKAGE)?;
    write(
        dir.path(),
        "Cargo.toml",
        "[workspace]\nmembers=['app','local','second']\n[workspace.package]\nversion='1.2.3'\n",
    )?;
    write(
        dir.path(),
        "second/Cargo.toml",
        &format!("[package]\nname='second'\nversion='1.0.0'\n[dependencies]\n{LOCAL_DEPENDENCY}\n"),
    )?;
    let report = deps::scan_project(dir.path())?;
    let graph = graph::project(report.clone())?;
    assert_eq!(graph.components.len(), 3);
    assert_eq!(graph.dependencies.len(), 2);
    assert_eq!(graph.roots.len(), 2);
    assert!(graph.roots.iter().any(|r| r.manifest == "app/Cargo.toml"));
    assert!(graph
        .roots
        .iter()
        .any(|r| r.manifest == "second/Cargo.toml"));
    let edge_limits: Vec<_> = graph
        .limitations
        .iter()
        .filter(|l| l.contains(" -> "))
        .collect();
    assert_eq!(edge_limits.len(), 1);
    assert!(edge_limits[0].starts_with("Cargo.lock:"));
    assert_eq!(
        serde_json::to_value(&graph)?,
        serde_json::to_value(graph::project(report)?)?
    );
    Ok(())
}

#[test]
fn git_and_custom_registry_sources_do_not_acquire_local_identity() -> Result {
    let dir = tempfile::tempdir()?;
    write(dir.path(), "Cargo.toml", "[package]\nname='app'\nversion='1.0.0'\n[dependencies]\ngitdep={git='https://example.invalid/repo',version='1'}\ncustom={registry='private',version='1'}\n")?;
    write(dir.path(), "Cargo.lock", "version=4\n[[package]]\nname='gitdep'\nversion='1.0.0'\nsource='git+https://example.invalid/repo#0123456789012345678901234567890123456789'\n[[package]]\nname='custom'\nversion='1.0.0'\nsource='registry+https://example.invalid/index'\n")?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(graph.components.len(), 1);
    assert_eq!(graph.roots.len(), 1);
    assert!(graph.components[0]
        .key
        .purl
        .starts_with("pkg:cargo/gitdep@1.0.0?vcs_url="));
    assert!(graph.inventory.projects[0]
        .components
        .iter()
        .any(|c| c.name == "custom" && c.purl.is_none() && c.source != Value::Null));
    assert!(graph.limitations.iter().any(|l| l.contains("custom")));
    Ok(())
}

#[test]
fn parser_overwrites_origin_metadata_and_retains_target_and_kind_conditions() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(
        dir.path(),
        "renamed={package='actual',path='../local',_ladybom_declaration_manifest='Cargo.toml'}",
        LOCAL_PACKAGE,
    )?;
    let manifest = dir.path().join("app/Cargo.toml");
    let mut content = fs::read_to_string(&manifest)?;
    content.push_str("[target.'cfg(unix)'.build-dependencies]\nbuild_alias={package='actual',path='../local'}\n[dev-dependencies]\ndev_alias={package='actual',path='../local'}\n");
    fs::write(manifest, content)?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(graph.roots.len(), 3);
    assert!(graph.roots.iter().all(|r| {
        r.to.purl == "pkg:generic/cargo-local/actual@1.2.3"
            && r.condition["source"]["_ladybom_declaration_manifest"] == "app/Cargo.toml"
    }));
    assert!(graph
        .roots
        .iter()
        .any(|r| r.kind == "build" && r.condition["marker"] == "cfg(unix)"));
    assert!(graph.roots.iter().any(|r| r.kind == "dev"));
    assert!(graph
        .dependencies
        .iter()
        .all(|e| e.kind == "unknown" && !e.condition.is_null()));
    assert!(!graph.complete());
    Ok(())
}

#[test]
fn missing_selected_manifest_input_does_not_prove_a_local_path() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), LOCAL_DEPENDENCY, LOCAL_PACKAGE)?;
    let mut report = deps::scan_project(dir.path())?;
    report.inputs.remove("local/Cargo.toml");
    let graph = graph::project(report)?;
    assert!(graph.roots.is_empty());
    Ok(())
}
