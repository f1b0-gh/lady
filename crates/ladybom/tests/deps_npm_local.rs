use ladybom::deps::{self, graph};
use serde_json::{json, Value};
use std::{fs, path::Path};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn write(root: &Path, path: &str, value: Value) -> Result {
    let path = root.join(path);
    fs::create_dir_all(path.parent().ok_or("parent")?)?;
    fs::write(path, value.to_string())?;
    Ok(())
}

fn fixture(root: &Path, prefix: &str, lock: &str, version: u8) -> Result {
    write(
        root,
        &format!("{prefix}package.json"),
        json!({
            "name":"root", "version":"1.0.0", "workspaces":["packages/a","packages/b","packages/c"],
            "dependencies":{"@fixture/a":"1.0.0","@fixture/b":"1.0.0","@fixture/c":"1.0.0"}
        }),
    )?;
    let mut packages = json!({"": {"name":"root","version":"1.0.0"},
        "node_modules/shared":{"version":"2.0.0","resolved":"https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"}
    });
    for name in ["a", "b", "c"] {
        let member = json!({"name":format!("@fixture/{name}"),"version":"1.0.0","dependencies":{"shared":"2.0.0"}});
        write(
            root,
            &format!("{prefix}packages/{name}/package.json"),
            member.clone(),
        )?;
        packages[format!("packages/{name}")] = member;
        packages[format!("node_modules/@fixture/{name}")] =
            json!({"resolved":format!("packages/{name}"),"link":true});
    }
    write(
        root,
        &format!("{prefix}{lock}"),
        json!({"lockfileVersion":version,"packages":packages}),
    )
}

// Losing local links must not turn a complete selected workspace into six unknowns.
#[test]
fn selected_local_workspaces_keep_six_occurrences_and_exact_link_edges() -> Result {
    for (prefix, lock, version) in [
        ("", "package-lock.json", 3),
        ("nested/", "package-lock.json", 2),
        ("nested/", "npm-shrinkwrap.json", 3),
    ] {
        let dir = tempfile::tempdir()?;
        fixture(dir.path(), prefix, lock, version)?;
        let report = deps::scan_project(dir.path())?;
        assert!(report.complete);
        let graph = graph::project(report)?;
        let local: Vec<_> = graph
            .components
            .iter()
            .filter(|n| n.key.purl.starts_with("pkg:generic/npm-local/"))
            .collect();
        assert_eq!(local.len(), 6);
        assert_eq!(graph.components.len(), 7);
        assert!(local.iter().all(|n| n.component.version == "1.0.0"));
        assert_eq!(
            graph
                .dependencies
                .iter()
                .filter(|e| e.kind == "link")
                .count(),
            3
        );
        assert_eq!(
            graph
                .dependencies
                .iter()
                .filter(|e| e.kind == "runtime")
                .count(),
            3
        );
        assert_eq!(graph.roots.len(), 6);
        for edge in graph.dependencies.iter().filter(|e| e.kind == "link") {
            let from = graph
                .components
                .iter()
                .find(|n| n.key == edge.from)
                .ok_or("from")?;
            let to = graph
                .components
                .iter()
                .find(|n| n.key == edge.to)
                .ok_or("to")?;
            assert!(from.component.context.starts_with("node_modules/"));
            assert!(to.component.context.starts_with("packages/"));
            assert_eq!(from.component.name, to.component.name);
            assert_eq!(edge.evidence["resolved"], to.component.context);
        }
    }
    Ok(())
}

#[test]
fn invalid_links_never_resolve_by_name_or_escape_selected_sources() -> Result {
    for resolved in [
        json!("../outside"),
        json!("/outside"),
        json!("./packages/a"),
        json!("packages//a"),
        json!("packages/a/"),
        json!("C:\\packages\\a"),
        json!("https://example.invalid/a"),
        json!("file:packages/a"),
        json!("packages/%61"),
        json!("packages/a\n"),
        json!("node_modules/@fixture/b"),
        json!("node_modules/@fixture/a"),
        json!("node_modules/shared"),
        json!("missing"),
        json!(false),
        Value::Null,
    ] {
        let dir = tempfile::tempdir()?;
        fixture(dir.path(), "", "package-lock.json", 3)?;
        let path = dir.path().join("package-lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
        lock["packages"]["node_modules/@fixture/a"]["resolved"] = resolved.clone();
        fs::write(path, lock.to_string())?;
        let graph = graph::project(deps::scan_project(dir.path())?)?;
        assert!(
            !graph
                .components
                .iter()
                .any(|n| n.component.context == "node_modules/@fixture/a"),
            "{resolved}"
        );
        assert!(
            !graph
                .roots
                .iter()
                .any(|r| r.manifest == "package.json" && r.to.purl.ends_with("/a@1.0.0")),
            "{resolved}"
        );
    }
    Ok(())
}

#[test]
fn local_names_and_versions_require_unambiguous_canonical_identity() -> Result {
    for (name, version) in [
        ("", "1.0.0"),
        ("@broken", "1.0.0"),
        ("@scope/", "1.0.0"),
        ("one/two", "1.0.0"),
        ("@a/b/c", "1.0.0"),
        ("percent%2fname", "1.0.0"),
        ("good", ""),
        ("good", "latest"),
        ("good", "1"),
    ] {
        let dir = tempfile::tempdir()?;
        fixture(dir.path(), "", "package-lock.json", 3)?;
        let path = dir.path().join("package-lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
        lock["packages"]["packages/a"]["name"] = json!(name);
        lock["packages"]["packages/a"]["version"] = json!(version);
        fs::write(path, lock.to_string())?;
        write(
            dir.path(),
            "packages/a/package.json",
            json!({"name":name,"version":version}),
        )?;
        let graph = graph::project(deps::scan_project(dir.path())?)?;
        assert!(!graph
            .components
            .iter()
            .any(|n| n.component.context == "packages/a"
                || n.component.context == "node_modules/@fixture/a"));
    }
    Ok(())
}

#[test]
fn aliases_and_identical_names_keep_local_paths_and_registry_sources_distinct() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let path = dir.path().join("package-lock.json");
    let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
    lock["packages"]["packages/b"]["name"] = json!("@fixture/a");
    lock["packages"]["node_modules/public"] = json!({"name":"@fixture/a","version":"1.0.0","resolved":"https://registry.npmjs.org/@fixture/a/-/a-1.0.0.tgz"});
    write(
        dir.path(),
        "packages/b/package.json",
        lock["packages"]["packages/b"].clone(),
    )?;
    fs::write(path, lock.to_string())?;
    let path = dir.path().join("package.json");
    let mut root: Value = serde_json::from_slice(&fs::read(&path)?)?;
    root["dependencies"]["@fixture/b"] = json!("npm:@fixture/a@1.0.0");
    root["dependencies"]["public"] = json!("npm:@fixture/a@1.0.0");
    fs::write(path, root.to_string())?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(graph.components.len(), 8);
    assert_eq!(
        graph
            .roots
            .iter()
            .filter(|r| r.manifest == "package.json")
            .count(),
        4
    );
    Ok(())
}

#[test]
fn linked_package_dependencies_resolve_from_the_target_and_check_constraints() -> Result {
    for constraint in ["3.0.0", "9.0.0"] {
        let dir = tempfile::tempdir()?;
        fixture(dir.path(), "", "package-lock.json", 3)?;
        let path = dir.path().join("package-lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
        lock["packages"]["packages/a"]["dependencies"]["shared"] = json!(constraint);
        lock["packages"]["packages/a/node_modules/shared"] = json!({"version":"3.0.0","resolved":"https://registry.npmjs.org/shared/-/shared-3.0.0.tgz"});
        write(
            dir.path(),
            "packages/a/package.json",
            lock["packages"]["packages/a"].clone(),
        )?;
        fs::write(path, lock.to_string())?;
        let graph = graph::project(deps::scan_project(dir.path())?)?;
        let target = graph
            .components
            .iter()
            .find(|n| n.component.context == "packages/a")
            .ok_or("target")?;
        let link = graph
            .components
            .iter()
            .find(|n| n.component.context == "node_modules/@fixture/a")
            .ok_or("link")?;
        assert!(graph
            .dependencies
            .iter()
            .filter(|e| e.from == link.key)
            .all(|e| e.kind == "link"));
        let edges: Vec<_> = graph
            .dependencies
            .iter()
            .filter(|e| e.from == target.key)
            .collect();
        if constraint == "3.0.0" {
            assert_eq!(edges.len(), 1);
            assert_eq!(edges[0].to.purl, "pkg:npm/shared@3.0.0");
        } else {
            assert!(edges.is_empty());
            assert!(!graph.complete());
        }
    }
    Ok(())
}

#[test]
fn snapshots_exports_and_advisories_preserve_local_occurrences_and_coverage_gaps() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let report = deps::scan_project(dir.path())?;
    let mut bom = Vec::new();
    deps::cyclonedx::write_json_with_profile(
        &report,
        deps::cyclonedx::ExportProfile::PrivateDetailed,
        &mut bom,
    )?;
    let bom: Value = serde_json::from_slice(&bom)?;
    assert_eq!(bom["components"].as_array().ok_or("components")?.len(), 7);
    // Six local origins have outgoing edges, plus the synthetic inventory root.
    assert_eq!(
        bom["dependencies"].as_array().ok_or("dependencies")?.len(),
        7
    );
    let advisories = deps::vuln::Snapshot {
        schema_version: 1,
        source: "https://osv.dev/synthetic".into(),
        fetched_at: "2026-11-06T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["npm".into()],
        advisories: vec![
            json!({"id":"TEST-LOCAL","modified":"2026-11-05T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"@fixture/a"},"versions":["1.0.0"]}]}),
        ],
    };
    let assessment = deps::vuln::assess(&report, &advisories, "2026-11-06T12:00:00Z", 86400)?;
    assert_eq!(assessment.coverage.assessed_components, 1);
    assert!(!assessment.complete);
    assert!(assessment.findings.is_empty());
    Ok(())
}

#[test]
fn separate_locks_do_not_merge_local_sources_or_inventory_occurrences() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "one/", "package-lock.json", 3)?;
    fixture(dir.path(), "two/", "package-lock.json", 3)?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(graph.components.len(), 14);
    Ok(())
}

#[test]
fn a_node_modules_substring_is_not_an_installation_path() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let path = dir.path().join("package-lock.json");
    let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let link = lock["packages"]
        .as_object_mut()
        .ok_or("packages")?
        .remove("node_modules/@fixture/a")
        .ok_or("link")?;
    lock["packages"]["not-node_modules/@fixture/a"] = link;
    fs::write(path, lock.to_string())?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert!(!graph
        .components
        .iter()
        .any(|n| n.component.context == "not-node_modules/@fixture/a"));
    Ok(())
}
