use ladybom::deps;
use ladybom_graph as graph;
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
        let alignment = graph::alignment(&graph)?;
        assert_eq!(alignment.coverage.unidentified_components, 0);
        assert_eq!(alignment.coverage.unprojected_components, 0);
        assert_eq!(alignment.coverage.unmapped_nodes, 0);
        assert!(alignment.coverage.versions_complete);
        assert_eq!(alignment.groups.len(), 4);
        assert!(alignment
            .groups
            .iter()
            .filter(|g| g.identity.starts_with("pkg:generic/npm-local/"))
            .all(|g| g.versions.len() == 1 && g.versions[0].nodes.len() == 2));
    }
    Ok(())
}

#[test]
fn missing_or_conflicting_manifest_proofs_keep_local_coverage_incomplete() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let original = deps::scan_project(dir.path())?;
    for case in [
        "root_input",
        "lock_input",
        "member_input",
        "legacy",
        "version",
        "name",
        "workspace",
    ] {
        let mut report = original.clone();
        match case {
            "root_input" => {
                report.inputs.remove("package.json");
            }
            "lock_input" => {
                report.inputs.remove("package-lock.json");
            }
            "member_input" => {
                report.inputs.remove("packages/a/package.json");
            }
            _ => {
                let manifest = if case == "workspace" {
                    "package.json"
                } else {
                    "packages/a/package.json"
                };
                let project = report
                    .projects
                    .iter_mut()
                    .find(|p| p.manifest == manifest)
                    .ok_or("project")?;
                match case {
                    "legacy" => project.manifest_package = None,
                    "version" => {
                        project.manifest_package.as_mut().ok_or("identity")?.version =
                            "9.0.0".into()
                    }
                    "name" => {
                        project.manifest_package.as_mut().ok_or("identity")?.name = "wrong".into()
                    }
                    "workspace" => project.workspace = json!(["packages/b", "packages/c"]),
                    _ => return Err("case".into()),
                }
            }
        }
        let graph = graph::project(report)?;
        let result = graph::alignment(&graph)?;
        assert!(!result.coverage.versions_complete, "{case}");
        assert!(result.coverage.unidentified_components >= 2, "{case}");
        assert_eq!(result.coverage.unmapped_nodes, 0, "{case}");
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
            !graph::alignment(&graph)?.coverage.versions_complete,
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
        assert!(
            !graph::alignment(&graph)?.coverage.versions_complete,
            "{name}@{version}"
        );
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
    let alignment = graph::alignment(&graph)?;
    assert_eq!(alignment.groups.len(), 5);
    assert!(alignment.coverage.versions_complete);
    let local_a: Vec<_> = alignment
        .groups
        .iter()
        .filter(|g| g.identity == "pkg:generic/npm-local/%40fixture/a")
        .collect();
    assert_eq!(local_a.len(), 2);
    assert_ne!(local_a[0].source, local_a[1].source);
    assert!(local_a.iter().all(|g| g.versions[0].nodes.len() == 2));
    assert!(alignment
        .groups
        .iter()
        .any(|g| g.identity == "pkg:npm/%40fixture/a"));
    let plan = graph::plan_alignment(&graph)?;
    assert!(plan.actions.iter().any(|a| a.kind
        == graph::AlignmentPlanActionKind::ReviewSourceVariants
        && a.group_indices.len() == 3));
    Ok(())
}

#[test]
fn snapshots_exports_and_advisories_preserve_local_occurrences_and_coverage_gaps() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let report = deps::scan_project(dir.path())?;
    let graph = graph::project(report)?;
    let snapshot_dir = tempfile::tempdir()?;
    let path = snapshot_dir.path().join("graph");
    graph::write_snapshot(&graph, &path)?;
    let restored = graph::read_snapshot(&path)?;
    assert_eq!(
        serde_json::to_value(&graph)?,
        serde_json::to_value(&restored)?
    );
    assert!(graph::alignment(&restored)?.coverage.versions_complete);
    write(dir.path(), "python/pyproject.toml", json!({}))?;
    fs::write(
        dir.path().join("python/pyproject.toml"),
        "[project]\nname='python-package'\nversion='1.0.0'\ndependencies=['requests>=2']\n",
    )?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    assert_eq!(
        graph::alignment(&graph)?.coverage.unidentified_components,
        0
    );
    assert!(!graph::alignment(&graph)?.coverage.inventory_complete);
    Ok(())
}

#[test]
fn separate_locks_do_not_merge_local_sources_or_inventory_occurrences() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "one/", "package-lock.json", 3)?;
    fixture(dir.path(), "two/", "package-lock.json", 3)?;
    let graph = graph::project(deps::scan_project(dir.path())?)?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.domains.len(), 2);
    assert_eq!(result.groups.len(), 8);
    assert_eq!(result.coverage.inventory_components, 14);
    assert!(result.coverage.versions_complete);
    Ok(())
}

#[test]
fn changed_node_or_inventory_evidence_cannot_keep_full_coverage() -> Result {
    let dir = tempfile::tempdir()?;
    fixture(dir.path(), "", "package-lock.json", 3)?;
    let original = graph::project(deps::scan_project(dir.path())?)?;
    assert!(graph::alignment(&original)?.coverage.versions_complete);
    for case in ["missing_node", "source", "metadata", "identity", "context"] {
        let mut graph = original.clone();
        let index = graph
            .components
            .iter()
            .position(|n| n.component.context == "node_modules/@fixture/a")
            .ok_or("local node")?;
        if case == "missing_node" {
            let node = graph.components.remove(index);
            graph
                .dependencies
                .retain(|e| e.from != node.key && e.to != node.key);
            graph.roots.retain(|r| r.to != node.key);
        } else {
            let node = &mut graph.components[index];
            match case {
                "source" => node.component.source = json!("packages/b"),
                "metadata" => node.component.metadata["resolved"] = json!("packages/b"),
                "identity" => node.component.name = "wrong".into(),
                "context" => node.component.context = "node_modules/other".into(),
                _ => return Err("case".into()),
            }
        }
        if let Ok(result) = graph::alignment(&graph) {
            assert!(!result.coverage.versions_complete, "{case}");
        }
    }
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
    assert!(!graph::alignment(&graph)?.coverage.versions_complete);
    Ok(())
}
