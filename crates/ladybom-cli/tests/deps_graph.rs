#![cfg(feature = "graph")]

use ladybom::deps;
use ladybom_graph as graph;
use serde_json::json;
use std::{fs, path::Path};

fn npm(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        root.join("package.json"),
        json!({"name":"demo","version":"1.0.0","dependencies":{"a":"1","c":"1"}}).to_string(),
    )?;
    fs::write(
        root.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":{
            "":{"name":"demo","version":"1.0.0"},
            "node_modules/a":{"version":"1.0.0","dependencies":{"b":"1"}},
            "node_modules/b":{"version":"1.0.0","dependencies":{"a":"1"}},
            "node_modules/c":{"version":"1.0.0","dependencies":{"b":"1"}},
            "node_modules/c/node_modules/b":{"version":"1.0.0","dependencies":{"d":"1"}},
            "node_modules/d":{"version":"1.0.0"}
        }})
        .to_string(),
    )?;
    Ok(())
}

#[test]
fn projection_preserves_npm_resolution_scopes_and_cycles() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    assert!(graph.complete(), "{:?}", graph.limitations);
    assert_eq!(graph.components.len(), 5);
    assert_eq!(graph.dependencies.len(), 4);
    let a = graph
        .components
        .iter()
        .find(|n| n.component.context == "node_modules/a")
        .ok_or("a")?;
    let b = graph
        .components
        .iter()
        .find(|n| n.component.context == "node_modules/b")
        .ok_or("b")?;
    let nested = graph
        .components
        .iter()
        .find(|n| n.component.context == "node_modules/c/node_modules/b")
        .ok_or("nested")?;
    assert_eq!(b.key.purl, nested.key.purl);
    assert_ne!(b.key.graph, nested.key.graph);
    assert!(graph
        .dependencies
        .iter()
        .any(|e| e.from == a.key && e.to == b.key));
    assert!(!graph
        .dependencies
        .iter()
        .any(|e| e.from == a.key && e.to == nested.key));
    assert_eq!(graph.roots.len(), 2);
    Ok(())
}

#[test]
fn unresolved_edges_are_partial_and_no_local_purls_are_invented(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut report = deps::scan_project(root.path())?;
    report.projects[0].components.retain(|c| c.name != "b");
    let graph = graph::project(report)?;
    assert!(!graph.complete());
    assert!(!graph.limitations.is_empty());
    assert!(graph.dependencies.is_empty());
    Ok(())
}

#[test]
fn snapshots_are_immutable_and_refuse_tampering() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let dest = root.path().join("snapshot");
    graph::write_snapshot(&graph, &dest)?;
    let restored = graph::read_snapshot(&dest)?;
    assert_eq!(
        serde_json::to_value(&restored)?,
        serde_json::to_value(&graph)?
    );
    assert!(graph::write_snapshot(&graph, &dest).is_err());
    let file = dest
        .join(&graph.components[0].key.graph)
        .join("components.parquet");
    fs::write(file, b"corrupt")?;
    assert!(graph::read_snapshot(&dest).is_err());
    Ok(())
}

#[test]
fn malformed_references_and_symlink_inputs_are_refused() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut graph = graph::project(deps::scan_project(root.path())?)?;
    graph.dependencies[0].to.purl = "pkg:npm/missing@1.0.0".into();
    assert!(graph::write_snapshot(&graph, &root.path().join("invalid")).is_err());
    assert!(!root.path().join("invalid").exists());
    std::os::unix::fs::symlink(root.path(), root.path().join("link"))?;
    assert!(graph::read_snapshot(&root.path().join("link")).is_err());
    Ok(())
}

#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_traversal_matches_bfs_and_filters_before_traversal(
) -> Result<(), Box<dyn std::error::Error>> {
    use graph::{Direction, Filter, Ladybug, Query};
    use std::collections::{BTreeMap, VecDeque};
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut graph = graph::project(deps::scan_project(root.path())?)?;
    let key = |name: &str| -> Result<graph::NodeRef, Box<dyn std::error::Error>> {
        Ok(graph
            .components
            .iter()
            .find(|n| n.component.context == name)
            .ok_or("node")?
            .key
            .clone())
    };
    let a = key("node_modules/a")?;
    let c = key("node_modules/c")?;
    let d = key("node_modules/d")?;
    let engine = Ladybug::new(
        std::env::var_os("LADYBOM_LADYBUG_BIN")
            .ok_or("LADYBOM_LADYBUG_BIN absent")?
            .into(),
    )?;
    for start in [&a, &c, &d] {
        for direction in [Direction::Dependencies, Direction::Dependants] {
            let mut seen = BTreeMap::from([(start.clone(), 0)]);
            let mut queue = VecDeque::from([start.clone()]);
            while let Some(node) = queue.pop_front() {
                let distance = seen[&node];
                for e in &graph.dependencies {
                    let (from, to) = if direction == Direction::Dependencies {
                        (&e.from, &e.to)
                    } else {
                        (&e.to, &e.from)
                    };
                    if *from == node && !seen.contains_key(to) {
                        seen.insert(to.clone(), distance + 1);
                        queue.push_back(to.clone());
                    }
                }
            }
            seen.remove(start);
            let result = engine.query(
                &graph,
                &Query {
                    start: start.clone(),
                    direction,
                    target: None,
                    max_depth: 32,
                    filter: Filter::default(),
                },
            )?;
            assert!(result.complete);
            assert_eq!(
                result
                    .nodes
                    .iter()
                    .map(|n| (n.node.clone(), n.distance))
                    .collect::<BTreeMap<_, _>>(),
                seen
            );
            for hit in result.nodes {
                assert_eq!(hit.path.first(), Some(start));
                assert_eq!(hit.path.last(), Some(&hit.node));
                assert_eq!(hit.path.len(), hit.distance as usize + 1);
            }
        }
    }
    let shallow = engine.query(
        &graph,
        &Query {
            start: c.clone(),
            direction: Direction::Dependencies,
            target: None,
            max_depth: 1,
            filter: Filter::default(),
        },
    )?;
    assert!(shallow.truncated);
    assert!(!shallow.complete);
    assert_eq!(shallow.nodes.len(), 1);
    let path = engine.query(
        &graph,
        &Query {
            start: c.clone(),
            direction: Direction::Dependencies,
            target: Some(d.clone()),
            max_depth: 32,
            filter: Filter::default(),
        },
    )?;
    assert_eq!(path.nodes.len(), 1);
    assert_eq!(path.nodes[0].distance, 2);
    let snapshot = root.path().join("snapshot");
    graph::write_snapshot(&graph, &snapshot)?;
    let impact = std::process::Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "impact", "--snapshot"])
        .arg(&snapshot)
        .arg("--engine")
        .arg(std::env::var_os("LADYBOM_LADYBUG_BIN").ok_or("engine")?)
        .args(["--purl", "pkg:npm/d@1.0.0"])
        .output()?;
    assert!(
        impact.status.success(),
        "{}",
        String::from_utf8_lossy(&impact.stderr)
    );
    let impact: serde_json::Value = serde_json::from_slice(&impact.stdout)?;
    assert_eq!(impact["nodes"].as_array().ok_or("nodes")?.len(), 2);
    assert_eq!(impact["roots"].as_array().ok_or("roots")?.len(), 1);
    assert_eq!(impact["roots"][0]["to"]["purl"], "pkg:npm/c@1.0.0");
    graph
        .dependencies
        .iter_mut()
        .filter(|e| e.from == c)
        .for_each(|e| e.kind = "dev".into());
    let filtered = engine.query(
        &graph,
        &Query {
            start: c,
            direction: Direction::Dependencies,
            target: None,
            max_depth: 32,
            filter: Filter {
                kinds: ["runtime".into()].into(),
                ..Default::default()
            },
        },
    )?;
    assert!(filtered.nodes.is_empty());
    Ok(())
}

#[test]
fn cli_exports_and_diffs_snapshots_without_engine_or_project_execution(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let dest = root.path().join("snapshot");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "export", "--project"])
        .arg(root.path())
        .arg("--output")
        .arg(&dest)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let diff = std::process::Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["graph", "diff", "--before"])
        .arg(&dest)
        .arg("--after")
        .arg(&dest)
        .output()?;
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&diff.stdout)?;
    assert_eq!(value["added"], json!([]));
    assert_eq!(value["removed_edges"], json!([]));
    Ok(())
}

#[test]
fn cargo_and_uv_keep_native_edges_and_unresolved_conditions(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("rust"))?;
    fs::create_dir(root.path().join("py"))?;
    fs::write(
        root.path().join("rust/Cargo.toml"),
        "[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\na='1'\n",
    )?;
    fs::write(
        root.path().join("rust/Cargo.lock"),
        r#"version=4
+[[package]]
+name="demo"
+version="1.0.0"
+dependencies=["a"]
+[[package]]
+name="a"
+version="1.0.0"
+source="registry+https://github.com/rust-lang/crates.io-index"
+dependencies=["b"]
+[[package]]
+name="b"
+version="1.0.0"
+source="registry+https://github.com/rust-lang/crates.io-index"
+"#
        .replace("\n+", "\n"),
    )?;
    fs::write(
        root.path().join("py/pyproject.toml"),
        "[project]\nname='py-demo'\nversion='1.0'\ndependencies=['a>=1']\n",
    )?;
    fs::write(
        root.path().join("py/uv.lock"),
        r#"version=1
+[[package]]
+name="a"
+version="1.0"
+source={registry="https://pypi.org/simple"}
+dependencies=[{name="b", marker="sys_platform == 'linux'"}]
+[[package]]
+name="b"
+version="1.0"
+source={registry="https://pypi.org/simple"}
+"#
        .replace("\n+", "\n"),
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    assert_eq!(graph.dependencies.len(), 3, "{:?}", graph.limitations);
    assert!(!graph.complete());
    assert!(graph.dependencies.iter().all(|e| !e.condition.is_null()));
    assert!(graph
        .components
        .iter()
        .any(|n| n.key.purl == "pkg:generic/cargo-local/demo@1.0.0"));
    assert!(graph
        .roots
        .iter()
        .any(|r| r.manifest == "rust/Cargo.toml" && r.to.purl == "pkg:cargo/a@1.0.0"));
    Ok(())
}

#[test]
fn package_conditions_and_malformed_metadata_cannot_claim_completeness(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut report = deps::scan_project(root.path())?;
    report.projects[0].components[0].metadata["os"] = json!(["linux"]);
    let graph = graph::project(report)?;
    assert!(!graph.complete(), "OS condition cannot be silently erased");
    let mut report = deps::scan_project(root.path())?;
    report.projects[0].components[0].metadata["dependencies"] = json!(["b"]);
    assert!(
        graph::project(report).is_err(),
        "malformed metadata must be refused"
    );
    Ok(())
}

#[test]
fn conditional_roots_are_partial_and_aliases_keep_separate_occurrences(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut report = deps::scan_project(root.path())?;
    report.projects[0].requirements[0].marker = Some("synthetic-condition".into());
    assert!(!graph::project(report)?.complete());
    let mut report = deps::scan_project(root.path())?;
    let mut alias = report.projects[0].components[0].clone();
    alias.context = "node_modules/alias".into();
    report.projects[0].components.push(alias);
    let graph = graph::project(report)?;
    assert_eq!(graph.components.len(), 6);
    let duplicate_keys: std::collections::BTreeSet<_> =
        graph.components.iter().map(|n| &n.key).collect();
    assert_eq!(duplicate_keys.len(), 6);
    Ok(())
}

#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_diamond_depth_conditions_contexts_and_timeout() -> Result<(), Box<dyn std::error::Error>>
{
    use graph::{Direction, Filter, Ladybug, Query};
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut graph = graph::project(deps::scan_project(root.path())?)?;
    let keys: Vec<_> = graph.components.iter().map(|n| n.key.clone()).collect();
    // Independent hand-checked graph: diamond 0->1,0->2,1->3,2->3,3->4.
    graph.dependencies.clear();
    for (a, b) in [(0, 1), (0, 2), (1, 3), (2, 3), (3, 4)] {
        graph.dependencies.push(graph::Edge {
            from: keys[a].clone(),
            to: keys[b].clone(),
            kind: "runtime".into(),
            condition: serde_json::Value::Null,
            evidence: json!({"fixture":true}),
        });
    }
    let engine = Ladybug::new(
        std::env::var_os("LADYBOM_LADYBUG_BIN")
            .ok_or("engine")?
            .into(),
    )?;
    let mut query = Query {
        start: keys[0].clone(),
        direction: Direction::Dependencies,
        target: None,
        max_depth: 2,
        filter: Filter::default(),
    };
    let shallow = engine.query(&graph, &query)?;
    assert_eq!(shallow.nodes.len(), 3);
    assert!(shallow.truncated);
    query.max_depth = 3;
    let full = engine.query(&graph, &query)?;
    assert_eq!(full.nodes.len(), 4);
    assert!(!full.truncated);
    assert_eq!(
        full.nodes
            .iter()
            .find(|n| n.node == keys[3])
            .ok_or("diamond join")?
            .distance,
        2
    );
    graph
        .dependencies
        .iter_mut()
        .filter(|e| e.to == keys[3])
        .for_each(|e| e.condition = json!({"marker":"synthetic"}));
    query.filter.include_conditional = false;
    let filtered = engine.query(&graph, &query)?;
    assert_eq!(filtered.nodes.len(), 2);
    assert!(filtered.nodes.iter().all(|n| n.node != keys[4]));
    query.filter.graphs = [keys[0].graph.clone()].into();
    let scoped = engine.query(&graph, &query)?;
    assert!(scoped.nodes.iter().all(|n| n.node.graph == keys[0].graph));
    let short = engine.with_timeout(std::time::Duration::from_millis(1))?;
    assert!(short.query(&graph, &query).is_err());
    Ok(())
}

#[test]
fn snapshot_rejects_duplicate_nodes_and_changed_files_even_with_hostile_names(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut graph = graph::project(deps::scan_project(root.path())?)?;
    graph.components.push(graph.components[0].clone());
    assert!(graph::write_snapshot(&graph, &root.path().join("duplicate")).is_err());
    graph.components.pop();
    let dest = root.path().join("spaces ' and ; $ characters");
    graph::write_snapshot(&graph, &dest)?;
    let metadata = dest.join("inventory.json");
    let outside = root.path().join("outside.json");
    fs::rename(&metadata, &outside)?;
    std::os::unix::fs::symlink(&outside, &metadata)?;
    assert!(graph::read_snapshot(&dest).is_err());
    Ok(())
}

#[test]
fn workspace_roots_do_not_attribute_other_members_dependencies(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join("app"))?;
    fs::create_dir(root.path().join("other"))?;
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=['app','other']\nresolver='2'\n",
    )?;
    for (member, dep) in [("app", "x"), ("other", "y")] {
        fs::write(
            root.path().join(member).join("Cargo.toml"),
            format!("[package]\nname='{member}'\nversion='1.0.0'\n[dependencies]\n{dep}='1'\n"),
        )?;
    }
    fs::write(
        root.path().join("Cargo.lock"),
        r#"version=4
[[package]]
name="app"
version="1.0.0"
dependencies=["x"]
[[package]]
name="other"
version="1.0.0"
dependencies=["y"]
[[package]]
name="x"
version="1.0.0"
source="registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name="y"
version="1.0.0"
source="registry+https://github.com/rust-lang/crates.io-index"
"#,
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let app_roots: Vec<_> = graph
        .roots
        .iter()
        .filter(|r| r.manifest == "app/Cargo.toml")
        .collect();
    assert_eq!(app_roots.len(), 1);
    assert_eq!(app_roots[0].to.purl, "pkg:cargo/x@1.0.0");
    assert!(!graph.roots.iter().any(|r| r.manifest == "Cargo.toml"));
    assert_eq!(
        graph.components.len(),
        4,
        "one lock graph shared by workspace members"
    );
    assert_eq!(
        graph.contexts.len(),
        2,
        "registry and local source contexts"
    );
    Ok(())
}

#[test]
fn python_group_inclusion_never_resolves_as_a_package_name(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::write(root.path().join("pyproject.toml"), "[project]\nname='demo'\nversion='1.0'\ndependencies=['a']\n[dependency-groups]\ndev=[{include-group='test'}]\ntest=['pytest']\n")?;
    fs::write(
        root.path().join("uv.lock"),
        r#"version=1
[[package]]
name="a"
version="1.0"
source={registry="https://pypi.org/simple"}
dependencies=[{name="test"}]
[[package]]
name="test"
version="1.0"
source={registry="https://pypi.org/simple"}
[[package]]
name="pytest"
version="1.0"
source={registry="https://pypi.org/simple"}
"#,
    )?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    assert!(!graph.roots.iter().any(|r| r.kind.ends_with(":include")));
    assert!(!graph.complete());
    Ok(())
}

#[test]
fn incompatible_versions_do_not_create_root_or_transitive_links(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let mut report = deps::scan_project(root.path())?;
    report.projects[0].requirements[0].constraint = "^2.0.0".into();
    report.projects[0].components[0].metadata["dependencies"]["b"] = json!("^2.0.0");
    let graph = graph::project(report)?;
    assert!(!graph.complete());
    assert!(!graph.roots.iter().any(|r| r.to.purl == "pkg:npm/a@1.0.0"));
    assert!(!graph
        .dependencies
        .iter()
        .any(|e| e.from.purl == "pkg:npm/a@1.0.0"));
    Ok(())
}

#[test]
fn engine_errors_zero_exit_missing_receipts_and_timeouts_are_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    use graph::{Direction, Filter, Ladybug, Query};
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir()?;
    npm(root.path())?;
    let graph = graph::project(deps::scan_project(root.path())?)?;
    let query = Query {
        start: graph.components[0].key.clone(),
        direction: Direction::Dependencies,
        target: None,
        max_depth: 32,
        filter: Filter::default(),
    };
    let binary = root.path().join("synthetic-engine");
    for body in [
        "printf 'Error: Parser exception\\n'",
        "printf '[]\\n'",
        "exit 1",
    ] {
        fs::write(&binary, format!("#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf 'Lbug 0.17.1\\n'; exit 0; fi\nprintf '%s\\n' '-- Processing: empty.cypher'\n{body}\n"))?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        assert!(Ladybug::new(binary.clone())?.query(&graph, &query).is_err());
    }
    fs::write(&binary, "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf 'Lbug 0.17.1\\n'; exit 0; fi\nexec /bin/sleep 10\n")?;
    let started = std::time::Instant::now();
    assert!(Ladybug::new(binary.clone())?
        .with_timeout(std::time::Duration::from_millis(50))?
        .query(&graph, &query)
        .is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    fs::write(&binary, "#!/bin/sh\nprintf 'Lbug 0.0.0\\n'\n")?;
    assert!(Ladybug::new(binary)?.query(&graph, &query).is_err());
    Ok(())
}

#[test]
fn independent_cargo_locks_do_not_share_occurrences_or_cached_dependencies(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    for (folder, dependencies) in [("one", ""), ("two", "dependencies=['y']")] {
        fs::create_dir(root.path().join(folder))?;
        fs::write(
            root.path().join(folder).join("Cargo.toml"),
            "[package]\nname='demo'\nversion='1.0.0'\n[dependencies]\nx='1'\n",
        )?;
        fs::write(root.path().join(folder).join("Cargo.lock"), format!("version=4\n[[package]]\nname='x'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n{dependencies}\n[[package]]\nname='y'\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\n"))?;
    }
    let graph = graph::project(deps::scan_project(root.path())?)?;
    assert_eq!(graph.components.len(), 4);
    assert_eq!(graph.contexts.len(), 2);
    assert_eq!(graph.dependencies.len(), 1);
    assert_eq!(
        graph.contexts[&graph.dependencies[0].from.graph].manifest,
        "two/Cargo.toml"
    );
    Ok(())
}
