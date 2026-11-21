use ladybom::deps;
use ladybom_graph as graph;
use serde_json::json;
use std::{fs, path::Path};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fixture(root: &Path) -> Result<graph::Graph> {
    fs::write(
        root.join("package.json"),
        json!({"dependencies":{"a":"1","c":"1"}}).to_string(),
    )?;
    fs::write(
        root.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":{
            "":{},
            "node_modules/a":{"version":"1.0.0","dependencies":{"shared":"1","unique":"1"}},
            "node_modules/c":{"version":"1.0.0","dependencies":{"shared":"1"}},
            "node_modules/shared":{"version":"1.0.0"},
            "node_modules/unique":{"version":"1.0.0","dependencies":{"a":"1"}},
            "node_modules/orphan":{"version":"1.0.0"}
        }})
        .to_string(),
    )?;
    Ok(graph::project(deps::scan_project(root)?)?)
}
#[test]
fn removal_requests_are_bound_to_graph_and_exact_declarations() -> Result {
    let dir = tempfile::tempdir()?;
    let g = fixture(dir.path())?;
    let roots = graph::root_catalog(&g)?;
    assert_eq!(roots.len(), 2);
    let mut request = graph::RemovalRequest::new(&g, vec![roots[0].id.clone()])?;
    request.validate(&g)?;
    request.remove_roots.push(roots[0].id.clone());
    assert!(request.validate(&g).is_err());
    request.remove_roots = vec!["0".repeat(64)];
    assert!(request.validate(&g).is_err());
    request.remove_roots.clear();
    assert!(request.validate(&g).is_err());
    request.remove_roots = vec![roots[0].id.clone()];
    request.graph_sha256 = "0".repeat(64);
    assert!(request.validate(&g).is_err());
    Ok(())
}
#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_removal_keeps_shared_dependencies_and_frees_orphaned_cycles() -> Result {
    let dir = tempfile::tempdir()?;
    let g = fixture(dir.path())?;
    let roots = graph::root_catalog(&g)?;
    let a = roots
        .iter()
        .find(|r| r.root.to.purl == "pkg:npm/a@1.0.0")
        .ok_or("root a")?;
    let engine = graph::Ladybug::new(
        std::env::var_os("LADYBOM_LADYBUG_BIN")
            .ok_or("engine")?
            .into(),
    )?;
    let request = graph::RemovalRequest::new(&g, vec![a.id.clone()])?;
    let result = engine.simulate_removal(&g, &request)?;
    assert!(result.complete);
    assert!(!result.truncated);
    assert_eq!(result.before_reachable, 4);
    assert_eq!(result.after_reachable, 2);
    assert_eq!(
        result
            .freed_in_model
            .iter()
            .map(|n| n.purl.as_str())
            .collect::<Vec<_>>(),
        ["pkg:npm/a@1.0.0", "pkg:npm/unique@1.0.0"]
    );
    assert_eq!(result.already_unreachable.len(), 1);
    assert_eq!(result.already_unreachable[0].purl, "pkg:npm/orphan@1.0.0");
    assert_eq!(result.retained_removed_targets.len(), 0);
    // Removing a declaration must not delete a package reached through another root.
    let mut shared = g.clone();
    let c = roots
        .iter()
        .find(|r| r.root.to.purl == "pkg:npm/c@1.0.0")
        .ok_or("root c")?;
    shared.dependencies.push(graph::Edge {
        from: c.root.to.clone(),
        to: a.root.to.clone(),
        kind: "runtime".into(),
        condition: serde_json::Value::Null,
        evidence: json!({}),
    });
    let retained_request = graph::RemovalRequest::new(&shared, vec![a.id.clone()])?;
    let retained = engine.simulate_removal(&shared, &retained_request)?;
    assert!(retained.freed_in_model.is_empty());
    assert_eq!(retained.retained_removed_targets.len(), 1);
    assert_eq!(retained.retained_removed_targets[0].via_roots[0].id, c.id);
    assert_eq!(
        retained.retained_removed_targets[0].path,
        vec![c.root.to.clone(), a.root.to.clone()]
    );
    let request = graph::RemovalRequest::new(&g, roots.iter().map(|r| r.id.clone()).collect())?;
    let result = engine.simulate_removal(&g, &request)?;
    assert_eq!(result.freed_in_model.len(), 4);
    assert_eq!(result.after_reachable, 0);
    Ok(())
}
#[test]
#[ignore = "requires pinned native LadybugDB via LADYBOM_LADYBUG_BIN"]
fn native_removal_distinguishes_contexts_and_refuses_gain_on_truncation() -> Result {
    let dir = tempfile::tempdir()?;
    let mut g = fixture(dir.path())?;
    let a = graph::root_catalog(&g)?
        .into_iter()
        .find(|r| r.root.to.purl == "pkg:npm/a@1.0.0")
        .ok_or("a")?;
    let unique = g
        .components
        .iter()
        .find(|n| n.component.name == "unique")
        .ok_or("unique")?
        .key
        .clone();
    let orphan = g
        .components
        .iter()
        .find(|n| n.component.name == "orphan")
        .ok_or("orphan")?
        .key
        .clone();
    g.dependencies.push(graph::Edge {
        from: unique,
        to: orphan,
        kind: "runtime".into(),
        condition: serde_json::Value::Null,
        evidence: json!({}),
    });
    let mut request = graph::RemovalRequest::new(&g, vec![a.id.clone()])?;
    request.max_depth = 1;
    let engine = graph::Ladybug::new(
        std::env::var_os("LADYBOM_LADYBUG_BIN")
            .ok_or("engine")?
            .into(),
    )?;
    let result = engine.simulate_removal(&g, &request)?;
    assert!(result.truncated);
    assert!(!result.complete);
    assert!(result.freed_in_model.is_empty());
    assert!(result.already_unreachable.is_empty());
    // A separate occurrence with the same PURL remains reachable from a retained root.
    let mut occurrence = g
        .components
        .iter()
        .find(|n| n.component.name == "a")
        .ok_or("a")?
        .clone();
    let context = graph::Context {
        manifest: "package.json".into(),
        native: json!({"installation":"isolated"}),
    };
    occurrence.key.graph = context.path()?;
    g.contexts.insert(occurrence.key.graph.clone(), context);
    g.components.push(occurrence.clone());
    let mut other_root = a.root.clone();
    other_root.to = occurrence.key.clone();
    g.roots.push(other_root);
    let request = graph::RemovalRequest::new(&g, vec![a.id])?;
    let result = engine.simulate_removal(&g, &request)?;
    assert_eq!(
        result
            .freed_in_model
            .iter()
            .filter(|n| n.purl == occurrence.key.purl)
            .count(),
        1
    );
    assert!(!result.freed_in_model.contains(&occurrence.key));
    Ok(())
}
