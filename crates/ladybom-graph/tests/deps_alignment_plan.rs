use ladybom::deps::{self, Component, Project, Report};
use ladybom_graph as graph;
use serde_json::{json, Value};
use std::collections::BTreeMap;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn package(version: &str, context: &str) -> Component {
    Component {
        name: "shared".into(),
        version: version.into(),
        purl: Some(format!("pkg:npm/shared@{version}")),
        context: context.into(),
        source: Value::Null,
        artifacts: Vec::new(),
        metadata: json!({}),
    }
}

fn project(prefix: &str, components: Vec<Component>) -> Project {
    Project {
        manifest_package: None,
        ecosystem: "npm".into(),
        root: ".".into(),
        manifest: format!("{prefix}package.json"),
        lockfile: Some(format!("{prefix}package-lock.json")),
        locked: true,
        manager: "npm".into(),
        tools: Vec::new(),
        requirements: Vec::new(),
        components,
        components_from: None,
        workspace: Value::Null,
    }
}

fn snapshot(projects: Vec<Project>) -> Result<graph::Graph, ladybom::error::Error> {
    graph::project(Report {
        schema_version: 2,
        complete: true,
        inputs: BTreeMap::new(),
        projects,
        diagnostics: Vec::new(),
    })
}

fn duplicate_graph() -> Result<graph::Graph, ladybom::error::Error> {
    snapshot(vec![project(
        "",
        vec![
            package("1.2.3", "node_modules/alias"),
            package("2.0.0", "node_modules/parent/node_modules/shared"),
        ],
    )])
}

// Losing the domain/source discriminator would offer a lock rewrite for independent locks.
#[test]
fn separates_duplicate_cross_domain_and_source_review_actions() -> TestResult {
    let within = graph::plan_alignment(&duplicate_graph()?)?;
    let value = serde_json::to_value(&within)?;
    assert_eq!(value["actions"][0]["kind"], "review_lock_resolution");
    assert_eq!(value["actions"][1]["kind"], "review_parent_migration");
    assert_eq!(value["actions"][0]["group_indices"], json!([0]));
    assert_eq!(within.occurrences.len(), 2);
    assert!(within
        .occurrences
        .iter()
        .any(|node| node.native_context == "node_modules/alias"));
    assert!(within.analysis_complete);
    assert!(!within.remediation_approved);
    assert!(within
        .occurrences
        .iter()
        .all(|node| !node.transitive_constraints_complete));

    let separate = graph::plan_alignment(&snapshot(vec![
        project("a/", vec![package("1.2.3", "node_modules/shared")]),
        project("b/", vec![package("2.0.0", "node_modules/shared")]),
    ])?)?;
    let value = serde_json::to_value(separate)?;
    assert_eq!(value["actions"].as_array().ok_or("actions")?.len(), 1);
    assert_eq!(value["actions"][0]["kind"], "review_cross_domain");
    assert_eq!(
        value["actions"][0]["group_indices"]
            .as_array()
            .ok_or("groups")?
            .len(),
        2
    );

    let mut a = package("1.2.3", "node_modules/shared");
    a.source = json!("https://one.invalid/shared.tgz");
    let mut b = package("2.0.0", "node_modules/parent/node_modules/shared");
    b.source = json!("https://two.invalid/shared.tgz");
    let sources = graph::plan_alignment(&snapshot(vec![project("", vec![a, b])])?)?;
    let value = serde_json::to_value(sources)?;
    assert_eq!(value["actions"].as_array().ok_or("actions")?.len(), 1);
    assert_eq!(value["actions"][0]["kind"], "review_source_variants");
    assert_eq!(
        value["alignment"]["source_variants"][0]["sources"]
            .as_array()
            .ok_or("sources")?
            .len(),
        2
    );
    Ok(())
}

// A partial report must remain blocked even when observed duplicates are actionable.
#[test]
fn coverage_gaps_precede_known_duplicates_and_unsupported_inventory() -> TestResult {
    let mut partial = duplicate_graph()?;
    partial.inventory.complete = false;
    partial.limitations.push("missing evidence".into());
    let plan = graph::plan_alignment(&partial)?;
    let value = serde_json::to_value(&plan)?;
    assert_eq!(value["actions"][0]["kind"], "complete_coverage");
    assert_eq!(value["actions"][1]["kind"], "review_lock_resolution");
    assert!(!plan.analysis_complete);
    assert!(plan.limitations.iter().any(|s| s == "missing evidence"));
    let mut unsupported = project("", vec![package("1.2.3", "node_modules/shared")]);
    unsupported.ecosystem = "unsupported".into();
    let plan = graph::plan_alignment(&snapshot(vec![unsupported])?)?;
    assert!(!plan.analysis_complete);
    assert_eq!(
        serde_json::to_value(&plan)?["actions"][0]["kind"],
        "complete_coverage"
    );
    let empty = graph::plan_alignment(&snapshot(Vec::new())?)?;
    assert!(!empty.analysis_complete);
    Ok(())
}

// An aligned inventory cannot be turned into a compatibility/security approval.
#[test]
fn no_duplicates_produces_no_migration_but_keeps_evidence_gates() -> TestResult {
    let graph = snapshot(vec![project(
        "",
        vec![package("1.2.3", "node_modules/shared")],
    )])?;
    let plan = graph::plan_alignment(&graph)?;
    assert!(plan.actions.is_empty());
    assert!(plan.analysis_complete);
    assert!(!plan.remediation_approved);
    let value = serde_json::to_value(&plan)?;
    let gates = value["gates"].as_array().ok_or("gates")?;
    for id in [
        "resolution_constraints",
        "current_advisories",
        "consumer_validation",
        "pins_and_policy",
    ] {
        assert!(gates.iter().any(|gate| gate["id"] == id), "missing {id}");
    }
    assert!(plan.to_markdown()?.contains("No reduction action"));
    Ok(())
}

// Cargo.lock edges are versions, not the missing published parent manifest ranges.
#[test]
fn cargo_preserves_parent_and_root_evidence_without_inventing_constraints() -> TestResult {
    let temp = tempfile::tempdir()?;
    std::fs::write(
        temp.path().join("Cargo.toml"),
        r#"[package]
name = "fixture"
version = "0.1.0"
[dependencies]
shared = "=1.2.3"
parent = "=3.0.0"
"#,
    )?;
    std::fs::write(
        temp.path().join("Cargo.lock"),
        r#"version = 4
[[package]]
name = "shared"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "shared"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "parent"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["shared 2.0.0"]
"#,
    )?;
    let graph = graph::project(deps::scan_project(temp.path())?)?;
    let plan = graph::plan_alignment(&graph)?;
    assert_eq!(plan.graph_digest, graph::graph_digest(&graph)?);
    let old = plan
        .occurrences
        .iter()
        .find(|node| node.node.purl == "pkg:cargo/shared@1.2.3")
        .ok_or("old")?;
    assert_eq!(old.roots.len(), 1);
    assert_eq!(old.roots[0].condition["constraint"], "=1.2.3");
    let new = plan
        .occurrences
        .iter()
        .find(|node| node.node.purl == "pkg:cargo/shared@2.0.0")
        .ok_or("new")?;
    assert_eq!(new.parents.len(), 1);
    assert_eq!(new.parents[0].from.purl, "pkg:cargo/parent@3.0.0");
    assert!(!new.transitive_constraints_complete);
    assert!(!plan.alignment.coverage.activation_known);
    Ok(())
}

// Repetition must not change action ordering; untrusted text must never form markup.
#[test]
fn deterministic_plan_and_markdown_escape_hostile_evidence() -> TestResult {
    let mut graph = duplicate_graph()?;
    graph
        .limitations
        .push("<script>alert(1)</script>\n[click](javascript:bad) | `code`\u{202e}".into());
    let before = graph::plan_alignment(&graph)?;
    let after = graph::plan_alignment(&graph)?;
    assert_eq!(serde_json::to_vec(&before)?, serde_json::to_vec(&after)?);
    assert_eq!(before.to_markdown()?, after.to_markdown()?);
    let markdown = before.to_markdown()?;
    for forbidden in ["<script>", "[click]", "javascript:", "`code`", "\u{202e}"] {
        assert!(!markdown.contains(forbidden), "unsafe {forbidden}");
    }
    assert!(markdown.contains("script"));
    assert!(markdown.contains(&before.graph_digest));
    graph.components.reverse();
    let reordered = graph::plan_alignment(&graph)?;
    // Digest records exact input order; action and evidence order must remain stable.
    assert_eq!(
        serde_json::to_value(before.actions)?,
        serde_json::to_value(reordered.actions)?
    );
    assert_eq!(
        serde_json::to_value(before.occurrences)?,
        serde_json::to_value(reordered.occurrences)?
    );
    Ok(())
}

// Installed aliases retain their actual package identity and native parent range.
#[test]
fn npm_aliases_keep_partial_parent_constraints_and_direct_declarations() -> TestResult {
    let temp = tempfile::tempdir()?;
    std::fs::write(
        temp.path().join("package.json"),
        json!({
            "name":"fixture", "version":"1.0.0",
            "dependencies":{"alias":"npm:shared@1.2.3", "parent":"3.0.0"}
        })
        .to_string(),
    )?;
    std::fs::write(
        temp.path().join("package-lock.json"),
        json!({
            "lockfileVersion":3, "packages":{
                "":{"name":"fixture","version":"1.0.0"},
                "node_modules/alias":{"name":"shared","version":"1.2.3"},
                "node_modules/parent":{"version":"3.0.0","dependencies":{"shared":"^2.0.0"}},
                "node_modules/parent/node_modules/shared":{"version":"2.0.0"}
            }
        })
        .to_string(),
    )?;
    let plan = graph::plan_alignment(&graph::project(deps::scan_project(temp.path())?)?)?;
    let group = plan
        .alignment
        .groups
        .iter()
        .find(|g| g.duplicate)
        .ok_or("duplicate")?;
    assert_eq!(group.identity, "pkg:npm/shared");
    let alias = plan
        .occurrences
        .iter()
        .find(|n| n.native_context == "node_modules/alias")
        .ok_or("alias")?;
    assert_eq!(alias.node.purl, "pkg:npm/shared@1.2.3");
    assert_eq!(alias.roots.len(), 1);
    let nested = plan
        .occurrences
        .iter()
        .find(|n| n.node.purl == "pkg:npm/shared@2.0.0")
        .ok_or("nested")?;
    assert_eq!(nested.parents[0].evidence["constraint"], "^2.0.0");
    assert!(!nested.transitive_constraints_complete);
    assert!(plan
        .alignment
        .pins
        .iter()
        .any(|p| p.requirement.name == "alias" && p.requirement.constraint == "npm:shared@1.2.3"));
    Ok(())
}

// PURL qualifiers must keep source reviews separate even with equal opaque sources.
#[test]
fn source_qualified_purls_do_not_become_lock_convergence_candidates() -> TestResult {
    let mut a = package("1.2.3", "node_modules/shared");
    a.purl = Some("pkg:npm/shared@1.2.3?repository_url=https://a.invalid#lib".into());
    let mut b = package("2.0.0", "node_modules/parent/node_modules/shared");
    b.purl = Some("pkg:npm/shared@2.0.0?repository_url=https://b.invalid#lib".into());
    let plan = graph::plan_alignment(&snapshot(vec![project("", vec![a, b])])?)?;
    assert_eq!(plan.actions.len(), 1);
    assert_eq!(
        plan.actions[0].kind,
        graph::AlignmentPlanActionKind::ReviewSourceVariants
    );
    assert_eq!(plan.occurrences.len(), 2);
    assert!(plan
        .alignment
        .groups
        .iter()
        .all(|g| g.identity.ends_with("#lib") && !g.duplicate));
    Ok(())
}

// The new entry point must enforce existing graph bounds before producing output.
#[test]
fn excessive_contexts_and_invalid_version_evidence_are_refused() -> TestResult {
    let mut graph = duplicate_graph()?;
    let context = graph.contexts.values().next().ok_or("context")?.clone();
    for index in 0..=graph::MAX_CONTEXTS {
        graph
            .contexts
            .insert(format!("extra/{index}"), context.clone());
    }
    assert!(graph::plan_alignment(&graph)
        .err()
        .ok_or("accepted excessive contexts")?
        .to_string()
        .contains("Graph limits"));
    let mut graph = duplicate_graph()?;
    graph.components[0].component.version = "9.0.0".into();
    assert!(graph::plan_alignment(&graph).is_err());
    Ok(())
}

// Canonical package identity can span native spellings; display names are not keys.
#[test]
fn python_source_review_keeps_every_supplier_despite_native_name_variants() -> TestResult {
    let mut old = package("1.2.3", "registry-a");
    old.name = "Shared".into();
    old.purl = Some("pkg:pypi/shared@1.2.3".into());
    old.source = json!({"registry":"https://a.invalid/simple"});
    old.metadata = json!({"resolution-markers":["python_version < '3.10'"]});
    let mut newer = old.clone();
    newer.name = "shared".into();
    newer.metadata = json!({"resolution-markers":["python_version >= '3.10'"]});
    let mut other = package("2.0.0", "registry-b");
    other.purl = Some("pkg:pypi/shared@2.0.0".into());
    other.source = json!({"registry":"https://b.invalid/simple"});
    let mut python = project("", vec![old, newer, other]);
    python.ecosystem = "python".into();
    python.manager = "uv".into();
    python.manifest = "pyproject.toml".into();
    python.lockfile = Some("uv.lock".into());
    let mut graph = snapshot(vec![python])?;
    let plan = graph::plan_alignment(&graph)?;
    assert_eq!(plan.alignment.groups.len(), 2);
    assert_eq!(plan.alignment.groups[0].name, "Shared");
    assert_eq!(plan.alignment.source_variants[0].name, "shared");
    assert_eq!(plan.actions.len(), 1);
    assert_eq!(
        plan.actions[0].kind,
        graph::AlignmentPlanActionKind::ReviewSourceVariants
    );
    assert_eq!(plan.actions[0].group_indices, [0, 1]);
    assert_eq!(plan.occurrences.len(), 3);
    assert_eq!(
        plan.occurrences
            .iter()
            .filter(|o| o.source == json!({"registry":"https://a.invalid/simple"}))
            .count(),
        2
    );
    assert_eq!(
        plan.occurrences
            .iter()
            .filter(|o| o.source == json!({"registry":"https://b.invalid/simple"}))
            .count(),
        1
    );
    graph.components.clear();
    let partial = graph::plan_alignment(&graph)?;
    assert!(!partial.analysis_complete);
    let review = partial
        .actions
        .iter()
        .find(|action| action.kind == graph::AlignmentPlanActionKind::ReviewSourceVariants)
        .ok_or("source review")?;
    assert_eq!(review.group_indices, [0, 1]);
    Ok(())
}
