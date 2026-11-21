use ladybom::deps::{Component, Project, Report};
use ladybom_graph as graph;
use serde_json::{json, Value};
use std::collections::BTreeMap;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn package(name: &str, version: &str, context: &str) -> Component {
    Component {
        name: name.into(),
        version: version.into(),
        purl: Some(format!("pkg:npm/{}@{version}", name.replace('@', "%40"))),
        context: context.into(),
        source: Value::Null,
        artifacts: Vec::new(),
        metadata: json!({}),
    }
}

fn project(manifest: &str, lockfile: &str, components: Vec<Component>) -> Project {
    Project {
        manifest_package: None,
        ecosystem: "npm".into(),
        root: ".".into(),
        manifest: manifest.into(),
        lockfile: Some(lockfile.into()),
        locked: true,
        manager: "npm".into(),
        tools: Vec::new(),
        requirements: Vec::new(),
        components,
        components_from: None,
        workspace: Value::Null,
    }
}

fn report(projects: Vec<Project>) -> Report {
    Report {
        schema_version: 2,
        complete: true,
        inputs: BTreeMap::new(),
        projects,
        diagnostics: Vec::new(),
    }
}

fn npm(components: Vec<Component>) -> Result<graph::Graph, Box<dyn std::error::Error>> {
    Ok(graph::project(report(vec![project(
        "package.json",
        "package-lock.json",
        components,
    )]))?)
}

// Comparing per installation context misses the conflict between these two versions.
#[test]
fn npm_nested_versions_share_one_resolution_domain() -> TestResult {
    let graph = npm(vec![
        package("shared", "1.2.3", "node_modules/shared"),
        package("shared", "2.0.0", "node_modules/parent/node_modules/shared"),
    ])?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, Some(false));
    assert_eq!(result.domains.len(), 1);
    assert_eq!(result.domains[0].graphs.len(), 2);
    assert_eq!(result.groups.len(), 1);
    assert_eq!(result.groups[0].identity, "pkg:npm/shared");
    assert!(result.groups[0].duplicate);
    assert_eq!(result.groups[0].versions.len(), 2);
    assert!(result.coverage.versions_complete);
    assert_eq!(result.coverage.projected_components, 2);
    Ok(())
}

// Repeated installations of one version must remain occurrences, not a conflict.
#[test]
fn npm_same_version_and_scoped_aliases_preserve_all_occurrences() -> TestResult {
    let graph = npm(vec![
        package("@scope/shared", "1.2.3", "node_modules/alias"),
        package(
            "@scope/shared",
            "1.2.3",
            "node_modules/parent/node_modules/@scope/shared",
        ),
    ])?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.groups.len(), 1);
    assert_eq!(result.groups[0].identity, "pkg:npm/%40scope/shared");
    assert!(!result.groups[0].duplicate);
    assert_eq!(result.groups[0].versions[0].nodes.len(), 2);
    Ok(())
}

// Independent lockfiles can disagree without creating an intra-lock conflict.
#[test]
fn independent_locks_have_separate_cross_domain_differences() -> TestResult {
    let graph = graph::project(report(vec![
        project(
            "a/package.json",
            "a/package-lock.json",
            vec![package("shared", "1.2.3", "node_modules/shared")],
        ),
        project(
            "b/package.json",
            "b/package-lock.json",
            vec![package("shared", "2.0.0", "node_modules/shared")],
        ),
    ]))?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.domains.len(), 2);
    assert!(result.groups.iter().all(|group| !group.duplicate));
    assert_eq!(result.cross_domain.len(), 1);
    assert_eq!(result.cross_domain[0].domains.len(), 2);
    Ok(())
}

// Shared-lock member manifests must not multiply inventory or version groups.
#[test]
fn shared_lock_is_counted_once_and_keeps_manifest_evidence() -> TestResult {
    let first = project(
        "packages/a/package.json",
        "package-lock.json",
        vec![package("shared", "1.2.3", "node_modules/shared")],
    );
    let mut second = project("packages/b/package.json", "package-lock.json", Vec::new());
    second.components_from = Some(first.manifest.clone());
    let graph = graph::project(report(vec![first, second]))?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.domains.len(), 1);
    assert_eq!(
        result.domains[0].manifests,
        ["packages/a/package.json", "packages/b/package.json"]
    );
    assert_eq!(result.coverage.inventory_components, 1);
    assert_eq!(result.coverage.projected_components, 1);
    Ok(())
}

// A successful parser flag alone is not proof of an observed locked inventory.
#[test]
fn empty_unlocked_and_partial_reports_cannot_claim_alignment() -> TestResult {
    let empty = graph::project(report(Vec::new()))?;
    let result = graph::alignment(&empty)?;
    assert_eq!(result.aligned, None);
    assert!(!result.coverage.inventory_complete);
    let mut unlocked = project("package.json", "package-lock.json", Vec::new());
    unlocked.lockfile = None;
    unlocked.locked = false;
    let result = graph::alignment(&graph::project(report(vec![unlocked]))?)?;
    assert_eq!(result.aligned, None);
    assert!(!result.coverage.versions_complete);
    let mut partial = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    partial.inventory.complete = false;
    let result = graph::alignment(&partial)?;
    assert_eq!(result.aligned, None);
    assert!(!result.coverage.inventory_complete);
    Ok(())
}

// One populated lock cannot supply the missing evidence of another empty lock.
#[test]
fn empty_independent_lock_keeps_mixed_inventory_incomplete() -> TestResult {
    let graph = graph::project(report(vec![
        project(
            "a/package.json",
            "a/package-lock.json",
            vec![package("shared", "1.2.3", "node_modules/shared")],
        ),
        project("b/package.json", "b/package-lock.json", Vec::new()),
    ]))?;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, None);
    assert!(!result.coverage.inventory_complete);
    assert!(!result.coverage.versions_complete);
    assert_eq!(result.domains.len(), 2);
    assert_eq!(result.groups.len(), 1);
    Ok(())
}

// Dropped projection nodes and unknown package identities must be counted explicitly.
#[test]
fn missing_and_unidentified_components_prevent_success() -> TestResult {
    let mut graph = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    graph.components.clear();
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, None);
    assert_eq!(result.coverage.unprojected_components, 1);
    assert!(!result.coverage.versions_complete);
    assert_eq!(result.groups.len(), 1);
    assert!(result.groups[0].versions[0].nodes.is_empty());
    let mut unidentified = package("unknown", "1.0.0", "node_modules/unknown");
    unidentified.purl = None;
    let result = graph::alignment(&npm(vec![unidentified])?)?;
    assert_eq!(result.aligned, None);
    assert_eq!(result.coverage.unidentified_components, 1);
    Ok(())
}

// Removing qualifiers/subpaths along with the version would merge distinct identities.
#[test]
fn purl_qualifiers_and_subpaths_remain_independent_identities() -> TestResult {
    let mut a = package("shared", "1.2.3", "node_modules/shared");
    a.purl = Some("pkg:npm/shared@1.2.3?repository_url=https://a.invalid#lib".into());
    let mut b = package("shared", "2.0.0", "node_modules/parent/node_modules/shared");
    b.purl = Some("pkg:npm/shared@2.0.0?repository_url=https://b.invalid#lib".into());
    let result = graph::alignment(&npm(vec![a, b])?)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.groups.len(), 2);
    assert!(result
        .groups
        .iter()
        .all(|group| group.identity.ends_with("#lib")));
    assert_eq!(result.source_variants.len(), 1);
    assert_eq!(result.source_variants[0].identities.len(), 2);
    Ok(())
}

// Local Cargo PURLs exist only in the projected clone and must still cover inventory.
#[test]
fn local_and_registry_cargo_sources_remain_distinct() -> TestResult {
    let mut local = package("shared", "1.2.3", "workspace");
    local.purl = None;
    local.metadata = json!({"name":"shared", "version":"1.2.3"});
    let mut registry = package("shared", "2.0.0", "registry");
    registry.purl = Some("pkg:cargo/shared@2.0.0".into());
    registry.source = json!("registry+https://github.com/rust-lang/crates.io-index");
    registry.metadata = json!({"name":"shared", "version":"2.0.0", "source":registry.source});
    let mut cargo = project("Cargo.toml", "Cargo.lock", vec![local, registry]);
    cargo.ecosystem = "rust".into();
    let result = graph::alignment(&graph::project(report(vec![cargo]))?)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.coverage.unidentified_components, 0);
    assert_eq!(result.groups.len(), 2);
    assert_eq!(result.source_variants.len(), 1);
    assert!(result
        .groups
        .iter()
        .any(|group| group.identity == "pkg:generic/cargo-local/shared"));
    Ok(())
}

// Known conflicts remain actionable evidence even when some inventory is missing.
#[test]
fn partial_inventory_retains_known_conflicts() -> TestResult {
    let mut graph = npm(vec![
        package("shared", "1.2.3", "node_modules/shared"),
        package("shared", "2.0.0", "node_modules/p/node_modules/shared"),
    ])?;
    graph.inventory.complete = false;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, Some(false));
    assert!(!result.coverage.versions_complete);
    Ok(())
}

// Version/component inconsistencies must be rejected instead of grouping forged evidence.
#[test]
fn divergent_purl_version_is_rejected() -> TestResult {
    let mut graph = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    graph.components[0].component.version = "9.0.0".into();
    assert!(graph::alignment(&graph).is_err());
    Ok(())
}

// Unresolved build activation is independent from complete locked version evidence.
#[test]
fn conditional_activation_does_not_hide_complete_versions() -> TestResult {
    let mut component = package("shared", "1.2.3", "node_modules/shared");
    component.metadata = json!({"optional":true});
    let result = graph::alignment(&npm(vec![component])?)?;
    assert_eq!(result.aligned, Some(true));
    assert!(result.coverage.versions_complete);
    assert!(!result.coverage.activation_known);
    Ok(())
}

#[test]
fn serialization_is_stable_when_graph_occurrences_are_reordered() -> TestResult {
    let mut graph = npm(vec![
        package("shared", "2.0.0", "node_modules/shared"),
        package("shared", "1.2.3", "node_modules/p/node_modules/shared"),
    ])?;
    let before = serde_json::to_value(graph::alignment(&graph)?)?;
    graph.components.reverse();
    let after = serde_json::to_value(graph::alignment(&graph)?)?;
    assert_eq!(before, after);
    Ok(())
}

// A PURL shared by separate registries is not evidence of one source's version conflict.
#[test]
fn distinct_python_registries_do_not_merge_versions() -> TestResult {
    let mut a = package("shared", "1.2.3", "registry-a");
    a.purl = Some("pkg:pypi/shared@1.2.3".into());
    a.source = json!({"registry":"https://a.invalid/simple"});
    let mut b = package("shared", "2.0.0", "registry-b");
    b.purl = Some("pkg:pypi/shared@2.0.0".into());
    b.source = json!({"registry":"https://b.invalid/simple"});
    let mut python = project("pyproject.toml", "uv.lock", vec![a, b]);
    python.ecosystem = "python".into();
    let result = graph::alignment(&graph::project(report(vec![python]))?)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.groups.len(), 2);
    assert!(result.groups.iter().all(|group| !group.duplicate));
    assert_eq!(result.source_variants.len(), 1);
    Ok(())
}

// Normal npm tarball filenames differ per version but identify the same registry source.
#[test]
fn npm_tarball_versions_group_while_providers_remain_distinct() -> TestResult {
    let mut a = package("shared", "1.2.3", "node_modules/shared");
    a.source = json!("https://registry.npmjs.org/shared/-/shared-1.2.3.tgz");
    let mut b = package("shared", "2.0.0", "node_modules/a/node_modules/shared");
    b.source = json!("https://registry.npmjs.org/shared/-/shared-2.0.0.tgz");
    let mut private = package("shared", "3.0.0", "node_modules/b/node_modules/shared");
    private.source = json!("https://private.invalid/shared/-/shared-3.0.0.tgz");
    let result = graph::alignment(&npm(vec![a, b, private])?)?;
    assert_eq!(result.aligned, Some(false));
    assert_eq!(result.groups.len(), 2);
    assert_eq!(
        result.groups.iter().filter(|group| group.duplicate).count(),
        1
    );
    assert_eq!(result.source_variants.len(), 1);
    Ok(())
}

// Unknown source evidence must survive even though it cannot produce a graph identity.
#[test]
fn unprojected_source_variants_are_not_lost() -> TestResult {
    let mut a = package("shared", "1.2.3", "registry");
    a.purl = Some("pkg:cargo/shared@1.2.3".into());
    a.source = json!("registry+https://github.com/rust-lang/crates.io-index");
    a.metadata = json!({"name":"shared", "version":"1.2.3", "source":a.source});
    let mut b = package("shared", "2.0.0", "git");
    b.purl = None;
    b.source = json!("git+https://example.invalid/repo#1234");
    b.metadata = json!({"name":"shared", "version":"2.0.0", "source":b.source});
    let mut cargo = project("Cargo.toml", "Cargo.lock", vec![a, b]);
    cargo.ecosystem = "rust".into();
    let result = graph::alignment(&graph::project(report(vec![cargo]))?)?;
    assert_eq!(result.aligned, None);
    assert_eq!(result.coverage.unidentified_components, 1);
    assert_eq!(result.source_variants.len(), 1);
    assert_eq!(result.source_variants[0].sources.len(), 2);
    assert!(result.source_variants[0]
        .sources
        .iter()
        .any(|source| source.identity.is_none()));
    Ok(())
}

// Tarball query selectors may change source identity and must not be stripped.
#[test]
fn npm_provider_query_selectors_are_not_normalized_away() -> TestResult {
    let mut a = package("shared", "1.2.3", "node_modules/shared");
    a.source = json!("https://registry.invalid/shared/-/shared-1.2.3.tgz?provider=a");
    let mut b = package("shared", "2.0.0", "node_modules/p/node_modules/shared");
    b.source = json!("https://registry.invalid/shared/-/shared-2.0.0.tgz?provider=b");
    let result = graph::alignment(&npm(vec![a, b])?)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.groups.len(), 2);
    Ok(())
}

// Conditional contexts sharing a Python lock cover one inventory, with all nodes retained.
#[test]
fn shared_python_lock_keeps_project_occurrences_without_double_counting() -> TestResult {
    let mut component = package("shared", "1.2.3", "registry");
    component.purl = Some("pkg:pypi/shared@1.2.3".into());
    component.source = json!({"registry":"https://pypi.org/simple"});
    let mut first = project("a/pyproject.toml", "uv.lock", vec![component]);
    first.ecosystem = "python".into();
    let mut second = project("b/pyproject.toml", "uv.lock", Vec::new());
    second.ecosystem = "python".into();
    second.components_from = Some(first.manifest.clone());
    let result = graph::alignment(&graph::project(report(vec![first, second]))?)?;
    assert_eq!(result.aligned, Some(true));
    assert_eq!(result.coverage.inventory_components, 1);
    assert_eq!(result.coverage.projected_components, 1);
    assert_eq!(result.groups[0].versions[0].nodes.len(), 2);
    Ok(())
}

// A detached graph node cannot supply coverage for an unrelated manifest.
#[test]
fn graph_nodes_from_unknown_domains_leave_explicit_coverage_gaps() -> TestResult {
    let mut graph = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    let context = graph::Context {
        manifest: "unselected/package.json".into(),
        native: json!({"installation_scope":"", "alias":null}),
    };
    let key = context.path()?;
    graph.contexts.clear();
    graph.contexts.insert(key.clone(), context);
    graph.components[0].key.graph = key;
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, None);
    assert_eq!(result.coverage.unmapped_nodes, 1);
    assert_eq!(result.coverage.unprojected_components, 1);
    Ok(())
}

// An opaque ecosystem projection cannot inherit npm's success merely from a valid PURL.
#[test]
fn unsupported_ecosystems_do_not_claim_complete_versions() -> TestResult {
    let mut unknown = project(
        "go.mod",
        "go.sum",
        vec![package("shared", "1.2.3", "registry")],
    );
    unknown.ecosystem = "go".into();
    let result = graph::alignment(&graph::project(report(vec![unknown]))?)?;
    assert_eq!(result.aligned, None);
    assert!(!result.coverage.versions_complete);
    Ok(())
}

// Matching a PURL alone must not cover a node whose retained source evidence changed.
#[test]
fn modified_component_evidence_is_not_accepted_as_inventory_coverage() -> TestResult {
    let mut graph = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    graph.components[0].component.metadata = json!({"different":true});
    let result = graph::alignment(&graph)?;
    assert_eq!(result.aligned, None);
    assert_eq!(result.coverage.unmapped_nodes, 1);
    assert_eq!(result.coverage.unprojected_components, 1);
    Ok(())
}

// Pin classification coverage and policy compliance have different unknown states.
#[test]
fn direct_pin_aggregate_distinguishes_ranges_exceptions_and_incomplete_audits() -> TestResult {
    let mut graph = npm(vec![package("shared", "1.2.3", "node_modules/shared")])?;
    let declaration = ladybom::deps::Requirement {
        name: "shared".into(),
        declared_name: None,
        constraint: "1.2.3".into(),
        kind: "runtime".into(),
        marker: None,
        extras: Vec::new(),
        source: Value::Null,
    };
    graph.inventory.projects[0].requirements.push(declaration);
    let result = graph::alignment(&graph)?;
    assert_eq!(result.pins_compliant, Some(true));
    assert!(result.coverage.pin_audit_complete);
    graph.inventory.complete = false;
    assert_eq!(graph::alignment(&graph)?.pins_compliant, None);
    graph.inventory.projects[0].requirements[0].constraint = "^1.2.3".into();
    assert_eq!(graph::alignment(&graph)?.pins_compliant, Some(false));
    graph.inventory.complete = true;
    graph.inventory.projects[0].requirements[0].constraint = "file:../shared".into();
    let result = graph::alignment(&graph)?;
    assert_eq!(result.pins_compliant, None);
    assert!(result.coverage.pin_audit_complete);
    graph.inventory.projects[0].requirements[0].constraint = "latest".into();
    let result = graph::alignment(&graph)?;
    assert_eq!(result.pins_compliant, None);
    assert!(!result.coverage.pin_audit_complete);
    graph.inventory.projects[0].requirements.clear();
    assert_eq!(graph::alignment(&graph)?.pins_compliant, None);
    Ok(())
}

fn direct_requirement(name: &str, constraint: &str) -> ladybom::deps::Requirement {
    ladybom::deps::Requirement {
        name: name.into(),
        declared_name: None,
        constraint: constraint.into(),
        kind: "runtime".into(),
        marker: None,
        extras: Vec::new(),
        source: Value::Null,
    }
}

#[test]
fn exact_pins_need_observed_lock_roots_even_when_versions_are_aligned() -> TestResult {
    let mut selected = project(
        "package.json",
        "package-lock.json",
        vec![package("shared", "2.0.0", "node_modules/shared")],
    );
    selected
        .requirements
        .push(direct_requirement("shared", "1.0.0"));
    let stale = graph::project(report(vec![selected.clone()]))?;
    let result = graph::alignment(&stale)?;
    assert_eq!(result.pins_compliant, Some(true));
    assert_eq!(result.aligned, Some(true));
    assert_ne!(result.pin_lock_consistent, Some(true));

    selected.requirements[0].constraint = "2.0.0".into();
    let mut matched = graph::project(report(vec![selected]))?;
    assert_eq!(graph::alignment(&matched)?.pin_lock_consistent, Some(true));
    matched.roots.clear();
    assert_ne!(graph::alignment(&matched)?.pin_lock_consistent, Some(true));
    Ok(())
}

#[test]
fn exact_pin_roots_cannot_be_reused_for_duplicate_declarations() -> TestResult {
    let mut selected = project(
        "package.json",
        "package-lock.json",
        vec![package("shared", "1.2.3", "node_modules/shared")],
    );
    selected.requirements = vec![direct_requirement("shared", "1.2.3"); 2];
    let mut graph = graph::project(report(vec![selected]))?;
    assert_eq!(graph.roots.len(), 2);
    assert_eq!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    graph.roots.pop();
    assert_ne!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    Ok(())
}

#[test]
fn exact_npm_alias_matches_installation_name_and_actual_package() -> TestResult {
    let mut selected = project(
        "package.json",
        "package-lock.json",
        vec![package("@scope/shared", "1.2.3", "node_modules/alias")],
    );
    selected
        .requirements
        .push(direct_requirement("alias", "npm:@scope/shared@1.2.3"));
    let mut graph = graph::project(report(vec![selected]))?;
    assert_eq!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    graph.inventory.projects[0].requirements[0].constraint = "npm:@other/shared@1.2.3".into();
    assert_ne!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    Ok(())
}

#[test]
fn exact_cargo_alias_requires_matching_declaration_evidence() -> TestResult {
    let mut component = package("shared", "1.2.3", "registry");
    component.purl = Some("pkg:cargo/shared@1.2.3".into());
    component.source = json!("registry+https://github.com/rust-lang/crates.io-index");
    component.metadata = json!({"name":"shared", "version":"1.2.3", "source":component.source});
    let mut selected = project("Cargo.toml", "Cargo.lock", vec![component]);
    selected.ecosystem = "rust".into();
    let mut requirement = direct_requirement("shared", "=1.2.3");
    requirement.declared_name = Some("renamed".into());
    requirement.source = json!({"package":"shared", "version":"=1.2.3"});
    selected.requirements.push(requirement);
    let mut graph = graph::project(report(vec![selected]))?;
    assert_eq!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    graph.roots[0].condition["declared_name"] = json!("different-alias");
    assert_ne!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    Ok(())
}

#[test]
fn exact_python_pin_uses_normalized_package_and_pep440_equality() -> TestResult {
    let mut component = package("shared-lib", "1.2.0", "registry");
    component.purl = Some("pkg:pypi/shared-lib@1.2.0".into());
    component.source = json!({"registry":"https://pypi.org/simple"});
    let mut selected = project("pyproject.toml", "uv.lock", vec![component]);
    selected.ecosystem = "python".into();
    selected
        .requirements
        .push(direct_requirement("shared-lib", "==1.2"));
    let mut graph = graph::project(report(vec![selected]))?;
    assert_eq!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    graph.inventory.projects[0].requirements[0].name = "Shared_Lib".into();
    assert_eq!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
    Ok(())
}

#[test]
fn exact_pin_cannot_borrow_a_root_from_an_independent_lock() -> TestResult {
    let mut a = project(
        "a/package.json",
        "a/package-lock.json",
        vec![package("shared", "2.0.0", "node_modules/shared")],
    );
    let mut b = project(
        "b/package.json",
        "b/package-lock.json",
        vec![package("shared", "1.0.0", "node_modules/shared")],
    );
    a.requirements.push(direct_requirement("shared", "1.0.0"));
    b.requirements.push(direct_requirement("shared", "1.0.0"));
    let mut graph = graph::project(report(vec![a, b]))?;
    let mut forged = graph.roots[0].clone();
    forged.manifest = "a/package.json".into();
    graph.roots.push(forged);
    graph.validate()?;
    assert!(!graph::analyze_alignment(&graph)?.policy_pass());
    Ok(())
}

#[test]
fn exact_pins_follow_native_build_and_local_version_matching() -> TestResult {
    for (ecosystem, package_type, manifest, lockfile, constraint, source) in [
        (
            "rust",
            "cargo",
            "Cargo.toml",
            "Cargo.lock",
            "=1.2.3",
            json!("registry+https://github.com/rust-lang/crates.io-index"),
        ),
        (
            "python",
            "pypi",
            "pyproject.toml",
            "uv.lock",
            "==1.2.3",
            json!({"registry":"https://pypi.org/simple"}),
        ),
    ] {
        let mut component = package("shared", "1.2.3+local", "registry");
        let mut purl = packageurl::PackageUrl::new(package_type, "shared")?;
        purl.with_version(&component.version)?;
        component.purl = Some(purl.to_string());
        component.source = source;
        component.metadata =
            json!({"name":"shared","version":component.version,"source":component.source});
        let mut selected = project(manifest, lockfile, vec![component]);
        selected.ecosystem = ecosystem.into();
        selected
            .requirements
            .push(direct_requirement("shared", constraint));
        let mut graph = graph::project(report(vec![selected]))?;
        assert_eq!(graph.roots.len(), 1, "{ecosystem}");
        assert_eq!(
            graph::alignment(&graph)?.pin_lock_consistent,
            Some(true),
            "{ecosystem}"
        );
        if ecosystem == "python" {
            graph.inventory.projects[0].requirements[0].constraint = "==1.2.3+other".into();
            assert_ne!(graph::alignment(&graph)?.pin_lock_consistent, Some(true));
        }
    }
    Ok(())
}
