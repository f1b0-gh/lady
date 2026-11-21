use ladybom::deps::{self, graph};
use serde_json::json;
use std::fs;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const COMMIT: &str = "0123456789012345678901234567890123456789";
const OTHER: &str = "abcdef0123456789012345678901234567890123";
const REPO: &str = "https://example.invalid/repo";

fn scan(dependency: &str, packages: &str) -> Result<deps::Report> {
    let dir = tempfile::tempdir()?;
    fs::write(
        dir.path().join("Cargo.toml"),
        format!("[package]\nname='app'\nversion='1.0.0'\n[dependencies]\n{dependency}\n"),
    )?;
    fs::write(
        dir.path().join("Cargo.lock"),
        format!("version=4\n{packages}"),
    )?;
    Ok(deps::scan_project(dir.path())?)
}

fn package(source: &str) -> String {
    format!("[[package]]\nname='actual'\nversion='1.2.3'\nsource='{source}'\n")
}

#[test]
fn locked_git_identity_keeps_version_repository_and_commit() -> Result {
    let source = format!("git+{REPO}?branch=stable#{COMMIT}");
    let report = scan(
        &format!("alias={{package='actual',git='{REPO}',branch='stable',version='1'}}"),
        &package(&source),
    )?;
    let c = &report.projects[0].components[0];
    let purl = c
        .purl
        .as_deref()
        .ok_or("Git PURL missing")?
        .parse::<packageurl::PackageUrl>()?;
    assert_eq!(purl.ty(), "cargo");
    assert_eq!(purl.version(), Some("1.2.3"));
    assert_eq!(
        purl.qualifiers().get("vcs_url").map(|s| s.as_ref()),
        Some(format!("git+{REPO}@{COMMIT}").as_str())
    );
    assert_eq!(c.source, source);
    assert_eq!(c.metadata["source"], source);
    assert!(c.artifacts.is_empty());
    let graph = graph::project(report)?;
    assert_eq!(graph.components.len(), 1);
    assert_eq!(graph.roots.len(), 1);
    assert_eq!(graph.roots[0].condition["declared_name"], "alias");
    Ok(())
}

#[test]
fn registry_and_two_git_commits_are_distinct_and_ambiguous_roots_stay_unresolved() -> Result {
    let packages = package(&format!("git+{REPO}#{COMMIT}"))
        + &package(&format!("git+{REPO}#{OTHER}"))
        + &package("registry+https://github.com/rust-lang/crates.io-index");
    let graph = graph::project(scan(&format!("actual={{git='{REPO}'}}"), &packages)?)?;
    assert_eq!(graph.components.len(), 3);
    let identities: std::collections::BTreeSet<_> =
        graph.components.iter().map(|c| &c.key.purl).collect();
    assert_eq!(identities.len(), 3);
    assert!(graph.roots.is_empty());
    assert!(graph
        .limitations
        .iter()
        .any(|l| l.contains("root requirement not resolved unambiguously")));
    Ok(())
}

#[test]
fn native_git_edges_resolve_cargo_source_normalization() -> Result {
    for selector in ["", "?branch=stable", "?tag=v1", "?rev=0123456"] {
        let source = format!("git+{REPO}{selector}#{COMMIT}");
        let packages = format!(
            "[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['actual']\n{}",
            package(&source)
        );
        let graph = graph::project(scan("", &packages)?)?;
        assert_eq!(
            graph.dependencies.len(),
            1,
            "{selector}: {:?}",
            graph.limitations
        );
        assert!(graph.dependencies[0].to.purl.contains("vcs_url="));
        assert_eq!(graph.dependencies[0].kind, "unknown");
    }
    Ok(())
}

#[test]
fn qualified_native_edges_preserve_selectors_and_resolved_revisions() -> Result {
    for (actual, requested, edges) in [
        ("?rev=0123456", format!("?rev={COMMIT}"), 1),
        ("?branch=a%2Bb", "?branch=a%2Bb".into(), 1),
        ("?branch=master", "?branch=master".into(), 1),
        ("?branch=master", "".into(), 0),
        ("", "?branch=master".into(), 0),
        ("?branch=stable", "?branch=other".into(), 0),
        ("?rev=0123456", format!("?rev={OTHER}"), 0),
        ("?branch=stable", format!("?branch=stable#{OTHER}"), 0),
    ] {
        let packages = format!("[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['actual 1.2.3 (git+{REPO}{requested})']\n{}", package(&format!("git+{REPO}{actual}#{COMMIT}")));
        let graph = graph::project(scan("", &packages)?)?;
        assert_eq!(graph.dependencies.len(), edges, "{actual} / {requested}");
    }
    Ok(())
}

#[test]
fn inherited_git_roots_match_selectors_and_never_fall_back_to_registry() -> Result {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("member"))?;
    fs::write(dir.path().join("Cargo.toml"), format!("[workspace]\nmembers=['member']\n[workspace.dependencies]\nalias={{package='actual',git='{REPO}',rev='0123456'}}\n"))?;
    fs::write(
        dir.path().join("member/Cargo.toml"),
        "[package]\nname='member'\nversion='1.0.0'\n[dependencies]\nalias={workspace=true}\n",
    )?;
    fs::write(
        dir.path().join("Cargo.lock"),
        format!(
            "version=4\n{}",
            package(&format!("git+{REPO}?rev=0123456#{COMMIT}"))
        ),
    )?;
    let report = deps::scan_project(dir.path())?;
    assert_eq!(graph::project(report)?.roots.len(), 1);
    for selector in [
        "branch='other'",
        "tag='stable'",
        "rev='fffffff'",
        "branch='stable',tag='v1'",
        "path='../actual'",
        "registry='private'",
    ] {
        let report = scan(
            &format!("actual={{git='{REPO}',{selector}}}"),
            &package(&format!("git+{REPO}?branch=stable#{COMMIT}")),
        )?;
        assert!(graph::project(report)?.roots.is_empty(), "{selector}");
    }
    Ok(())
}

#[test]
fn unresolved_or_unsupported_git_locations_remain_unidentified() -> Result {
    for source in [
        format!("git+{REPO}"),
        format!("git+{REPO}#0123456"),
        format!("git+{REPO}#{}", "z".repeat(40)),
        format!("git+ssh://git@example.invalid/repo#{COMMIT}"),
        format!("git+file:///tmp/repo#{COMMIT}"),
    ] {
        let report = scan(&format!("actual={{git='{REPO}'}}"), &package(&source))?;
        assert!(report.projects[0].components[0].purl.is_none(), "{source}");
        let graph = graph::project(report)?;
        assert!(graph.components.is_empty());
    }
    Ok(())
}

#[test]
fn forged_git_purl_cannot_disagree_with_locked_source() -> Result {
    let original = scan("", &package(&format!("git+{REPO}#{COMMIT}")))?;
    for field in ["purl", "metadata", "source", "registry_pair"] {
        let mut report = original.clone();
        let c = &mut report.projects[0].components[0];
        if field == "purl" {
            c.purl = Some("pkg:cargo/actual@1.2.3".into());
        } else if field == "metadata" {
            c.metadata["source"] = json!(format!("git+{REPO}#{OTHER}"));
        } else {
            c.source = json!("registry+https://github.com/rust-lang/crates.io-index");
            if field == "registry_pair" {
                c.purl = Some("pkg:cargo/actual@1.2.3".into());
            }
        }
        assert!(graph::project(report).is_err(), "{field}");
    }
    Ok(())
}

#[test]
fn ambiguous_native_dependencies_cannot_select_the_first_git_provider() -> Result {
    for dependency in ["actual", "actual 1.2.3"] {
        let packages = format!(
            "[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['{dependency}']\n{}{}",
            package(&format!("git+{REPO}#{COMMIT}")),
            package(&format!("git+https://fork.invalid/repo#{OTHER}"))
        );
        let report = scan("", &packages)?;
        assert!(!report.complete, "{dependency}");
    }
    Ok(())
}

#[test]
fn native_dependency_selectors_cannot_be_silently_discarded() -> Result {
    for query in ["provider=private", "branch=other&branch=stable"] {
        let packages = format!("[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['actual 1.2.3 (git+{REPO}?{query})']\n{}", package(&format!("git+{REPO}?branch=stable#{COMMIT}")));
        assert!(!scan("", &packages)?.complete, "{query}");
    }
    Ok(())
}

#[test]
fn encoded_selectors_survive_inventory_roots_and_native_edges() -> Result {
    for (branch, encoded) in [
        ("a+b", "a%2Bb"),
        ("a&b", "a%26b"),
        ("a#b", "a%23b"),
        ("master", "master"),
    ] {
        let source = format!("git+{REPO}?branch={encoded}#{COMMIT}");
        let packages = format!(
            "[[package]]\nname='app'\nversion='1.0.0'\ndependencies=['actual']\n{}",
            package(&source)
        );
        let report = scan(
            &format!("actual={{git='{REPO}',branch='{branch}'}}"),
            &packages,
        )?;
        let c = report.projects[0]
            .components
            .iter()
            .find(|c| c.name == "actual")
            .ok_or("package")?;
        assert_eq!(c.source, source);
        let graph = graph::project(report)?;
        assert_eq!(graph.roots.len(), 1, "{branch}: {:?}", graph.limitations);
        assert_eq!(graph.dependencies.len(), 1, "{branch}");
    }
    Ok(())
}

#[test]
fn default_branch_does_not_match_explicit_master_selection() -> Result {
    for (requirement, selector) in [("", "?branch=master"), (",branch='master'", "")] {
        let graph = graph::project(scan(
            &format!("actual={{git='{REPO}'{requirement}}}"),
            &package(&format!("git+{REPO}{selector}#{COMMIT}")),
        )?)?;
        assert!(graph.roots.is_empty());
    }
    Ok(())
}

#[test]
fn snapshot_validation_rechecks_git_provenance_after_public_graph_mutation() -> Result {
    let original = graph::project(scan("", &package(&format!("git+{REPO}#{COMMIT}")))?)?;
    for inventory in [true, false] {
        let mut graph = original.clone();
        let component = if inventory {
            &mut graph.inventory.projects[0].components[0]
        } else {
            &mut graph.components[0].component
        };
        component.metadata["source"] = json!(format!("git+{REPO}#{OTHER}"));
        assert!(graph.validate().is_err(), "inventory={inventory}");
    }
    Ok(())
}

#[test]
fn identified_git_package_is_not_automatically_assessed_as_a_registry_release() -> Result {
    let report = scan("", &package(&format!("git+{REPO}#{COMMIT}")))?;
    assert!(report.projects[0].components[0].purl.is_some());
    let snapshot = ladybom::vuln::Snapshot {
        schema_version: 1,
        source: "https://example.invalid/synthetic-advisories".into(),
        fetched_at: "2026-11-05T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["crates.io".into()],
        advisories: vec![json!({
            "id":"RUSTSEC-2026-TEST", "modified":"2026-11-04T00:00:00Z",
            "affected":[{"package":{"ecosystem":"crates.io","name":"actual"},
                "versions":["1.2.3"]}]
        })],
    };
    let assessment = ladybom::vuln::assess(&report, &snapshot, "2026-11-05T12:00:00Z", 86400)?;
    assert!(!assessment.complete);
    assert!(!assessment.coverage.identities_complete);
    assert_eq!(assessment.coverage.assessed_components, 0);
    assert!(assessment.findings.is_empty());
    assert!(!assessment.coverage.limitations.is_empty());
    Ok(())
}

#[test]
fn lossy_git_selectors_are_rejected_before_native_parser_normalization() -> Result {
    for query in [
        "provider=private",
        "branch=a&branch=b",
        "tag=v1&rev=0123456",
        "branch=",
    ] {
        let report = scan("", &package(&format!("git+{REPO}?{query}#{COMMIT}")))?;
        assert!(!report.complete, "{query}");
        assert!(!report.diagnostics.is_empty());
        assert!(report.projects.iter().all(|p| p.components.is_empty()));
    }
    Ok(())
}
