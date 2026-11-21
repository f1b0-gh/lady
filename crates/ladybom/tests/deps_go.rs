use ladybom::{cyclonedx, deps, sources};
use serde_json::Value;
use std::{fs, path::Path};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn write(root: &Path, path: &str, text: &str) -> std::io::Result<()> {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap_or(root))?;
    fs::write(path, text)
}
const SUM: &str = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
#[test]
fn declarations_are_requirements_not_resolved_components() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.mod", "module example.org/app\ngo 1.24.0\ntoolchain go1.24.2\nrequire (\n example.org/direct v1.2.3\n example.org/indirect/v2 v2.0.1 // indirect\n)\nexclude example.org/direct v1.2.2\nretract [v1.0.0, v1.0.1]\ntool example.org/direct/cmd/tool\n")?;
    write(
        root.path(),
        "go.sum",
        &format!("example.org/direct v1.2.3 {SUM}\nexample.org/unused v3.2.1/go.mod {SUM}\n"),
    )?;
    let report = deps::scan_project(root.path())?;
    report.validate()?;
    assert_eq!(report.projects.len(), 1);
    let p = &report.projects[0];
    assert_eq!(p.ecosystem, "go");
    assert_eq!(
        p.manifest_package.as_ref().ok_or("module")?.name,
        "example.org/app"
    );
    assert!(!p.locked);
    assert!(p.lockfile.is_none());
    assert!(p.components.is_empty());
    assert_eq!(p.requirements.len(), 2);
    assert_eq!(p.requirements[0].constraint, "v1.2.3");
    assert_eq!(p.requirements[1].source["indirect"], true);
    assert_eq!(p.tools.len(), 2);
    assert_eq!(
        p.workspace["go"]["checksums"]
            .as_array()
            .ok_or("checksums")?
            .len(),
        2
    );
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_resolution_unknown"));
    Ok(())
}
#[test]
fn workspace_members_and_local_replacements_use_only_selected_manifests() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.work",
        "go 1.24.0\nuse (\n .\n ./staging/client\n)\nreplace example.org/lib v0.0.0 => ./staging/client\n",
    )?;
    write(root.path(), "go.mod", "module example.org/app\ngo 1.24.0\nrequire example.org/lib v0.0.0\nreplace example.org/lib => ../outside\n")?;
    write(
        root.path(),
        "staging/client/go.mod",
        "module example.org/lib\ngo 1.24.0\n",
    )?;
    let report = deps::scan_project(root.path())?;
    let p = report
        .projects
        .iter()
        .find(|p| p.manifest == "go.mod")
        .ok_or("main module")?;
    assert_eq!(p.workspace["go"]["workspace"], "go.work");
    assert_eq!(
        p.requirements[0].source["replacement"]["manifest"],
        "staging/client/go.mod"
    );
    assert!(!report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_local_source_unavailable"));
    let selection = sources::Sources {
        include: vec!["go.mod".into(), "go.work".into()],
        exclude: vec![],
    };
    let partial = deps::scan_snapshot(
        root.path(),
        &sources::snapshot(root.path(), &selection, None)?,
    )?;
    assert!(!partial.complete);
    assert!(partial
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_member_unavailable"));
    assert!(!partial.inputs.contains_key("staging/client/go.mod"));
    Ok(())
}
#[test]
fn vendor_observations_have_purls_but_never_lock_or_complete_the_graph() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.mod",
        "module example.org/app\ngo 1.24.0\nrequire example.org/lib v1.2.3\n",
    )?;
    write(
        root.path(),
        "vendor/modules.txt",
        "# example.org/lib v1.2.3\n## explicit; go 1.20\nexample.org/lib/sub\n",
    )?;
    let report = deps::scan_project(root.path())?;
    let p = &report.projects[0];
    assert!(!p.locked);
    assert_eq!(p.components.len(), 1);
    assert_eq!(
        p.components[0].purl.as_deref(),
        Some("pkg:golang/example.org/lib@v1.2.3")
    );
    assert!(report.inputs.contains_key("vendor/modules.txt"));
    let mut bytes = Vec::new();
    cyclonedx::write_json(&report, &mut bytes)?;
    let bom: Value = serde_json::from_slice(&bytes)?;
    assert!(bom["components"]
        .as_array()
        .ok_or("components")?
        .iter()
        .any(|c| c["purl"] == "pkg:golang/example.org/lib@v1.2.3"));
    Ok(())
}
#[test]
fn stale_vendor_and_checksum_only_inputs_remain_incomplete() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.mod",
        "module example.org/app\ngo 1.24.0\nrequire example.org/lib v1.2.3\n",
    )?;
    write(
        root.path(),
        "vendor/modules.txt",
        "# example.org/lib v1.2.2\n## explicit\nexample.org/lib\n",
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_vendor_inconsistent" && d.blocking));
    let orphan = tempfile::tempdir()?;
    write(
        orphan.path(),
        "go.sum",
        &format!("example.org/lib v1.2.3 {SUM}\n"),
    )?;
    let report = deps::scan_project(orphan.path())?;
    assert!(report.projects.is_empty());
    assert!(!report.complete);
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_orphan_input"));
    Ok(())
}
#[test]
fn malformed_go_inputs_are_blocked_without_panics() -> TestResult {
    for text in [
        "module a\nrequire (\nx v1.0.0\n",
        "module a\nmodule b\n",
        "module a\nrequire x latest\n",
        "module a\nunknown value\n",
        "module a\nrequire x v1.0.0\nrequire x v1.0.1\n",
        "module a\nreplace x => /tmp/outside\nrequire x v1.0.0\n",
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), "go.mod", text)?;
        let report = deps::scan_project(root.path())?;
        assert!(!report.complete, "{text}");
        assert!(report.diagnostics.iter().any(|d| d.blocking));
    }
    Ok(())
}

#[test]
fn replacements_preserve_effective_vendor_identity_and_local_uncertainty() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.mod", "module example.org/app\ngo 1.24.0\nrequire (\n example.org/lib v1.2.3\n example.org/local v0.0.0\n)\nreplace example.org/lib => example.org/fork v1.4.0\nreplace example.org/local => ./local\n")?;
    write(
        root.path(),
        "local/go.mod",
        "module example.org/local\ngo 1.24.0\n",
    )?;
    write(root.path(), "vendor/modules.txt", "# example.org/lib v1.2.3 => example.org/fork v1.4.0\n## explicit; go 1.20\nexample.org/lib/sub\n# example.org/local v0.0.0 => ./local\n## explicit; go 1.24.0\nexample.org/local\n# example.org/lib => example.org/fork v1.4.0\n# example.org/local => ./local\n")?;
    let report = deps::scan_project(root.path())?;
    let p = report
        .projects
        .iter()
        .find(|p| p.manifest == "go.mod")
        .ok_or("project")?;
    assert_eq!(
        p.components[0].purl.as_deref(),
        Some("pkg:golang/example.org/fork@v1.4.0")
    );
    assert!(p.components[1].purl.is_none());
    assert!(p.components[1].version.is_empty());
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.code == "go_vendor_inconsistent"),
        "{:?}",
        report.diagnostics
    );
    Ok(())
}
#[test]
fn conflicting_workspace_replacements_and_missing_targets_are_blocked() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.work", "go 1.24.0\nuse (\n ./a\n ./b\n)\n")?;
    for (member, target) in [("a", "one"), ("b", "two")] {
        write(root.path(),&format!("{member}/go.mod"),&format!("module example.org/{member}\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib => example.org/{target} v1.0.0\n"))?;
    }
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_conflict"));
    Ok(())
}
#[test]
fn unknown_empty_blocks_bad_versions_and_utf8_checksums_are_diagnostics() -> TestResult {
    for text in [
        "module example.org/a\nunknown (\n)\n",
        "module example.org/a\ngo 1.24betaWHAT\n",
        "module example.org/a\nrequire example.org/lib/v2 v1.2.3\n",
    ] {
        let root = tempfile::tempdir()?;
        write(root.path(), "go.mod", text)?;
        let report = deps::scan_project(root.path())?;
        assert!(!report.complete, "{text}");
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.code == "invalid_manifest"));
    }
    let root = tempfile::tempdir()?;
    write(root.path(), "go.mod", "module example.org/a\n")?;
    write(
        root.path(),
        "go.sum",
        &format!("example.org/lib v1.0.0 h1:{}é=\n", "A".repeat(41)),
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "invalid_go_checksum"));
    Ok(())
}
#[test]
fn unused_checksum_versions_do_not_become_sbom_components() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.mod", "module example.org/a\n")?;
    write(
        root.path(),
        "go.sum",
        &format!("example.org/lib v1.0.0 {SUM}\nexample.org/lib v1.1.0 {SUM}\n"),
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(report.complete);
    assert!(report.projects[0].components.is_empty());
    Ok(())
}

#[test]
fn workspace_replacements_are_shared_and_work_overrides_module_specific_versions() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.work",
        "go 1.24.0\nuse (\n ./a\n ./b\n)\nreplace example.org/lib => example.org/workfork v1.5.0\n",
    )?;
    write(root.path(),"a/go.mod","module example.org/a\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib v1.0.0 => example.org/oldfork v1.1.0\n")?;
    write(
        root.path(),
        "b/go.mod",
        "module example.org/b\ngo 1.24.0\nreplace example.org/other => example.org/shared v1.0.0\n",
    )?;
    let report = deps::scan_project(root.path())?;
    let a = report
        .projects
        .iter()
        .find(|p| p.manifest == "a/go.mod")
        .ok_or("a")?;
    assert_eq!(
        a.requirements[0].source["replacement"]["target"],
        "example.org/workfork"
    );
    assert!(!report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_conflict"));
    Ok(())
}
#[test]
fn malformed_vendor_metadata_duplicate_versions_and_footer_drift_are_blocked() -> TestResult {
    for vendor in [
        "# example.org/lib v1.0.0\n## explicit; go garbage\nexample.org/lib\n",
        "# example.org/lib v1.0.0\n## explicit\nexample.org/lib\n# example.org/lib v1.1.0\nexample.org/lib/other\n",
        "# example.org/lib v1.0.0 => example.org/fork v1.1.0\n## explicit\nexample.org/lib\n# example.org/lib => example.org/other v1.1.0\n",
    ] {
        let root=tempfile::tempdir()?;
        write(root.path(),"go.mod","module example.org/app\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib => example.org/fork v1.1.0\n")?;
        write(root.path(),"vendor/modules.txt",vendor)?;
        let report=deps::scan_project(root.path())?;
        assert!(report.diagnostics.iter().any(|d|matches!(d.code.as_str(),"invalid_go_vendor"|"go_vendor_inconsistent")),"{vendor}");
    }
    Ok(())
}
#[test]
fn vendor_symlinks_and_excluded_metadata_do_not_expand_source_scope() -> TestResult {
    let root = tempfile::tempdir()?;
    let private = tempfile::tempdir()?;
    write(root.path(), "go.mod", "module example.org/app\n")?;
    write(private.path(), "metadata", "PRIVATE_SENTINEL")?;
    fs::create_dir(root.path().join("vendor"))?;
    std::os::unix::fs::symlink(
        private.path().join("metadata"),
        root.path().join("vendor/modules.txt"),
    )?;
    assert!(deps::scan_project(root.path()).is_err());
    let spec = sources::Sources {
        include: vec!["go.mod".into()],
        exclude: vec!["vendor".into()],
    };
    let report = deps::scan_snapshot(root.path(), &sources::snapshot(root.path(), &spec, None)?)?;
    assert!(report.complete);
    assert!(!serde_json::to_string(&report)?.contains("PRIVATE_SENTINEL"));
    Ok(())
}

#[test]
fn workspace_vendor_normalizes_local_paths_and_retains_multiple_explicit_minima() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.work", "go 1.24.0\nuse (\n ./a\n ./b\n)\n")?;
    write(root.path(),"a/go.mod","module example.org/a\ngo 1.24.0\nrequire (\n example.org/lib v1.0.0\n example.org/local v0.0.0\n)\nreplace example.org/local => ../local\n")?;
    write(
        root.path(),
        "b/go.mod",
        "module example.org/b\ngo 1.24.0\nrequire example.org/lib v1.2.0\n",
    )?;
    write(
        root.path(),
        "local/go.mod",
        "module example.org/local\ngo 1.24.0\n",
    )?;
    write(root.path(),"vendor/modules.txt","## workspace\n# example.org/lib v1.0.0\n## explicit; go 1.20\n# example.org/lib v1.2.0\n## explicit; go 1.20\nexample.org/lib\n# example.org/local v0.0.0 => ./local\n## explicit; go 1.24.0\nexample.org/local\n# example.org/local => ./local\n")?;
    let report = deps::scan_project(root.path())?;
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.code == "go_vendor_inconsistent"),
        "{:?}",
        report.diagnostics
    );
    let p = report
        .projects
        .iter()
        .find(|p| p.manifest == "go.work")
        .ok_or("work")?;
    assert_eq!(p.components.len(), 2);
    Ok(())
}
#[test]
fn missing_unused_replacement_marker_is_not_consistent_vendor_metadata() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(),"go.mod","module example.org/app\ngo 1.24.0\nreplace example.org/unused => example.org/fork v1.1.0\n")?;
    write(root.path(), "vendor/modules.txt", "")?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_vendor_inconsistent"));
    Ok(())
}

#[test]
fn go_generated_indirect_comments_and_legacy_gopkg_pseudoversions_are_retained() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(),"go.mod","module example.org/app\nrequire (\n gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405\n example.org/a v1.0.0 // indirect; explanation\n example.org/b v1.0.0 // indirect explanation\n)\n")?;
    let report = deps::scan_project(root.path())?;
    let p = report.projects.first().ok_or("Go project")?;
    assert_eq!(p.requirements[1].source["indirect"], true);
    assert_eq!(p.requirements[2].source["indirect"], false);
    Ok(())
}
#[test]
fn wildcard_workspace_replacement_of_a_main_module_is_a_conflict() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.work",
        "go 1.24.0\nuse ./member\nreplace example.org/member => ./member\n",
    )?;
    write(
        root.path(),
        "member/go.mod",
        "module example.org/member\ngo 1.24.0\n",
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_conflict"));
    Ok(())
}

#[test]
fn legacy_vendor_consistency_is_explicitly_unqualified_not_reported_as_stale() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.mod",
        "module example.org/app\ngo 1.13\nrequire example.org/lib v1.0.0\n",
    )?;
    write(
        root.path(),
        "vendor/modules.txt",
        "# example.org/lib v1.0.0\nexample.org/lib\n",
    )?;
    let report = deps::scan_project(root.path())?;
    assert!(!report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_vendor_inconsistent"));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_vendor_legacy_coverage" && d.blocking));
    assert!(report.projects[0].workspace["go"]["vendor_consistent"].is_null());
    Ok(())
}
#[test]
fn overlapping_cross_member_replacements_do_not_silently_select_a_fork() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.work", "go 1.24.0\nuse (\n ./a\n ./b\n)\n")?;
    write(root.path(),"a/go.mod","module example.org/a\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib => example.org/one v1.0.0\n")?;
    write(root.path(),"b/go.mod","module example.org/b\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib v1.0.0 => example.org/two v1.0.0\n")?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_conflict"));
    Ok(())
}

#[test]
fn vendor_purls_do_not_imply_go_advisory_coverage() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "go.mod",
        "module example.org/app\ngo 1.24.0\nrequire example.org/lib v1.0.0\n",
    )?;
    write(
        root.path(),
        "vendor/modules.txt",
        "# example.org/lib v1.0.0\n## explicit; go 1.20\nexample.org/lib\n",
    )?;
    let report = deps::scan_project(root.path())?;
    let snapshot = deps::vuln::Snapshot {
        schema_version: 1,
        source: "https://osv.dev/synthetic".into(),
        fetched_at: "2026-11-21T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["npm".into()],
        advisories: vec![],
    };
    let assessment = deps::vuln::assess(&report, &snapshot, "2026-11-21T01:00:00Z", 86400)?;
    assert!(!assessment.complete);
    assert!(!assessment.coverage.identities_complete);
    assert_eq!(assessment.coverage.assessed_components, 0);
    Ok(())
}

#[test]
fn each_member_specific_replacement_shadows_its_own_wildcard() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.work", "go 1.24.0\nuse (\n ./a\n ./b\n)\n")?;
    write(root.path(),"a/go.mod","module example.org/a\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib v1.0.0 => example.org/two v1.0.0\n")?;
    write(root.path(),"b/go.mod","module example.org/b\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace (\n example.org/lib => example.org/one v1.0.0\n example.org/lib v1.0.0 => example.org/two v1.0.0\n)\n")?;
    let report = deps::scan_project(root.path())?;
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.code == "go_workspace_conflict"),
        "{:?}",
        report.diagnostics
    );
    for p in report
        .projects
        .iter()
        .filter(|p| !p.requirements.is_empty())
    {
        assert_eq!(
            p.requirements[0].source["replacement"]["target"],
            "example.org/two"
        );
    }
    Ok(())
}

#[test]
fn duplicate_wildcard_origins_still_participate_in_effective_conflict_checks() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "go.work", "go 1.24.0\nuse (\n ./a\n ./b\n)\n")?;
    write(root.path(),"a/go.mod","module example.org/a\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace (\n example.org/lib => example.org/one v1.0.0\n example.org/lib v1.0.0 => example.org/two v1.0.0\n)\n")?;
    write(root.path(),"b/go.mod","module example.org/b\ngo 1.24.0\nrequire example.org/lib v1.0.0\nreplace example.org/lib => example.org/one v1.0.0\n")?;
    let report = deps::scan_project(root.path())?;
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_conflict"));
    Ok(())
}
