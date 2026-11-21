use ladybom::{deps, sources, vuln};
use std::{fs, path::Path};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NAMES: [&str; 4] = ["go.mod", "go.sum", "go.work", "go.work.sum"];
const MODULE: &str = "module example.org/demo\nrequire example.org/x v1.0.0\n";

fn write(root: &Path, name: &str, content: &[u8]) -> std::io::Result<()> {
    let path = root.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

// Removing any exact Go name from discovery would turn unsupported coverage green.
#[test]
fn standalone_go_inputs_are_fingerprinted_and_blocked_at_any_depth() -> TestResult {
    for name in NAMES {
        for prefix in ["", "nested/module/"] {
            let root = tempfile::tempdir()?;
            let path = format!("{prefix}{name}");
            write(root.path(), &path, MODULE.as_bytes())?;
            let report = deps::scan_project(root.path())?;
            assert!(!report.complete, "{path}");
            assert_eq!(report.projects.len(), usize::from(name == "go.mod"));
            assert_eq!(report.inputs.len(), 1);
            assert_eq!(
                report.inputs[&path],
                ladybom::files::hash(MODULE.as_bytes())
            );
            assert_eq!(report.diagnostics.len(), 1);
            let expected = match name {
                "go.mod" => "go_resolution_unknown",
                "go.work" => "invalid_manifest",
                _ => "invalid_go_checksum",
            };
            assert_eq!(report.diagnostics[0].code, expected);
            assert_eq!(report.diagnostics[0].file, path);
            assert!(report.diagnostics[0].blocking);
            report.validate()?;
        }
    }
    Ok(())
}

#[test]
fn go_exclusions_and_near_match_names_do_not_expand_the_scope() -> TestResult {
    let root = tempfile::tempdir()?;
    for name in [
        "go.mod.bak",
        "Go.mod",
        "go.work.sum.old",
        "go.mod.txt",
        "go.sum.md",
    ] {
        write(root.path(), &format!("project/{name}"), MODULE.as_bytes())?;
    }
    for name in NAMES {
        write(root.path(), &format!("project/excluded/{name}"), &[0xff])?;
    }
    let spec = sources::Sources {
        include: vec!["project".into()],
        exclude: vec!["project/excluded".into()],
    };
    let report = deps::scan_snapshot(root.path(), &sources::snapshot(root.path(), &spec, None)?)?;
    assert!(report.complete);
    assert!(report.inputs.is_empty());
    assert!(report.projects.is_empty());
    assert!(report.diagnostics.is_empty());
    Ok(())
}

#[test]
fn go_inputs_changed_after_snapshot_are_rejected() -> TestResult {
    for name in NAMES {
        let root = tempfile::tempdir()?;
        write(root.path(), name, MODULE.as_bytes())?;
        let spec = sources::Sources {
            include: vec![name.into()],
            exclude: vec![],
        };
        let snapshot = sources::snapshot(root.path(), &spec, None)?;
        write(root.path(), name, b"changed\n")?;
        let error = deps::scan_snapshot(root.path(), &snapshot)
            .err()
            .ok_or("changed Go input accepted")?;
        assert!(
            error.to_string().contains("Source modifiée pendant scan"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn symlinks_replacing_go_inputs_are_rejected_without_reading_targets() -> TestResult {
    let outside = tempfile::tempdir()?;
    write(outside.path(), "private", b"SECRET_SENTINEL")?;
    for name in NAMES {
        let root = tempfile::tempdir()?;
        write(root.path(), name, MODULE.as_bytes())?;
        let spec = sources::Sources {
            include: vec![name.into()],
            exclude: vec![],
        };
        let snapshot = sources::snapshot(root.path(), &spec, None)?;
        fs::remove_file(root.path().join(name))?;
        std::os::unix::fs::symlink(outside.path().join("private"), root.path().join(name))?;
        let result = deps::scan_snapshot(root.path(), &snapshot);
        assert!(result.is_err(), "{name}");
        assert!(!format!("{result:?}").contains("SECRET_SENTINEL"));
    }
    Ok(())
}

#[test]
fn invalid_and_oversized_go_inputs_keep_fingerprints_and_block() -> TestResult {
    for name in NAMES {
        for (bytes, code) in [
            (vec![0xff], "invalid_utf8"),
            (vec![b'#'; 8 * 1024 * 1024 + 1], "file_limit"),
        ] {
            let root = tempfile::tempdir()?;
            write(root.path(), name, &bytes)?;
            let report = deps::scan_project(root.path())?;
            assert!(!report.complete, "{name} {code}");
            assert!(report.inputs.contains_key(name));
            assert!(report.projects.is_empty());
            assert_eq!(report.diagnostics.len(), 1);
            assert_eq!(report.diagnostics[0].file, name);
            assert_eq!(report.diagnostics[0].code, code);
            assert!(report.diagnostics[0].blocking);
        }
    }
    Ok(())
}

#[test]
fn go_references_are_not_followed_or_inferred_as_packages() -> TestResult {
    let root = tempfile::tempdir()?;
    write(root.path(), "private/go.mod", b"SECRET_SENTINEL")?;
    write(
        root.path(),
        "go.work",
        b"go 1.26.0\nuse (\n ./private\n ../outside\n)\nreplace example.org/x => /outside\n",
    )?;
    write(root.path(), "go.mod", b"module example.org/demo\nrequire example.org/x v1.0.0\nreplace example.org/x => ./private\n")?;
    let spec = sources::Sources {
        include: vec!["go.mod".into(), "go.work".into()],
        exclude: vec![],
    };
    let report = deps::scan_snapshot(root.path(), &sources::snapshot(root.path(), &spec, None)?)?;
    assert!(!report.complete);
    assert_eq!(report.inputs.len(), 2);
    assert_eq!(report.projects.len(), 2);
    assert!(report.projects.iter().all(|p| p.ecosystem == "go"));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "go_workspace_member_unavailable"));
    assert!(!serde_json::to_string(&report)?.contains("SECRET_SENTINEL"));
    Ok(())
}

// A known npm project must not mask an unparsed Go context in advisory coverage.
#[test]
fn mixed_inventory_preserves_known_findings_but_blocks_global_coverage() -> TestResult {
    let root = tempfile::tempdir()?;
    write(
        root.path(),
        "package.json",
        br#"{"name":"fixture","version":"1.0.0","dependencies":{"dep":"1.0.0"}}"#,
    )?;
    write(root.path(), "package-lock.json", br#"{"lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"},"node_modules/dep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/dep/-/dep-1.0.0.tgz"}}}"#)?;
    let before = deps::scan_project(root.path())?;
    let advisory = vuln::Snapshot {
        schema_version: 1,
        source: "https://osv.dev/test-fixture".into(),
        fetched_at: "2026-11-07T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["npm".into()],
        advisories: vec![serde_json::json!({
            "schema_version":"1.6.0", "id":"GHSA-synthetic-go-coverage", "modified":"2026-11-06T00:00:00Z",
            "affected":[{"package":{"ecosystem":"npm","name":"dep"},"versions":["1.0.0"]}]
        })],
    };
    let assessment = vuln::assess(&before, &advisory, "2026-11-07T12:00:00Z", 86400)?;
    assert!(assessment.complete);
    assert_eq!(assessment.findings.len(), 1);
    write(root.path(), "go.mod", MODULE.as_bytes())?;
    let after = deps::scan_project(root.path())?;
    assert_eq!(
        serde_json::to_value(&before.projects)?,
        serde_json::to_value(
            after
                .projects
                .iter()
                .filter(|p| p.ecosystem != "go")
                .collect::<Vec<_>>()
        )?
    );
    assert_eq!(after.inputs.len(), before.inputs.len() + 1);
    let partial = vuln::assess(&after, &advisory, "2026-11-07T12:00:00Z", 86400)?;
    assert!(!partial.complete);
    assert!(!partial.coverage.inventory_complete);
    assert_eq!(partial.findings.len(), 1);
    assert_eq!(partial.findings[0].status, vuln::MatchStatus::Matched);
    Ok(())
}
