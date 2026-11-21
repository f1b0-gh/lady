mod audit_support;
use ladyshell::audit::{
    journal::RunJournal,
    model::Budget,
    model::{EvidenceManifest, RunMetadata},
    publish::{self, Output},
    verify,
};
use serde_json::{json, Value};
use std::{error::Error, fs, path::Path};

fn pending(confirmed: bool) -> Result<(tempfile::TempDir, RunMetadata, Output), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let dir = audit_support::fixture(confirmed)?;
    let root = dir.path();
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let metadata = serde_json::from_slice(&fs::read(root.join("run-metadata.json"))?)?;
    let evidence: EvidenceManifest =
        serde_json::from_slice(&fs::read(root.join("evidence-manifest.json"))?)?;
    let output = Output {
        findings: serde_json::from_slice(&fs::read(root.join("findings.json"))?)?,
        coverage: serde_json::from_slice(&fs::read(root.join("coverage-ledger.json"))?)?,
        sources: serde_json::from_slice(&fs::read(root.join("source-manifest.json"))?)?,
        links: serde_json::from_value(
            serde_json::from_slice::<Value>(&fs::read(root.join("run-metadata.json"))?)?["links"]
                .clone(),
        )?,
        artifacts: evidence.artifacts,
    };
    for name in [
        "run-metadata.json",
        "findings.json",
        "coverage-ledger.json",
        "source-manifest.json",
        "evidence-manifest.json",
    ] {
        fs::remove_file(root.join(name))?;
    }
    Ok((dir, metadata, output))
}

#[test]
fn aggregate_coverage_is_upstream_valid_for_reviewed_blocked_candidate_and_deferred_states(
) -> Result<(), Box<dyn Error>> {
    let paths = vec!["src/audit.rs".into(), "src/main.rs".into()];
    for (hunter, fingerprints, unresolved, status) in [
        (Some("hunter"), vec![], vec![], "covered"),
        (
            Some("hunter"),
            vec![],
            vec!["Missing external condition".into()],
            "blocked",
        ),
        (
            Some("hunter"),
            vec!["candidate-one".into()],
            vec!["Independent check pending".into()],
            "candidate",
        ),
        (None, vec![], vec![], "deferred"),
    ] {
        let unit = publish::coverage(
            &paths,
            hunter,
            "Source review only, partial scope",
            &fingerprints,
            &unresolved,
        )?;
        assert_eq!(unit["status"], status);
        assert_eq!(
            unit["canonical_refs"]["subsystem"],
            "profile/quick/all-in-scope-subsystems"
        );
        assert_eq!(unit["coverage_id"], "src%2Faudit.rs%23audit-scope::src%2Faudit.rs%23trust-boundaries::profile%2Fquick%2Fall-in-scope-subsystems::ATTACK-CLASSES.md%23Access%20control");
        assert_eq!(
            ladyshell::audit::validator::validate(
                ladyshell::audit::validator::Mode::Coverage,
                &serde_json::to_vec(&json!([unit.clone()]))?
            )?,
            1
        );
        if hunter.is_none() {
            assert_eq!(unit["reviewed_paths"], json!([]));
            assert_eq!(unit["local_checks"], json!([]));
            assert!(!unit["unresolved"]
                .as_array()
                .ok_or("unresolved")?
                .is_empty());
        } else {
            assert_eq!(unit["reviewed_paths"], json!(paths));
            assert_eq!(unit["local_checks"][0]["method"], "source");
        }
    }
    Ok(())
}

#[test]
fn coverage_refuses_unsafe_empty_duplicate_or_unattributed_inputs() {
    assert!(publish::coverage(&[], Some("hunter"), "summary", &[], &[]).is_err());
    for paths in [
        vec!["../outside".into()],
        vec!["src/a.rs".into(), "src/a.rs".into()],
    ] {
        assert!(publish::coverage(&paths, Some("hunter"), "summary", &[], &[]).is_err());
    }
    let paths = ["src/a.rs".into()];
    assert!(publish::coverage(&paths, Some("../hunter"), "summary", &[], &[]).is_err());
    assert!(publish::coverage(&paths, None, "summary", &["orphan".into()], &[]).is_err());
    assert!(publish::coverage(&paths, Some("hunter"), &"x".repeat(4097), &[], &[]).is_err());
}

#[test]
fn publication_recomputes_hashes_verifies_evidence_and_derives_partial_report(
) -> Result<(), Box<dyn Error>> {
    let (dir, mut metadata, output) = pending(true)?;
    metadata.documents.clear();
    metadata
        .documents
        .insert("forged.json".into(), "untrusted".into());
    metadata.links.clear();
    let summary = publish::write(dir.path(), metadata, output)?;
    assert_eq!(summary["run_status"], "partial");
    assert_eq!(summary["counts"]["confirmed"], 1);
    assert_eq!(summary["coverage_complete"], false);
    assert_eq!(summary["authenticity_verified"], false);
    assert_eq!(summary, verify::summary(&verify::load(dir.path())?));
    let report = fs::read_to_string(dir.path().join("REPORT.md"))?;
    assert!(report.contains("couverture partielle"));
    assert!(report.contains("| Confirmé | 1 |"));
    Ok(())
}

#[test]
fn generated_journal_identity_is_publishable_without_rewriting_it() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let parent = tempfile::tempdir()?;
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))?;
    for _ in 0..16 {
        let journal = RunJournal::create(
            parent.path(),
            &"a".repeat(64),
            Budget {
                invocations: 7,
                seconds: 120,
            },
        )?;
        let (dir, mut metadata, output) = pending(false)?;
        metadata.run_id = journal.data().run_id.clone();
        let summary = publish::write(dir.path(), metadata, output)?;
        assert_eq!(summary["run_id"], journal.data().run_id);
    }
    Ok(())
}

#[test]
fn deferred_partial_run_is_publishable_without_invented_review() -> Result<(), Box<dyn Error>> {
    let (dir, metadata, mut output) = pending(false)?;
    output.coverage.push(publish::coverage(
        &["src/handler.c".into()],
        None,
        "Hunter did not run",
        &[],
        &[],
    )?);
    let summary = publish::write(dir.path(), metadata, output)?;
    assert_eq!(summary["coverage_units"], 1);
    assert_eq!(summary["counts"]["confirmed"], 0);
    verify::load(dir.path())?;
    Ok(())
}

#[test]
fn invalid_relationships_or_evidence_never_produce_a_report() -> Result<(), Box<dyn Error>> {
    for corruption in [
        "same-agent",
        "missing-artifact",
        "tampered-proof",
        "upstream",
        "false-complete",
    ] {
        let (dir, mut metadata, mut output) = pending(true)?;
        match corruption {
            "same-agent" => output.links[0].verifier_id = output.links[0].hunter_id.clone(),
            "missing-artifact" => output.links[0].artifact_ids = vec!["absent".into()],
            "tampered-proof" => fs::write(
                dir.path().join("agents/verifier/artifacts/proof.txt"),
                "changed",
            )?,
            "upstream" => output.coverage[0]["coverage_id"] = json!("forged-id"),
            "false-complete" => metadata.status = ladyshell::audit::model::RunStatus::Complete,
            _ => unreachable!(),
        }
        assert!(
            publish::write(dir.path(), metadata, output).is_err(),
            "{corruption}"
        );
        assert!(!dir.path().join("REPORT.md").exists());
    }
    Ok(())
}

#[test]
fn publication_never_overwrites_existing_or_linked_destinations() -> Result<(), Box<dyn Error>> {
    for kind in ["regular", "symlink", "hardlink", "directory"] {
        let (dir, metadata, output) = pending(false)?;
        let outside = dir.path().join("sentinel");
        fs::write(&outside, "keep")?;
        let target = dir.path().join("findings.json");
        match kind {
            "regular" => fs::write(&target, "existing")?,
            "symlink" => std::os::unix::fs::symlink(&outside, &target)?,
            "hardlink" => fs::hard_link(&outside, &target)?,
            "directory" => fs::create_dir(&target)?,
            _ => unreachable!(),
        }
        assert!(publish::write(dir.path(), metadata, output).is_err());
        assert_eq!(fs::read_to_string(outside)?, "keep");
        assert!(!dir.path().join("REPORT.md").exists());
    }
    let (dir, metadata, output) = pending(false)?;
    publish::write(dir.path(), metadata.clone(), output.clone())?;
    let before = fs::read(dir.path().join("run-metadata.json"))?;
    assert!(publish::write(dir.path(), metadata, output).is_err());
    assert_eq!(fs::read(dir.path().join("run-metadata.json"))?, before);
    Ok(())
}

#[test]
fn publication_refuses_symlink_ancestors_and_nonprivate_run_directory() -> Result<(), Box<dyn Error>>
{
    use std::os::unix::fs::PermissionsExt;
    let (dir, metadata, output) = pending(false)?;
    let parent = tempfile::tempdir()?;
    let link = parent.path().join("linked");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    assert!(publish::write(&link, metadata.clone(), output.clone()).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
    assert!(publish::write(dir.path(), metadata, output).is_err());
    assert!(!Path::new(dir.path()).join("run-metadata.json").exists());
    Ok(())
}
