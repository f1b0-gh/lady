use serde_json::{json, Value};
use std::process::Command;
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
fn fixture() -> Value {
    json!({"vxdfVersion":"0.0.1","id":"10000000-0000-4000-8000-000000000001",
    "generatedAt":"2026-11-04T12:00:00Z", "exploitFlows":[{
        "id":"20000000-0000-4000-8000-000000000001", "title":"Synthetic claim", "category":"OTHER",
        "severity":{"level":"LOW"}, "validatedAt":"2026-11-04T11:00:00Z",
        "affectedComponents":[{"name":"fixture","componentType":"SOFTWARE_LIBRARY"}],
        "evidence":[{"evidenceType":"OTHER_EVIDENCE","description":"Synthetic assertion",
            "data":{"dataTypeDescription":"text","dataContent":"file:///missing"}}]
    }]})
}
#[test]
fn local_intake_preserves_bytes_without_qualification_or_overwriting() -> Result {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("input.json");
    let output = dir.path().join("intake.json");
    let original = serde_json::to_vec_pretty(&fixture())?;
    std::fs::write(&input, &original)?;
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ladybom"))
            .env_clear()
            .env("PATH", "")
            .args(["vxdf", "import", "--input"])
            .arg(&input)
            .arg("--output")
            .arg(&output)
            .output()
    };
    let result = run()?;
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&output)?.permissions().mode() & 0o777,
        0o600
    );
    let stored = std::fs::read(&output)?;
    let receipt: Value = serde_json::from_slice(&stored)?;
    assert_eq!(receipt["original"], String::from_utf8(original)?);
    assert_eq!(receipt["trust"], "untrusted");
    assert_eq!(receipt["schema_validation"], "valid_pinned_0.0.1");
    assert_eq!(receipt["qualified"], false);
    assert!(!run()?.status.success());
    assert_eq!(std::fs::read(&output)?, stored);
    Ok(())
}
#[test]
fn rejects_symlinks_and_oversized_input_without_creating_output() -> Result {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("input.json");
    std::fs::write(&input, fixture().to_string())?;
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&input, &link)?;
    let output = dir.path().join("output.json");
    let rejected = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["vxdf", "import", "--input"])
        .arg(&link)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert!(!rejected.status.success());
    assert!(!output.exists());
    std::fs::File::create(&input)?.set_len(4 * 1024 * 1024 + 1)?;
    let rejected = Command::new(env!("CARGO_BIN_EXE_ladybom"))
        .args(["vxdf", "import", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .output()?;
    assert!(!rejected.status.success());
    assert!(!output.exists());
    Ok(())
}

#[test]
fn correlation_recomputes_inputs_and_never_adopts_import_receipts() -> Result {
    let dir = tempfile::tempdir()?;
    let mut report: ladybom::Report =
        serde_json::from_str(include_str!("fixtures/report-v2.json"))?;
    let mut project = report.projects.remove(1);
    project.components.retain(|c| c.purl.is_some());
    report.projects = vec![project];
    let snapshot = ladybom::vuln::Snapshot {
        schema_version: 1,
        source: "fixture".into(),
        fetched_at: "2026-11-04T00:00:00Z".into(),
        complete: true,
        ecosystems: vec!["crates.io".into()],
        advisories: vec![json!({
            "id":"TEST-1", "modified":"2026-11-03T00:00:00Z", "affected":[{
                "package":{"ecosystem":"crates.io","name":"itoa"},"versions":["1.0.15"]
            }]
        })],
    };
    let assessment = ladybom::vuln::assess(&report, &snapshot, "2026-11-04T12:00:00Z", 86400)?;
    let finding = &assessment.findings[0];
    let mut document = fixture();
    let flow = &mut document["exploitFlows"][0];
    flow["affectedComponents"][0]["name"] = json!("itoa");
    flow["affectedComponents"][0]["version"] = json!("1.0.15");
    flow["affectedComponents"][0]["purl"] = json!("pkg:cargo/itoa@1.0.15");
    flow["evidence"][0]["id"] = json!("30000000-0000-4000-8000-000000000001");
    flow["evidence"][0]["timestamp"] = json!("2026-11-04T10:00:00Z");
    flow["x-ladybom"] = json!({"report_digest":assessment.report_digest,
        "snapshot_digest":assessment.snapshot_digest,"finding_id":finding.id,
        "component_ref":finding.component_ref,"purl":finding.purl,"source":report.projects[0].components[0].source,
        "manifest":finding.manifest,"lockfile":finding.lockfile,"context":finding.context,
        "revision":"fixture-commit","target_profile":"fixture-linux"});
    let report_path = dir.path().join("report.json");
    let snapshot_path = dir.path().join("snapshot.json");
    let input = dir.path().join("document.json");
    std::fs::write(&report_path, serde_json::to_vec(&report)?)?;
    std::fs::write(&snapshot_path, serde_json::to_vec(&snapshot)?)?;
    std::fs::write(&input, serde_json::to_vec(&document)?)?;
    let command = |action: &str| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ladybom"));
        command
            .env_clear()
            .env("PATH", "")
            .args(["vxdf", action, "--input"])
            .arg(&input)
            .arg("--report")
            .arg(&report_path)
            .arg("--snapshot")
            .arg(&snapshot_path)
            .args([
                "--revision",
                "fixture-commit",
                "--target-profile",
                "fixture-linux",
                "--as-of",
                "2026-11-04T12:00:00Z",
            ]);
        command
    };
    let result = command("correlate").output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(receipt["qualified"], false);
    assert_eq!(receipt["matches"][0]["finding_id"], finding.id);
    assert!(receipt.get("original").is_none());
    let review_path = dir.path().join("review.json");
    let template = command("review-template")
        .arg("--output")
        .arg(&review_path)
        .output()?;
    assert!(
        template.status.success(),
        "{}",
        String::from_utf8_lossy(&template.stderr)
    );
    let mut review: Value = serde_json::from_slice(&std::fs::read(&review_path)?)?;
    assert_eq!(review["flows"][0]["decision"], "unreviewed");
    review["reviewer"] = json!("fixture-reviewer");
    review["reviewed_at"] = json!("2026-11-04T12:00:00Z");
    review["expires_at"] = json!("2026-11-05T12:00:00Z");
    review["public_content_approved"] = json!(true);
    review["flows"][0]["decision"] = json!("validated_exploitable");
    review["flows"][0]["public"] = json!({"title":"Synthetic issue","summary":"Reviewed synthetic proof",
        "severity":"HIGH","scenario":"Run synthetic fixture","observed_result":"Protected marker observed",
        "tool_name":"fixture-runner","tool_version":"1.0","environment":"Isolated fixture","limitations":"Synthetic only"});
    let reviewed = serde_json::to_vec(&review)?;
    std::fs::write(&review_path, &reviewed)?;
    let exported_path = dir.path().join("public.vxdf.json");
    let export = |accepted_digest: &str| {
        command("export")
            .arg("--review")
            .arg(&review_path)
            .arg("--review-sha256")
            .arg(accepted_digest)
            .args(["--reviewer", "fixture-reviewer"])
            .arg("--output")
            .arg(&exported_path)
            .output()
    };
    assert!(!export("wrong")?.status.success());
    assert!(!exported_path.exists());
    let result = export(&ladybom::files::hash(&reviewed))?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let exported: Value = serde_json::from_slice(&std::fs::read(&exported_path)?)?;
    assert_eq!(
        exported["x-ladybom-review"]["trust"],
        "human_review_assertion"
    );
    assert_eq!(
        exported["x-ladybom-review"]["cryptographically_verified"],
        false
    );
    assert!(!export(&ladybom::files::hash(&reviewed))?.status.success());
    let mut fake_receipt = receipt.clone();
    fake_receipt["qualified"] = json!(true);
    std::fs::write(&input, serde_json::to_vec(&fake_receipt)?)?;
    let refused = command("correlate").output()?;
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    Ok(())
}
