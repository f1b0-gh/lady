//! Host-only retained evidence and Git binding; never execute agent-provided checks.
use super::*;
use crate::{
    Config,
    setup::native::{command, git, git_bytes},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    process::Stdio,
};

fn hash(bytes: &[u8]) -> Result<String> {
    let mut child = command("/usr/bin/openssl")
        .args(["dgst", "-sha256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let write = child
        .stdin
        .take()
        .context("Hash input missing")?
        .write_all(bytes);
    let output = child.wait_with_output()?;
    ensure!(
        write.is_ok() && output.status.success(),
        "Artifact hashing failed"
    );
    let text = String::from_utf8(output.stdout)?;
    let digest = text
        .split_whitespace()
        .last()
        .context("Artifact hash missing")?;
    ensure!(super::digest(digest), "Artifact hash malformed");
    Ok(digest.into())
}
fn read(config: &Config, a: &Artifact) -> Result<Vec<u8>> {
    a.validate(&config.workspace)?;
    let meta = fs::symlink_metadata(&a.path)?;
    ensure!(
        meta.is_file() && meta.len() <= 256 * 1024,
        "Conflict review artifact missing, nonregular or oversized"
    );
    let mut bytes = Vec::new();
    fs::File::open(&a.path)?
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 256 * 1024 && hash(&bytes)? == a.sha256,
        "Conflict review artifact changed"
    );
    Ok(bytes)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    commands: Vec<Vec<String>>,
    timeout: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema_version: u32,
    checks: Policy,
}
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    executable: bool,
    sha256: String,
}
#[derive(Deserialize)]
struct Manifest {
    schema_version: u32,
    files: std::collections::BTreeMap<String, FileRecord>,
    sandbox_id: String,
}
#[derive(Deserialize)]
struct CheckResult {
    command: Vec<String>,
    exit_code: i64,
    output_sha256: String,
}
#[derive(Deserialize)]
struct Verifier {
    sandbox_id: String,
}
#[derive(Deserialize)]
struct Receipt {
    schema_version: u32,
    export: PathBuf,
    snapshot_sha256: String,
    policy_sha256: String,
    commands: Vec<Vec<String>>,
    passed: bool,
    cleanup_confirmed: bool,
    results: Vec<CheckResult>,
    verifier: Verifier,
}
fn evidence(config: &Config, p: &Package) -> Result<bool> {
    let manifest: Manifest = serde_json::from_slice(&read(config, &p.manifest)?)?;
    let receipt: Receipt = serde_json::from_slice(&read(config, &p.checks)?)?;
    let policy: PolicyFile = serde_json::from_slice(&read(config, &p.policy)?)?;
    ensure!(
        manifest.schema_version == 2 && receipt.schema_version == 1 && policy.schema_version == 1,
        "Unsupported retained evidence schema"
    );
    ensure!(
        manifest.files.len() <= 4096,
        "Export inventory exceeds profile"
    );
    ensure!(
        p.manifest
            .path
            .file_name()
            .is_some_and(|s| s == "manifest.json")
            && p.checks
                .path
                .file_name()
                .is_some_and(|s| s == "checks.json")
            && p.manifest.path.parent() == p.checks.path.parent()
            && p.manifest.path.parent() == Some(receipt.export.as_path()),
        "Check receipt belongs to another export"
    );
    ensure!(
        policy.checks.timeout > 0
            && policy.checks.timeout <= 86400
            && !policy.checks.commands.is_empty()
            && policy.checks.commands.len() <= 32
            && receipt.commands == policy.checks.commands
            && receipt.results.len() <= receipt.commands.len(),
        "Check command set differs from host policy"
    );
    ensure!(
        receipt.policy_sha256 == hash(&serde_json::to_vec(&policy.checks)?)?
            && receipt.snapshot_sha256
                == hash(&serde_json::to_vec(&serde_json::to_value(
                    &manifest.files
                )?)?)?,
        "Native check policy or snapshot digest differs"
    );
    ensure!(
        !manifest.sandbox_id.is_empty()
            && !receipt.verifier.sandbox_id.is_empty()
            && receipt.verifier.sandbox_id != manifest.sandbox_id,
        "Independent verifier instance missing"
    );
    for c in &p.independent_checks {
        ensure!(
            c.command_index < receipt.commands.len(),
            "Independent check references an absent command"
        );
    }
    for (result, command) in receipt.results.iter().zip(&receipt.commands) {
        ensure!(
            &result.command == command && digest(&result.output_sha256),
            "Check result command or output binding differs"
        );
    }
    // Rebuild the candidate inventory from Git objects, not mutable working files.
    let raw = git_bytes(
        &config.workspace,
        &["ls-tree", "--full-tree", "-r", "-z", &p.candidate_tree],
    )?;
    let mut actual = std::collections::BTreeMap::new();
    let mut total = 0usize;
    for record in raw.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let record = std::str::from_utf8(record)?;
        let (header, path) = record.split_once('\t').context("Invalid Git tree entry")?;
        let fields = header.split_whitespace().collect::<Vec<_>>();
        ensure!(
            source_path(path)
                && fields.len() == 3
                && fields[1] == "blob"
                && matches!(fields[0], "100644" | "100755"),
            "Unsupported resolved tree path or mode"
        );
        let size = git(&config.workspace, &["cat-file", "-s", fields[2]])?.parse::<usize>()?;
        ensure!(
            size <= 4 * 1024 * 1024,
            "Conflict review blob exceeds 4 MiB profile"
        );
        let bytes = git_bytes(&config.workspace, &["cat-file", "blob", fields[2]])?;
        total = total
            .checked_add(bytes.len())
            .context("Tree size overflow")?;
        ensure!(
            total <= 64 * 1024 * 1024,
            "Conflict review tree exceeds 64 MiB profile"
        );
        ensure!(
            actual
                .insert(
                    path.to_owned(),
                    FileRecord {
                        executable: fields[0] == "100755",
                        sha256: hash(&bytes)?
                    }
                )
                .is_none(),
            "Repeated Git tree path"
        );
    }
    ensure!(
        actual == manifest.files,
        "Resolved Git tree differs from independently checked export"
    );
    Ok(receipt.passed
        && receipt.cleanup_confirmed
        && receipt.results.len() == receipt.commands.len()
        && receipt.results.iter().all(|r| r.exit_code == 0))
}
fn load(config: &Config) -> Result<(Package, String)> {
    let selected = config
        .conflict_review
        .as_ref()
        .context("Host-selected conflict review package missing")?;
    let p: Package = serde_json::from_slice(&read(config, selected)?)
        .map_err(|_| anyhow::anyhow!("Invalid conflict review package"))?;
    p.structural()?;
    let exported = p
        .manifest
        .path
        .parent()
        .context("Manifest parent missing")?
        .join("project");
    for path in [&selected.path, &p.policy.path] {
        ensure!(
            !crate::resolved(path)?.starts_with(crate::resolved(&exported)?),
            "Host review package or check policy resolves inside the sandbox export"
        );
    }
    ensure!(
        p.repository == format!("{}/{}", config.owner, config.repository)
            && config.stack_base.as_deref() == Some(p.target.as_str()),
        "Conflict review repository or target differs"
    );
    Ok((p, selected.sha256.clone()))
}
/// Both publication and integration inspect immutable local candidate bytes.
pub fn verify_candidate(
    config: &Config,
    head: &str,
    target: Option<&str>,
    require_message: bool,
    require_ready: bool,
) -> Result<Option<Value>> {
    ensure!(
        crate::integration::full_oid(head),
        "Conflict review requires a full candidate object ID"
    );
    let message = git(&config.workspace, &["show", "-s", "--format=%B", head])?;
    if config.conflict_review.is_none() {
        let introduced = if let Some(target) = target {
            ensure!(
                crate::integration::full_oid(target),
                "Conflict scan requires an exact target object ID"
            );
            git(
                &config.workspace,
                &["log", "--format=%B", &format!("{target}..{head}")],
            )?
        } else {
            message.clone()
        };
        ensure!(
            !introduced.lines().any(|s| s.starts_with(MARKER)),
            "Introduced conflict marker requires its host-selected package"
        );
        return Ok(None);
    }
    let (p, sha) = load(config)?;
    ensure!(
        git(
            &config.workspace,
            &["rev-parse", &format!("{head}^{{tree}}")]
        )? == p.candidate_tree,
        "Conflict review belongs to another resolved tree"
    );
    ensure!(
        head != p.upstream_head,
        "Conflict candidate must follow the selected upstream"
    );
    git(
        &config.workspace,
        &["merge-base", "--is-ancestor", &p.upstream_head, head],
    )?;
    if let Some(target) = target {
        ensure!(target == p.upstream_head, "Conflict review target is stale");
    }
    git(
        &config.workspace,
        &[
            "merge-base",
            "--is-ancestor",
            &p.original_base,
            &p.previous_head,
        ],
    )?;
    git(
        &config.workspace,
        &[
            "merge-base",
            "--is-ancestor",
            &p.original_base,
            &p.upstream_head,
        ],
    )?;
    let passed = evidence(config, &p)?;
    let body = render(&p, &sha)?;
    if require_message {
        // The first line is the PR title. Its body is the complete canonical
        // review text, so extra markup cannot conceal the authoritative section.
        let description = message
            .split_once('\n')
            .context("Signed conflict description missing")?
            .1
            .trim();
        ensure!(
            description == body.trim(),
            "Signed conflict description must exactly match its review package"
        );
    }
    if require_ready {
        p.validate()?;
        ensure!(
            passed,
            "Independent verification did not pass or cleanup is unconfirmed"
        );
    }
    Ok(Some(
        json!({"sha256":sha,"candidate":head,"tree":p.candidate_tree,"upstream":p.upstream_head,"independent_checks_passed":passed,
        "coverage_complete":p.validate().is_ok(),"human_review_required":true,"body":body}),
    ))
}
pub fn verify_display(text: &str, body: &str, sha: &str) -> Result<()> {
    ensure!(
        digest(sha)
            && body
                .lines()
                .filter(|line| line.starts_with(MARKER))
                .collect::<Vec<_>>()
                == vec![format!("{MARKER}{sha}").as_str()],
        "Conflict display digest missing or ambiguous"
    );
    // Reuse jjpr's exact managed-body format; arbitrary surrounding Markdown or
    // HTML could hide the review. Put additional discussion in review comments.
    let wrapped = jjpr::submit::plan::wrap_managed_body(body.trim_end());
    ensure!(
        text.trim() == body.trim() || text.trim() == wrapped.trim(),
        "Published conflict review must be the complete visible canonical body"
    );
    Ok(())
}

pub fn inspect(config: &Config, head: &str, render_only: bool) -> Result<Value> {
    config.validate_host_paths()?;
    let mut value = verify_candidate(config, head, None, !render_only, false)?
        .context("No conflict package selected")?;
    value["status"] = json!(if value["coverage_complete"] == true
        && value["independent_checks_passed"] == true
    {
        "observed"
    } else {
        "pending"
    });
    Ok(value)
}
