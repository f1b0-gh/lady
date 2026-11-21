use super::{
    invalid,
    model::*,
    read::{Reader, ARTIFACT_LIMIT},
};
use crate::{config, error::Result, files, json};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const DOCUMENTS: [&str; 4] = [
    "findings.json",
    "coverage-ledger.json",
    "source-manifest.json",
    "evidence-manifest.json",
];
pub(crate) fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
pub(crate) fn digest(s: &str) -> Result<()> {
    check(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid SHA-256",
    )
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    Ok(serde_json::from_value(json::parse(bytes)?)?)
}
pub(crate) fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Missing text field: {field}")))
}
fn array<'a>(v: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    v.get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("Missing array: {field}")))
}
fn unique<'a>(values: impl Iterator<Item = &'a str>) -> Result<BTreeSet<&'a str>> {
    let mut set = BTreeSet::new();
    for value in values {
        check(set.insert(value), "Duplicate reference")?;
    }
    Ok(set)
}
pub fn load(path: &Path) -> Result<VerifiedRun> {
    let mut reader = Reader::new(path)?;
    let metadata: RunMetadata = decode(reader.document("run-metadata.json")?)?;
    check(
        metadata.schema_version == 1 && metadata.document_schema == "upstream-v1",
        "Incompatible run version",
    )?;
    config::identifier(&metadata.run_id)?;
    check(!metadata.scope_paths.is_empty(), "Empty scope")?;
    unique(metadata.scope_paths.iter().map(String::as_str))?;
    for p in &metadata.scope_paths {
        config::relative_path(p)?;
    }
    for h in [
        &metadata.config_sha256,
        &metadata.toolchain_sha256,
        &metadata.method_sha256,
    ] {
        digest(h)?;
    }
    check(
        metadata.documents.len() == DOCUMENTS.len(),
        "Incorrect document set",
    )?;
    for name in DOCUMENTS {
        let hash = metadata
            .documents
            .get(name)
            .ok_or_else(|| invalid("Missing document hash"))?;
        digest(hash)?;
        check(
            files::hash(reader.document(name)?) == *hash,
            "Document hash mismatch",
        )?;
    }
    let bytes = |name| {
        reader
            .files
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| invalid("Missing document"))
    };
    crate::audit::validator::validate(
        crate::audit::validator::Mode::Findings,
        bytes("findings.json")?,
    )?;
    crate::audit::validator::validate(
        crate::audit::validator::Mode::Coverage,
        bytes("coverage-ledger.json")?,
    )?;
    let findings: Vec<Value> = decode(bytes("findings.json")?)?;
    let coverage: Vec<Value> = decode(bytes("coverage-ledger.json")?)?;
    let sources: SourceManifest = decode(bytes("source-manifest.json")?)?;
    let evidence: EvidenceManifest = decode(bytes("evidence-manifest.json")?)?;
    check(
        sources.schema_version == 1 && evidence.schema_version == 1,
        "Incompatible manifest version",
    )?;
    let paths = unique(sources.files.iter().map(|s| s.path.as_str()))?;
    for source in &sources.files {
        config::relative_path(&source.path)?;
        digest(&source.sha256)?;
    }
    check(
        metadata.budget.invocations > 0 && metadata.budget.seconds > 0,
        "Zero budget",
    )?;
    check(
        metadata.invocations.len() <= metadata.budget.invocations as usize
            && (metadata.elapsed_seconds <= metadata.budget.seconds
                || (metadata.status != RunStatus::Complete
                    && !metadata.open_obligations.is_empty())),
        "Budget exceeded",
    )?;
    unique(metadata.invocations.iter().map(|i| i.id.as_str()))?;
    let invocations: BTreeMap<_, _> = metadata
        .invocations
        .iter()
        .map(|i| (i.id.as_str(), i))
        .collect();
    for invocation in &metadata.invocations {
        config::identifier(&invocation.id)?;
    }
    check(evidence.artifacts.len() <= 1024, "Too much evidence")?;
    unique(evidence.artifacts.iter().map(|a| a.id.as_str()))?;
    unique(evidence.artifacts.iter().map(|a| a.path.as_str()))?;
    for artifact in &evidence.artifacts {
        config::identifier(&artifact.id)?;
        config::identifier(&artifact.producer)?;
        check(
            invocations.contains_key(artifact.producer.as_str()),
            "Unknown evidence producer",
        )?;
        check(
            artifact
                .path
                .starts_with(&format!("agents/{}/artifacts/", artifact.producer)),
            "Evidence outside its producer's directory",
        )?;
        check(
            !artifact.command.is_empty()
                && artifact
                    .command
                    .iter()
                    .all(|s| !s.is_empty() && !s.contains('\0')),
            "Invalid evidence command",
        )?;
        digest(&artifact.sha256)?;
        check(artifact.size <= ARTIFACT_LIMIT as u64, "Evidence too large")?;
        let data = reader.read(&artifact.path, ARTIFACT_LIMIT)?;
        check(
            data.len() as u64 == artifact.size && files::hash(data) == artifact.sha256,
            "Evidence tampered with",
        )?;
    }
    validate_relations(
        &metadata,
        &findings,
        &coverage,
        &paths,
        &evidence,
        &invocations,
    )?;
    Ok(VerifiedRun {
        metadata,
        sources,
        findings,
        coverage,
        files: reader.files,
    })
}

fn validate_relations(
    metadata: &RunMetadata,
    findings: &[Value],
    coverage: &[Value],
    paths: &BTreeSet<&str>,
    evidence: &EvidenceManifest,
    invocations: &BTreeMap<&str, &InvocationReceipt>,
) -> Result<()> {
    let findings_map: BTreeMap<_, _> = findings
        .iter()
        .map(|f| Ok((text(f, "fingerprint")?, f)))
        .collect::<Result<_>>()?;
    check(
        findings_map.len() == findings.len(),
        "Fingerprint collision",
    )?;
    let coverage_map: BTreeMap<_, _> = coverage
        .iter()
        .map(|u| Ok((text(u, "coverage_id")?, u)))
        .collect::<Result<_>>()?;
    check(coverage_map.len() == coverage.len(), "Coverage collision")?;
    unique(metadata.links.iter().map(|l| l.fingerprint.as_str()))?;
    check(
        metadata.links.len() == findings.len(),
        "Missing finding link",
    )?;
    let artifacts: BTreeMap<_, _> = evidence
        .artifacts
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();
    for finding in findings {
        for field in ["trace", "evidence"] {
            for entry in array(finding, field)? {
                check(
                    paths.contains(text(entry, "file")?),
                    "Cited source missing from manifest",
                )?;
            }
        }
    }
    for link in &metadata.links {
        let finding = findings_map
            .get(link.fingerprint.as_str())
            .ok_or_else(|| invalid("Missing link to finding"))?;
        check(!link.coverage_ids.is_empty(), "Finding without coverage")?;
        unique(link.coverage_ids.iter().map(String::as_str))?;
        unique(link.artifact_ids.iter().map(String::as_str))?;
        check(
            link.hunter_id != link.verifier_id,
            "Hunter and verifier are identical",
        )?;
        for (id, role) in [
            (&link.hunter_id, Role::Hunter),
            (&link.verifier_id, Role::Verifier),
        ] {
            let invocation = invocations
                .get(id.as_str())
                .ok_or_else(|| invalid("Unknown invocation"))?;
            check(
                invocation.role == role && invocation.status == InvocationStatus::Finished,
                "Invocation lacks the expected role or completion",
            )?;
        }
        for id in &link.coverage_ids {
            let unit = coverage_map
                .get(id.as_str())
                .ok_or_else(|| invalid("Missing coverage unit"))?;
            let mut linked = false;
            for attempt in std::iter::once(*unit).chain(array(unit, "attempts")?.iter()) {
                linked |= attempt["agent_id"].as_str() == Some(&link.hunter_id)
                    && array(attempt, "result_fingerprints")?
                        .iter()
                        .any(|v| v.as_str() == Some(&link.fingerprint));
            }
            check(linked, "Coverage link or hunter identity is not reciprocal")?;
        }
        let mut independent_proof = false;
        for id in &link.artifact_ids {
            let artifact = artifacts
                .get(id.as_str())
                .ok_or_else(|| invalid("Referenced artifact missing"))?;
            independent_proof |= artifact.producer == link.verifier_id;
        }
        if text(finding, "verdict")? == "confirmed" {
            check(independent_proof, "Confirmation without verifier evidence")?;
        }
    }
    let mut pending = false;
    for unit in coverage {
        for field in ["starting_paths", "reviewed_paths"] {
            for p in array(unit, field)? {
                let p = p.as_str().ok_or_else(|| invalid("Path is not text"))?;
                check(
                    paths
                        .iter()
                        .any(|s| *s == p || s.starts_with(&format!("{p}/"))),
                    "Coverage path missing from manifest",
                )?;
            }
        }
        for attempt in std::iter::once(unit).chain(array(unit, "attempts")?.iter()) {
            for fingerprint in array(attempt, "result_fingerprints")? {
                let f = fingerprint
                    .as_str()
                    .ok_or_else(|| invalid("Invalid fingerprint"))?;
                if findings_map.contains_key(f) {
                    check(
                        metadata.links.iter().any(|l| {
                            l.fingerprint == f
                                && l.coverage_ids
                                    .iter()
                                    .any(|c| Some(c.as_str()) == unit["coverage_id"].as_str())
                        }),
                        "Finding reference is not reciprocal",
                    )?;
                } else {
                    check(
                        !array(attempt, "unresolved")?.is_empty(),
                        "Candidate without disposition or blocker",
                    )?;
                    pending = true;
                }
            }
            validate_checks(attempt, paths, evidence, invocations)?;
        }
        pending |= coverage_pending(unit);
    }
    if metadata.status == RunStatus::Complete {
        check(
            !coverage.is_empty() && !pending && metadata.open_obligations.is_empty(),
            "Incomplete run reported as complete",
        )?;
        check(
            metadata.environment_verified && metadata.cleanup_verified,
            "Missing environment checks or cleanup",
        )?;
        check(
            invocations
                .values()
                .all(|i| i.status == InvocationStatus::Finished),
            "Unfinished invocation",
        )?;
        check(
            invocations.values().any(|i| i.role == Role::Critic),
            "Missing final critique",
        )?;
        check(
            !findings.iter().any(|f| f["verdict"] == "needs_validation"),
            "Validation still pending",
        )?;
    }
    Ok(())
}

pub(crate) fn coverage_pending(unit: &Value) -> bool {
    matches!(
        unit["status"].as_str(),
        Some("planned" | "in_progress" | "blocked" | "deferred")
    ) || (unit["status"] == "candidate"
        && unit["unresolved"].as_array().is_some_and(|v| !v.is_empty()))
}

fn validate_checks(
    unit: &Value,
    paths: &BTreeSet<&str>,
    evidence: &EvidenceManifest,
    invocations: &BTreeMap<&str, &InvocationReceipt>,
) -> Result<()> {
    if let Some(id) = unit["agent_id"].as_str() {
        check(invocations.contains_key(id), "Unknown coverage agent")?;
    }
    for entry in array(unit, "local_checks")? {
        let agent = text(entry, "agent_id")?;
        check(invocations.contains_key(agent), "Unknown check agent")?;
        for p in array(entry, "reviewed_paths")? {
            check(
                p.as_str().is_some_and(|s| paths.contains(s)),
                "Missing check source",
            )?;
        }
        if let Some(path) = entry["artifact"].as_str() {
            check(
                evidence
                    .artifacts
                    .iter()
                    .any(|a| a.path == path && a.producer == agent),
                "Missing check artifact or wrong producer",
            )?;
        }
    }
    Ok(())
}

pub fn summary(run: &VerifiedRun) -> Value {
    let mut counts = BTreeMap::from([
        ("confirmed", 0usize),
        ("needs_validation", 0),
        ("rejected", 0),
    ]);
    for finding in &run.findings {
        if let Some(count) = finding["verdict"].as_str().and_then(|s| counts.get_mut(s)) {
            *count += 1;
        }
    }
    json!({"schema_version":1,"operation":"verify","run_id":run.metadata.run_id,"run_status":run.metadata.status,"documents_valid":true,"evidence_integrity_verified":true,"authenticity_verified":false,"coverage_complete":false,"coverage_units":run.coverage.len(),"counts":counts,"open_obligations":run.metadata.open_obligations})
}
