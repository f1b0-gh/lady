//! Bounded VXDF intake validated against the pinned published JSON Schema.
//! URLs, paths, commands, receipts and claimed validations remain inert, untrusted data.
//! A valid schema or execution receipt never qualifies an assertion as exploitable.
use super::{assess, digest, instant, parse_json, MatchStatus, Snapshot};
use crate::{
    deps::{cyclonedx, Report},
    error::{ensure, Error, Result},
    files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, sync::OnceLock};

pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 20_000;
const MAX_FLOWS: usize = 256;
const MAX_EVIDENCE: usize = 256;
const GAP: &str = "La conformité au schéma ne prouve ni authenticité ni exploitabilité ; une revue humaine distincte est requise pour l’export";
pub const SCHEMA_SHA256: &str = "757177284eb87d75ecb6133c6aafdf8877cc1eef6cd6a69d401495f905129da9";
const SCHEMA_BYTES: &[u8] = include_bytes!("../../../schemas/vxdf-0.0.1.schema.json");

struct DenyExternalReferences;
impl jsonschema::Retrieve for DenyExternalReferences {
    fn retrieve(
        &self,
        _: &jsonschema::Uri<String>,
    ) -> std::result::Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(std::io::Error::other(
            "External schema references are forbidden",
        )))
    }
}
fn schema_validator() -> Result<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<std::result::Result<jsonschema::Validator, String>> =
        OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            if files::hash(SCHEMA_BYTES) != SCHEMA_SHA256 {
                return Err("VXDF : empreinte du schéma embarqué différente".into());
            }
            let schema: Value =
                serde_json::from_slice(SCHEMA_BYTES).map_err(|error| error.to_string())?;
            jsonschema::options()
                .with_draft(jsonschema::Draft::Draft202012)
                .with_retriever(DenyExternalReferences)
                .with_pattern_options(jsonschema::PatternOptions::regex())
                .should_validate_formats(true)
                .build(&schema)
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|message| invalid(message.clone()))
}
fn validate_schema(document: &Value) -> Result<()> {
    // Do not echo payloads, paths or secrets contained in validation errors.
    ensure!(
        schema_validator()?.is_valid(document),
        "VXDF : document non conforme au schéma 0.0.1 épinglé"
    );
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ImportedDocument {
    schema_version: u32,
    document_digest: String,
    /// Exact UTF-8 source, including potentially sensitive untrusted payloads.
    original: String,
    trust: &'static str,
    schema_validation: &'static str,
    schema_digest: &'static str,
    qualified: bool,
    limitations: Vec<&'static str>,
    #[serde(skip)]
    document: Value,
}

/// Operator-supplied expected scope. Revision and profile are compared as opaque
/// identifiers; the static inventory does not independently attest a tested build.
#[derive(Debug, Clone)]
pub struct Scope {
    pub revision: String,
    pub target_profile: String,
    pub as_of: String,
    pub snapshot_max_age_seconds: u64,
    pub evidence_max_age_seconds: u64,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    report_digest: String,
    snapshot_digest: String,
    finding_id: String,
    component_ref: String,
    purl: String,
    source: Value,
    manifest: String,
    lockfile: Option<String>,
    context: String,
    revision: String,
    target_profile: String,
}

#[derive(Debug, Serialize)]
pub struct Correlation {
    schema_version: u32,
    document_digest: String,
    report_digest: String,
    snapshot_digest: String,
    as_of: String,
    revision: String,
    target_profile: String,
    trust: &'static str,
    schema_validation: &'static str,
    schema_digest: &'static str,
    qualified: bool,
    limitations: Vec<&'static str>,
    matches: Vec<CorrelatedFlow>,
}
#[derive(Debug, Serialize)]
struct CorrelatedFlow {
    flow_id: String,
    finding_id: String,
    component_ref: String,
    evidence_ids: Vec<String>,
}

fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| invalid(format!("VXDF : chaîne non vide requise pour {field}")))
}
fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("VXDF : tableau requis pour {field}")))
}
fn uuid(value: &str) -> Result<()> {
    ensure!(
        value.len() == 36
            && value.bytes().enumerate().all(|(i, byte)| {
                if [8, 13, 18, 23].contains(&i) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "VXDF : UUID invalide"
    );
    Ok(())
}
fn bounds(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    ensure!(
        depth <= 32 && *nodes <= MAX_NODES,
        "VXDF : profondeur ou nombre d’éléments excessif"
    );
    match value {
        Value::Array(values) => {
            for value in values {
                bounds(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                bounds(value, depth + 1, nodes)?;
            }
        }
        Value::String(value) => {
            ensure!(value.len() <= 1024 * 1024, "VXDF : chaîne trop volumineuse")
        }
        _ => {}
    }
    Ok(())
}
fn references(value: &Value, ids: &BTreeSet<String>) -> Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(refs) = object.get("evidenceRefs") {
                let refs = refs
                    .as_array()
                    .ok_or_else(|| invalid("VXDF : références invalides"))?;
                let mut seen = BTreeSet::new();
                for reference in refs {
                    let id = reference
                        .as_str()
                        .ok_or_else(|| invalid("VXDF : référence invalide"))?;
                    ensure!(
                        ids.contains(&id.to_ascii_lowercase())
                            && seen.insert(id.to_ascii_lowercase()),
                        "VXDF : référence de preuve absente ou dupliquée"
                    );
                }
            }
            for value in object.values() {
                references(value, ids)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                references(value, ids)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate the complete pinned schema (including formats), then enforce stricter
/// intake bounds, identifiers and local references. Embedded extensions stay opaque
/// data; no schema selected by the document and no external reference is resolved.
pub fn import(bytes: &[u8]) -> Result<ImportedDocument> {
    ensure!(
        bytes.len() <= MAX_DOCUMENT_BYTES,
        "VXDF : document supérieur à 4 Mio"
    );
    let document = parse_json(bytes)?;
    bounds(&document, 0, &mut 0)?;
    validate_schema(&document)?;
    ensure!(
        string(&document, "vxdfVersion")? == "0.0.1",
        "VXDF : version non prise en charge"
    );
    uuid(string(&document, "id")?)?;
    instant(string(&document, "generatedAt")?)?;
    let flows = array(&document, "exploitFlows")?;
    ensure!(
        !flows.is_empty() && flows.len() <= MAX_FLOWS,
        "VXDF : nombre de findings invalide"
    );
    let mut flow_ids = BTreeSet::new();
    for flow in flows {
        let id = string(flow, "id")?;
        uuid(id)?;
        ensure!(
            flow_ids.insert(id.to_ascii_lowercase()),
            "VXDF : finding dupliqué"
        );
        string(flow, "title")?;
        string(flow, "category")?;
        instant(string(flow, "validatedAt")?)?;
        ensure!(
            flow.get("severity").is_some_and(Value::is_object),
            "VXDF : sévérité structurée requise"
        );
        ensure!(
            flow.get("affectedComponents")
                .is_some_and(|v| v.as_array().is_some_and(|a| !a.is_empty()))
                || (flow.get("source").is_some_and(Value::is_object)
                    && flow.get("sink").is_some_and(Value::is_object)),
            "VXDF : composants affectés ou source/puits requis"
        );
        let evidence = array(flow, "evidence")?;
        ensure!(
            !evidence.is_empty() && evidence.len() <= MAX_EVIDENCE,
            "VXDF : nombre de preuves invalide"
        );
        let mut ids = BTreeSet::new();
        for item in evidence {
            string(item, "evidenceType")?;
            string(item, "description")?;
            ensure!(
                item.get("data").is_some_and(Value::is_object),
                "VXDF : données de preuve structurées requises"
            );
            if item.get("id").is_some() {
                let id = string(item, "id")?;
                uuid(id)?;
                ensure!(
                    ids.insert(id.to_ascii_lowercase()),
                    "VXDF : preuve dupliquée"
                );
            }
            if item.get("timestamp").is_some() {
                instant(string(item, "timestamp")?)?;
            }
        }
        references(flow, &ids)?;
    }
    let original = std::str::from_utf8(bytes)
        .map_err(|_| invalid("VXDF : UTF-8 invalide"))?
        .to_owned();
    Ok(ImportedDocument {
        schema_version: 1,
        document_digest: files::hash(bytes),
        original,
        trust: "untrusted",
        schema_validation: "valid_pinned_0.0.1",
        schema_digest: SCHEMA_SHA256,
        qualified: false,
        limitations: vec![GAP],
        document,
    })
}

/// Correlate assertions with the exact current inputs. Even a successful result
/// records untrusted claims only, with no VEX decision or execution receipt adoption.
pub fn correlate(
    document: &ImportedDocument,
    report: &Report,
    snapshot: &Snapshot,
    scope: &Scope,
) -> Result<Correlation> {
    ensure!(
        !scope.revision.trim().is_empty() && !scope.target_profile.trim().is_empty(),
        "VXDF : révision et profil explicites requis"
    );
    ensure!(
        scope.evidence_max_age_seconds > 0,
        "VXDF : durée de validité nulle"
    );
    let assessment = assess(
        report,
        snapshot,
        &scope.as_of,
        scope.snapshot_max_age_seconds,
    )?;
    ensure!(
        assessment.complete,
        "VXDF : couverture courante incomplète ou périmée"
    );
    ensure!(
        assessment.report_digest == digest(report)?,
        "VXDF : rapport incohérent"
    );
    let now = instant(&scope.as_of)?;
    let generated = instant(string(&document.document, "generatedAt")?)?;
    ensure!(generated <= now, "VXDF : document daté dans le futur");
    let mut matches = Vec::new();
    let mut seen_findings = BTreeSet::new();
    for flow in array(&document.document, "exploitFlows")? {
        let binding: Binding = serde_json::from_value(
            flow.get("x-ladybom")
                .cloned()
                .ok_or_else(|| invalid("VXDF : liaison x-ladybom explicite requise"))?,
        )?;
        let finding = assessment
            .findings
            .iter()
            .find(|finding| finding.id == binding.finding_id)
            .ok_or_else(|| invalid("VXDF : finding inconnu"))?;
        ensure!(
            finding.status == MatchStatus::Matched && seen_findings.insert(&finding.id),
            "VXDF : finding inconnu ou dupliqué"
        );
        let project = report
            .projects
            .iter()
            .find(|project| project.manifest == finding.manifest)
            .ok_or_else(|| invalid("VXDF : manifest introuvable"))?;
        let component = project
            .components
            .iter()
            .find(|component| {
                cyclonedx::component_reference(project, component)
                    .is_ok_and(|reference| reference == finding.component_ref)
            })
            .ok_or_else(|| invalid("VXDF : composant introuvable"))?;
        let purl = finding
            .purl
            .as_ref()
            .ok_or_else(|| invalid("VXDF : PURL inconnu"))?;
        let expected = Binding {
            report_digest: assessment.report_digest.clone(),
            snapshot_digest: assessment.snapshot_digest.clone(),
            finding_id: finding.id.clone(),
            component_ref: finding.component_ref.clone(),
            purl: purl.clone(),
            source: component.source.clone(),
            manifest: finding.manifest.clone(),
            lockfile: finding.lockfile.clone(),
            context: finding.context.clone(),
            revision: scope.revision.clone(),
            target_profile: scope.target_profile.clone(),
        };
        ensure!(
            binding == expected,
            "VXDF : périmètre différent du rapport, des sources ou du profil courant"
        );
        let affected = array(flow, "affectedComponents")?;
        ensure!(
            affected.len() == 1
                && string(&affected[0], "purl")? == purl
                && string(&affected[0], "name")? == finding.name
                && string(&affected[0], "version")? == finding.version,
            "VXDF : composant affecté absent, ambigu ou différent"
        );
        if flow.get("status").is_some() {
            ensure!(
                string(flow, "status")? == "OPEN",
                "VXDF : seul un constat ouvert peut être corrélé dans ce pilote"
            );
        }
        let validated = instant(string(flow, "validatedAt")?)?;
        ensure!(
            validated <= generated
                && validated <= now
                && (now - validated).whole_nanoseconds()
                    <= i128::from(scope.evidence_max_age_seconds) * 1_000_000_000,
            "VXDF : validation périmée ou future"
        );
        let mut evidence_ids = Vec::new();
        for evidence in array(flow, "evidence")? {
            let captured = instant(string(evidence, "timestamp")?)?;
            ensure!(
                captured <= validated
                    && (now - captured).whole_nanoseconds()
                        <= i128::from(scope.evidence_max_age_seconds) * 1_000_000_000,
                "VXDF : preuve périmée ou postérieure à la validation"
            );
            evidence_ids.push(string(evidence, "id")?.into());
        }
        matches.push(CorrelatedFlow {
            flow_id: string(flow, "id")?.into(),
            finding_id: finding.id.clone(),
            component_ref: finding.component_ref.clone(),
            evidence_ids,
        });
    }
    Ok(Correlation {
        schema_version: 1,
        document_digest: document.document_digest.clone(),
        report_digest: assessment.report_digest,
        snapshot_digest: assessment.snapshot_digest,
        as_of: scope.as_of.clone(),
        revision: scope.revision.clone(),
        target_profile: scope.target_profile.clone(),
        trust: "untrusted",
        schema_validation: "valid_pinned_0.0.1",
        schema_digest: SCHEMA_SHA256,
        qualified: false,
        limitations: vec![GAP],
        matches,
    })
}

/// Operator acceptance supplied independently of the untrusted document and review.
/// This is an explicit human trust decision, not identity or signature verification.
#[derive(Debug, Clone)]
pub struct ReviewAcceptance {
    pub review_digest: String,
    pub reviewer: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TechnicalReview {
    schema_version: u32,
    review_kind: String,
    document_digest: String,
    reviewer: String,
    reviewed_at: String,
    expires_at: String,
    public_content_approved: bool,
    flows: Vec<ReviewedFlow>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedFlow {
    flow_id: String,
    binding_digest: String,
    evidence: Vec<ReviewedEvidence>,
    decision: String,
    public: PublicReview,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewedEvidence {
    id: String,
    digest: String,
}
/// All strings here are expressly reviewed for publication, never copied from
/// untrusted payloads, commands, context strings or execution receipts.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicReview {
    title: String,
    summary: String,
    severity: String,
    scenario: String,
    observed_result: String,
    tool_name: String,
    tool_version: String,
    environment: String,
    limitations: String,
}
fn evidence_digests(flow: &Value) -> Result<Vec<ReviewedEvidence>> {
    array(flow, "evidence")?
        .iter()
        .map(|evidence| {
            Ok(ReviewedEvidence {
                id: string(evidence, "id")?.into(),
                digest: digest(evidence)?,
            })
        })
        .collect()
}

/// Produce an unsigned, unapproved review template after exact correlation.
/// Empty technical fields and `unreviewed` decisions deliberately prevent export.
/// Neither timestamps nor a successful receipt populate a review automatically.
pub fn review_template(
    document: &ImportedDocument,
    report: &Report,
    snapshot: &Snapshot,
    scope: &Scope,
) -> Result<Value> {
    correlate(document, report, snapshot, scope)?;
    let flows = array(&document.document, "exploitFlows")?
        .iter()
        .map(|flow| {
            Ok(ReviewedFlow {
                flow_id: string(flow, "id")?.into(),
                binding_digest: digest(&flow["x-ladybom"])?,
                evidence: evidence_digests(flow)?,
                decision: "unreviewed".into(),
                public: PublicReview::default(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::to_value(TechnicalReview {
        schema_version: 1,
        review_kind: "human_technical_review".into(),
        document_digest: document.document_digest.clone(),
        reviewer: String::new(),
        reviewed_at: String::new(),
        expires_at: String::new(),
        public_content_approved: false,
        flows,
    })?)
}
fn public_text(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty()
            && value.len() <= 4096
            && !value
                .chars()
                .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t' | '\r')),
        "VXDF : texte public de revue absent, trop long ou invalide"
    );
    Ok(())
}
fn document_uuid(value: &impl Serialize) -> Result<String> {
    let urn = cyclonedx::serial_from_digest(&digest(value)?)?;
    urn.strip_prefix("urn:uuid:")
        .map(str::to_owned)
        .ok_or_else(|| invalid("VXDF : UUID documentaire invalide"))
}

/// Export a public VXDF projection only after the operator explicitly accepts a
/// separate technical review's exact bytes and expected reviewer. A review is a
/// human assertion: no signature, identity or exploitability is verified by Rust.
/// The returned schema-valid document carries that limitation explicitly and
/// cannot automatically create a VEX decision or requalify itself on import.
pub fn export_reviewed(
    document: &ImportedDocument,
    report: &Report,
    snapshot: &Snapshot,
    scope: &Scope,
    review_bytes: &[u8],
    acceptance: &ReviewAcceptance,
) -> Result<Value> {
    ensure!(
        review_bytes.len() <= MAX_DOCUMENT_BYTES,
        "VXDF : revue supérieure à 4 Mio"
    );
    ensure!(
        files::hash(review_bytes) == acceptance.review_digest
            && !acceptance.reviewer.trim().is_empty(),
        "VXDF : revue non acceptée explicitement par son empreinte et son auteur"
    );
    let value = parse_json(review_bytes)?;
    bounds(&value, 0, &mut 0)?;
    let review: TechnicalReview = serde_json::from_value(value)?;
    ensure!(
        review.schema_version == 1
            && review.review_kind == "human_technical_review"
            && review.public_content_approved,
        "VXDF : revue technique et approbation de publication requises"
    );
    ensure!(
        review.document_digest == document.document_digest
            && review.reviewer == acceptance.reviewer,
        "VXDF : revue d’un autre document ou d’un autre auteur"
    );
    let correlation = correlate(document, report, snapshot, scope)?;
    let now = instant(&scope.as_of)?;
    let reviewed_at = instant(&review.reviewed_at)?;
    let expires_at = instant(&review.expires_at)?;
    ensure!(
        reviewed_at <= now
            && expires_at > now
            && reviewed_at < expires_at
            && reviewed_at >= instant(string(&document.document, "generatedAt")?)?,
        "VXDF : revue périmée, future ou antérieure au document"
    );
    let original_flows = array(&document.document, "exploitFlows")?;
    ensure!(
        review.flows.len() == original_flows.len(),
        "VXDF : revue incomplète des findings"
    );
    let mut seen = BTreeSet::new();
    let mut flows = Vec::new();
    for reviewed in &review.flows {
        ensure!(
            seen.insert(&reviewed.flow_id) && reviewed.decision == "validated_exploitable",
            "VXDF : finding dupliqué, suspecté ou non validé par la revue"
        );
        let flow = original_flows
            .iter()
            .find(|flow| flow["id"].as_str() == Some(&reviewed.flow_id))
            .ok_or_else(|| invalid("VXDF : finding de revue inconnu"))?;
        ensure!(
            reviewed.binding_digest == digest(&flow["x-ladybom"])?
                && reviewed.evidence == evidence_digests(flow)?,
            "VXDF : périmètre ou preuves différents de ceux examinés"
        );
        let public = &reviewed.public;
        for text in [
            &public.title,
            &public.summary,
            &public.severity,
            &public.scenario,
            &public.observed_result,
            &public.tool_name,
            &public.tool_version,
            &public.environment,
            &public.limitations,
        ] {
            public_text(text)?;
        }
        let component = &array(flow, "affectedComponents")?[0];
        let flow_id = document_uuid(&(
            "reviewed-flow",
            &acceptance.review_digest,
            &reviewed.flow_id,
        ))?;
        let evidence_id = document_uuid(&(
            "reviewed-evidence",
            &acceptance.review_digest,
            &reviewed.flow_id,
        ))?;
        flows.push(serde_json::json!({
            "id":flow_id, "title":public.title, "description":public.summary,
            "category":"VULNERABLE_COMPONENTS", "status":"OPEN", "severity":{"level":public.severity},
            "validatedAt":review.reviewed_at,
            "affectedComponents":[{"name":string(component,"name")?,"version":string(component,"version")?,
                "purl":string(component,"purl")?,"componentType":"SOFTWARE_LIBRARY","evidenceRefs":[evidence_id]}],
            "evidence":[{"id":evidence_id,"evidenceType":"MANUAL_VERIFICATION_NOTES",
                "validationMethod":"OTHER_VALIDATION_METHOD", "description":"Operator-accepted human technical review; not cryptographically verified",
                "timestamp":review.reviewed_at,
                "data":{"verificationSteps":public.scenario,"observedOutcome":public.observed_result,
                    "toolsUsed":[format!("{} {}",public.tool_name,public.tool_version)],
                    "x-environment":public.environment,"x-limitations":public.limitations},
                "x-reviewed-evidence":reviewed.evidence}],
            "x-ladybom-binding-digest":reviewed.binding_digest
        }));
    }
    let mut exported = serde_json::json!({"vxdfVersion":"0.0.1", "generatedAt":scope.as_of,
        "generatorTool":{"name":"Ladybom","version":env!("CARGO_PKG_VERSION")},
        "exploitFlows":flows,
        "x-ladybom-review":{"trust":"human_review_assertion", "qualification":"operator_accepted_human_review",
            "cryptographically_verified":false,"schema_digest":SCHEMA_SHA256,"reviewer_digest":files::hash(review.reviewer.as_bytes()),
            "review_digest":acceptance.review_digest,"document_digest":document.document_digest,
            "report_digest":correlation.report_digest,"snapshot_digest":correlation.snapshot_digest,
            "reviewed_at":review.reviewed_at,"expires_at":review.expires_at,
            "limitation":"Human assertion only; no execution, receipt authentication or automatic VEX conversion"}
    });
    exported["id"] = Value::String(document_uuid(&exported)?);
    ensure!(
        serde_json::to_vec(&exported)?.len() <= MAX_DOCUMENT_BYTES,
        "VXDF : export supérieur à 4 Mio"
    );
    validate_schema(&exported)?;
    Ok(exported)
}
