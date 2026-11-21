//! Local, fail-closed qualification. Evidence references document a human review;
//! their truth is not established by this policy evaluator.
use super::{
    Assessment, Decision, DecisionState, Decisions, FindingDecision, MatchStatus, Policy,
    PolicyResult, Signals, MAX_FINDINGS, MAX_RECORDS,
};
use crate::{
    deps::invalid,
    error::{ensure, Result},
};
use cyclonedx_bom::models::vulnerability_analysis::{
    validate_impact_analysis_justification, ImpactAnalysisJustification,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_TEXT: usize = 8192;
const MAX_EVIDENCE: usize = 128;
const MAX_AGE: u64 = 31_536_000;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SIGNAL_MAX_AGE: i128 = 86_400 * NANOS_PER_SECOND;

pub(super) struct Qualification<'a> {
    pub state: DecisionState,
    pub decision: Option<&'a Decision>,
    pub active: bool,
    pub reasons: Vec<String>,
}

fn text(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= MAX_TEXT && !value.contains(['\r', '\n', '\t']),
        "Field {field} is empty, too long or not normalized"
    );
    Ok(())
}
fn evidence(values: &[String]) -> Result<()> {
    ensure!(
        !values.is_empty() && values.len() <= MAX_EVIDENCE,
        "Evidence is required and must be bounded"
    );
    for value in values {
        text(value, "evidence")?;
    }
    Ok(())
}
fn instant(value: &str) -> Result<i128> {
    Ok(super::instant(value)?.unix_timestamp_nanos())
}

fn active(issued: &str, expires: &str, as_of: i128) -> Result<bool> {
    let issued = instant(issued)?;
    let expires = instant(expires)?;
    ensure!(
        issued <= as_of && expires > issued,
        "Decision is dated in the future or has an inconsistent validity period"
    );
    Ok(as_of < expires)
}
fn age_bound(age: u64) -> Result<()> {
    ensure!(
        (1..=MAX_AGE).contains(&age),
        "Freshness duration out of bounds (1..31536000 seconds)"
    );
    Ok(())
}

pub(super) fn qualify<'a>(
    assessment: &Assessment,
    decisions: Option<&'a Decisions>,
) -> Result<BTreeMap<String, Qualification<'a>>> {
    ensure!(
        assessment.schema_version == 1,
        "Unsupported assessment version"
    );
    ensure!(
        assessment.findings.len() <= MAX_FINDINGS,
        "Too many results"
    );
    age_bound(assessment.max_age_seconds)?;
    text(&assessment.report_digest, "report_digest")?;
    text(&assessment.snapshot_digest, "snapshot_digest")?;
    text(&assessment.snapshot_source, "snapshot_source")?;
    let as_of = instant(&assessment.as_of)?;
    ensure!(
        instant(&assessment.snapshot_fetched_at)? <= as_of,
        "Snapshot is dated in the future"
    );
    let mut result = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    for finding in &assessment.findings {
        text(&finding.id, "finding_id")?;
        text(&finding.component_ref, "component_ref")?;
        for id in finding.advisory_ids.iter().chain(&finding.aliases) {
            text(id, "advisory_id")?;
        }
        ensure!(
            !result.contains_key(&finding.id),
            "Duplicate result identifier"
        );
        statuses.insert(finding.id.as_str(), finding.status);
        result.insert(
            finding.id.clone(),
            Qualification {
                state: DecisionState::InTriage,
                decision: None,
                active: false,
                reasons: vec![
                    "Initial assessment is in_triage; a match does not establish exploitability"
                        .into(),
                ],
            },
        );
    }
    if let Some(document) = decisions {
        ensure!(
            document.schema_version == 1,
            "Unsupported decisions version"
        );
        ensure!(
            document.report_digest == assessment.report_digest
                && document.snapshot_digest == assessment.snapshot_digest,
            "Decisions outside the report/snapshot scope"
        );
        ensure!(
            document.decisions.len() <= MAX_FINDINGS,
            "Too many decisions"
        );
        let mut seen = BTreeSet::new();
        for decision in &document.decisions {
            text(&decision.finding_id, "finding_id")?;
            ensure!(seen.insert(&decision.finding_id), "Duplicate decision");
            let Some(qualification) = result.get_mut(&decision.finding_id) else {
                return Err(invalid("Decision for an unknown result".into()));
            };
            text(&decision.author, "author")?;
            text(&decision.detail, "detail")?;
            evidence(&decision.evidence)?;
            if let Some(justification) = &decision.justification {
                text(justification, "justification")?;
                ensure!(
                    validate_impact_analysis_justification(
                        &ImpactAnalysisJustification::new_unchecked(justification)
                    )
                    .is_ok(),
                    "Unrecognized VEX justification"
                );
            }
            ensure!(
                decision.state != DecisionState::NotAffected || decision.justification.is_some(),
                "VEX justification required for not_affected"
            );
            let is_active = active(&decision.issued_at, &decision.expires_at, as_of)?;
            qualification.decision = Some(decision);
            qualification.active = is_active;
            qualification.reasons.push(format!("Assertion documented by {}; detail={}; evidence={}; issued={}; expires={}; evidence verification is human", decision.author, decision.detail, serde_json::to_string(&decision.evidence)?, decision.issued_at, decision.expires_at));
            if !is_active {
                qualification
                    .reasons
                    .push("Expired decision; reverting to in_triage".into());
                continue;
            }
            let status = statuses
                .get(decision.finding_id.as_str())
                .ok_or_else(|| invalid("Missing result".into()))?;
            if *status == MatchStatus::Unknown {
                qualification
                    .reasons
                    .push("Unknown result: assertion has no effect on qualification".into());
                continue;
            }
            ensure!(decision.state != DecisionState::Resolved, "The resolved assertion contradicts the current match; rescan the corrected sources");
            qualification.state = decision.state;
        }
    }
    Ok(result)
}

/// Evaluate at the assessment's explicit date. A policy can tighten freshness but
/// cannot relax the freshness limit used to produce the assessment.
pub fn evaluate(
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    policy: &Policy,
    signals: Option<&Signals>,
) -> Result<PolicyResult> {
    let qualifications = qualify(assessment, decisions)?;
    ensure!(policy.schema_version == 1, "Unsupported policy version");
    age_bound(policy.max_age_seconds)?;
    ensure!(
        policy.exceptions.len() <= MAX_FINDINGS,
        "Too many exceptions"
    );
    let as_of = instant(&assessment.as_of)?;
    let snapshot_age = as_of - instant(&assessment.snapshot_fetched_at)?;
    let fresh = assessment.coverage.fresh
        && snapshot_age
            <= i128::from(policy.max_age_seconds.min(assessment.max_age_seconds))
                * NANOS_PER_SECOND;
    let complete = assessment.complete
        && assessment.coverage.inventory_complete
        && assessment.coverage.advisories_complete
        && assessment.coverage.identities_complete
        && assessment.coverage.matching_complete
        && assessment.coverage.assessed_components == assessment.coverage.components
        && assessment
            .findings
            .iter()
            .all(|f| f.status == MatchStatus::Matched)
        && fresh;
    let mut reasons = vec![format!(
        "Snapshot source={}; date={}; age={}s; limits: assessment={}s policy={}s",
        assessment.snapshot_source,
        assessment.snapshot_fetched_at,
        snapshot_age as f64 / NANOS_PER_SECOND as f64,
        assessment.max_age_seconds,
        policy.max_age_seconds
    )];
    if !complete {
        reasons.push("Incomplete coverage or stale data: refused regardless of exceptions".into());
    }
    reasons.extend(assessment.coverage.limitations.iter().cloned());
    let mut exceptions = BTreeMap::new();
    for exception in &policy.exceptions {
        text(&exception.finding_id, "finding_id")?;
        ensure!(
            qualifications.contains_key(&exception.finding_id),
            "Exception for an unknown result"
        );
        ensure!(
            !exceptions.contains_key(&exception.finding_id),
            "Duplicate exception"
        );
        ensure!(
            exception.report_digest == assessment.report_digest
                && exception.snapshot_digest == assessment.snapshot_digest,
            "Exception outside the report/snapshot scope"
        );
        text(&exception.author, "author")?;
        text(&exception.reason, "reason")?;
        evidence(&exception.evidence)?;
        let is_active = active(&exception.issued_at, &exception.expires_at, as_of)?;
        exceptions.insert(exception.finding_id.clone(), (exception, is_active));
    }
    let mut signals_by_id = BTreeMap::new();
    let mut signals_fresh = true;
    if let Some(signals) = signals {
        ensure!(signals.schema_version == 1, "Unsupported signals version");
        text(&signals.source, "source")?;
        let fetched_at = instant(&signals.fetched_at)?;
        ensure!(fetched_at <= as_of, "Signaux futurs");
        ensure!(signals.entries.len() <= MAX_RECORDS, "Too many signals");
        signals_fresh = as_of - fetched_at <= SIGNAL_MAX_AGE;
        reasons.push(format!("Signals source={}; date={}; fresh={}; fixed EPSS threshold=0.1 (a priority heuristic, never an exemption)", signals.source, signals.fetched_at, signals_fresh));
        if !signals_fresh {
            reasons.push("Explicitly supplied signals are stale: refused".into());
        }
        for signal in &signals.entries {
            text(&signal.id, "signal.id")?;
            ensure!(
                signal
                    .epss
                    .is_none_or(|score| score.is_finite() && (0.0..=1.0).contains(&score)),
                "Invalid EPSS score"
            );
            ensure!(
                signals_by_id.insert(signal.id.as_str(), signal).is_none(),
                "Duplicate signal"
            );
        }
    }
    let mut findings = Vec::with_capacity(assessment.findings.len());
    for finding in &assessment.findings {
        let qualification = &qualifications[&finding.id];
        let mut finding_reasons = qualification.reasons.clone();
        finding_reasons.extend(finding.limitations.iter().cloned());
        if finding.status == MatchStatus::Unknown {
            finding_reasons.push(
                "Unknown match: qualification and exceptions cannot override the refusal".into(),
            );
        }
        let mut accepted_risk = false;
        if let Some((exception, is_active)) = exceptions.get(&finding.id) {
            finding_reasons.push(format!(
                "Risk accepted by {}; reason={}; evidence={}; issued={}; expires={}; active={}",
                exception.author,
                exception.reason,
                serde_json::to_string(&exception.evidence)?,
                exception.issued_at,
                exception.expires_at,
                is_active
            ));
            if !is_active {
                finding_reasons.push("Expired exception; risk acceptance is inactive".into());
            }
            accepted_risk = *is_active && finding.status == MatchStatus::Matched;
            if finding.status == MatchStatus::Unknown {
                finding_reasons.push("The exception cannot accept an unknown result".into());
            }
        }
        let matching_signals: Vec<_> = std::iter::once(&finding.id)
            .chain(&finding.advisory_ids)
            .chain(&finding.aliases)
            .filter_map(|id| signals_by_id.get(id.as_str()).copied())
            .collect();
        for signal in &matching_signals {
            finding_reasons.push(format!(
                "Signal {} : known_exploited={} ; epss={:?}",
                signal.id, signal.known_exploited, signal.epss
            ));
        }
        let priority = if matching_signals.iter().any(|s| s.known_exploited) {
            "known_exploited"
        } else if qualification.state == DecisionState::Exploitable {
            "exploitable"
        } else if matching_signals
            .iter()
            .any(|s| s.epss.is_some_and(|score| score >= 0.1))
        {
            "high_epss"
        } else {
            "review"
        };
        let blocking = finding.status == MatchStatus::Unknown
            || (!accepted_risk
                && !matches!(
                    qualification.state,
                    DecisionState::NotAffected | DecisionState::FalsePositive
                ));
        findings.push(FindingDecision {
            finding_id: finding.id.clone(),
            state: qualification.state,
            priority: priority.into(),
            accepted_risk,
            blocking,
            reasons: finding_reasons,
        });
    }
    Ok(PolicyResult {
        schema_version: 1,
        report_digest: assessment.report_digest.clone(),
        snapshot_digest: assessment.snapshot_digest.clone(),
        as_of: assessment.as_of.clone(),
        allowed: complete && signals_fresh && findings.iter().all(|f| !f.blocking),
        complete,
        findings,
        reasons,
    })
}
