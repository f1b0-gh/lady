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
        "Champ {field} vide, trop long ou non normalisé"
    );
    Ok(())
}
fn evidence(values: &[String]) -> Result<()> {
    ensure!(
        !values.is_empty() && values.len() <= MAX_EVIDENCE,
        "Preuves requises et bornées"
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
        "Décision future ou période de validité incohérente"
    );
    Ok(as_of < expires)
}
fn age_bound(age: u64) -> Result<()> {
    ensure!(
        (1..=MAX_AGE).contains(&age),
        "Durée de fraîcheur hors limites (1..31536000 secondes)"
    );
    Ok(())
}

pub(super) fn qualify<'a>(
    assessment: &Assessment,
    decisions: Option<&'a Decisions>,
) -> Result<BTreeMap<String, Qualification<'a>>> {
    ensure!(
        assessment.schema_version == 1,
        "Version d'analyse non prise en charge"
    );
    ensure!(
        assessment.findings.len() <= MAX_FINDINGS,
        "Trop de résultats"
    );
    age_bound(assessment.max_age_seconds)?;
    text(&assessment.report_digest, "report_digest")?;
    text(&assessment.snapshot_digest, "snapshot_digest")?;
    text(&assessment.snapshot_source, "snapshot_source")?;
    let as_of = instant(&assessment.as_of)?;
    ensure!(
        instant(&assessment.snapshot_fetched_at)? <= as_of,
        "Instantané futur"
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
            "Identifiant de résultat dupliqué"
        );
        statuses.insert(finding.id.as_str(), finding.status);
        result.insert(finding.id.clone(), Qualification { state: DecisionState::InTriage, decision: None, active: false,
            reasons: vec!["Analyse initiale in_triage ; une correspondance ne prouve pas l'exploitabilité".into()] });
    }
    if let Some(document) = decisions {
        ensure!(
            document.schema_version == 1,
            "Version des décisions non prise en charge"
        );
        ensure!(
            document.report_digest == assessment.report_digest
                && document.snapshot_digest == assessment.snapshot_digest,
            "Décisions hors du périmètre rapport/instantané"
        );
        ensure!(
            document.decisions.len() <= MAX_FINDINGS,
            "Trop de décisions"
        );
        let mut seen = BTreeSet::new();
        for decision in &document.decisions {
            text(&decision.finding_id, "finding_id")?;
            ensure!(seen.insert(&decision.finding_id), "Décision dupliquée");
            let Some(qualification) = result.get_mut(&decision.finding_id) else {
                return Err(invalid("Décision pour un résultat inconnu".into()));
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
                    "Justification VEX non reconnue"
                );
            }
            ensure!(
                decision.state != DecisionState::NotAffected || decision.justification.is_some(),
                "Justification VEX requise pour not_affected"
            );
            let is_active = active(&decision.issued_at, &decision.expires_at, as_of)?;
            qualification.decision = Some(decision);
            qualification.active = is_active;
            qualification.reasons.push(format!("Assertion documentée par {} ; détail={} ; preuves={} ; émission={} ; expiration={} ; vérification des preuves humaine", decision.author, decision.detail, serde_json::to_string(&decision.evidence)?, decision.issued_at, decision.expires_at));
            if !is_active {
                qualification
                    .reasons
                    .push("Décision expirée ; retour à in_triage".into());
                continue;
            }
            let status = statuses
                .get(decision.finding_id.as_str())
                .ok_or_else(|| invalid("Résultat absent".into()))?;
            if *status == MatchStatus::Unknown {
                qualification
                    .reasons
                    .push("Résultat inconnu : assertion sans effet sur la qualification".into());
                continue;
            }
            ensure!(decision.state != DecisionState::Resolved, "Assertion resolved contradictoire avec la correspondance actuelle ; rescanner les sources corrigées");
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
    ensure!(
        policy.schema_version == 1,
        "Version de politique non prise en charge"
    );
    age_bound(policy.max_age_seconds)?;
    ensure!(policy.exceptions.len() <= MAX_FINDINGS, "Trop d'exceptions");
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
        "Instantané source={} ; date={} ; âge={}s ; limites analyse={}s politique={}s",
        assessment.snapshot_source,
        assessment.snapshot_fetched_at,
        snapshot_age as f64 / NANOS_PER_SECOND as f64,
        assessment.max_age_seconds,
        policy.max_age_seconds
    )];
    if !complete {
        reasons.push(
            "Couverture incomplète ou données périmées : refus indépendant des exceptions".into(),
        );
    }
    reasons.extend(assessment.coverage.limitations.iter().cloned());
    let mut exceptions = BTreeMap::new();
    for exception in &policy.exceptions {
        text(&exception.finding_id, "finding_id")?;
        ensure!(
            qualifications.contains_key(&exception.finding_id),
            "Exception pour un résultat inconnu"
        );
        ensure!(
            !exceptions.contains_key(&exception.finding_id),
            "Exception dupliquée"
        );
        ensure!(
            exception.report_digest == assessment.report_digest
                && exception.snapshot_digest == assessment.snapshot_digest,
            "Exception hors du périmètre rapport/instantané"
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
        ensure!(
            signals.schema_version == 1,
            "Version de signaux non prise en charge"
        );
        text(&signals.source, "source")?;
        let fetched_at = instant(&signals.fetched_at)?;
        ensure!(fetched_at <= as_of, "Signaux futurs");
        ensure!(signals.entries.len() <= MAX_RECORDS, "Trop de signaux");
        signals_fresh = as_of - fetched_at <= SIGNAL_MAX_AGE;
        reasons.push(format!("Signaux source={} ; date={} ; fraîcheur={} ; seuil EPSS fixe=0.1 (heuristique de priorité, jamais une exemption)", signals.source, signals.fetched_at, signals_fresh));
        if !signals_fresh {
            reasons.push("Signaux explicitement fournis mais périmés : refus".into());
        }
        for signal in &signals.entries {
            text(&signal.id, "signal.id")?;
            ensure!(
                signal
                    .epss
                    .is_none_or(|score| score.is_finite() && (0.0..=1.0).contains(&score)),
                "Score EPSS invalide"
            );
            ensure!(
                signals_by_id.insert(signal.id.as_str(), signal).is_none(),
                "Signal dupliqué"
            );
        }
    }
    let mut findings = Vec::with_capacity(assessment.findings.len());
    for finding in &assessment.findings {
        let qualification = &qualifications[&finding.id];
        let mut finding_reasons = qualification.reasons.clone();
        finding_reasons.extend(finding.limitations.iter().cloned());
        if finding.status == MatchStatus::Unknown {
            finding_reasons.push("Correspondance inconnue : qualification et exception ne peuvent pas lever le refus".into());
        }
        let mut accepted_risk = false;
        if let Some((exception, is_active)) = exceptions.get(&finding.id) {
            finding_reasons.push(format!("Acceptation du risque par {} ; raison={} ; preuves={} ; émission={} ; expiration={} ; active={}", exception.author, exception.reason, serde_json::to_string(&exception.evidence)?, exception.issued_at, exception.expires_at, is_active));
            if !is_active {
                finding_reasons.push("Exception expirée ; acceptation du risque inactive".into());
            }
            accepted_risk = *is_active && finding.status == MatchStatus::Matched;
            if finding.status == MatchStatus::Unknown {
                finding_reasons.push("L'exception ne peut pas accepter un résultat inconnu".into());
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
