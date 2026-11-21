//! Version debt ratchet over verified, all-platform lock inventories.
//! A baseline is evidence of existing debt, never an approval or a CVE assessment.
use super::{
    alignment, graph_digest, Alignment, AlignmentCoverage, Graph, VersionGroup, MAX_BYTES,
};
use crate::{
    deps::invalid,
    error::{ensure, Result},
    files,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const MAX_ALIGNMENT_POLICY_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXCEPTIONS: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlignmentPolicy {
    pub schema_version: u32,
    /// Binds the reviewed reference; replacing its files cannot reset the gate.
    pub baseline_graph_digest: String,
    pub exceptions: Vec<AlignmentException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlignmentException {
    pub finding_id: String,
    pub versions: Vec<String>,
    pub owner: String,
    pub reason: String,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentChange {
    New,
    Changed,
    Unchanged,
    Reduced,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentReview {
    Required,
    Backlog,
    Accepted,
    Expired,
    Resolved,
}

#[derive(Debug, Serialize)]
pub struct AlignmentPolicyFinding {
    /// Hash of (resolution domain, unversioned PURL, normalized source).
    pub id: String,
    pub domain: String,
    pub identity: String,
    pub source: Value,
    pub name: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub change: AlignmentChange,
    pub review: AlignmentReview,
    pub exception: Option<AlignmentException>,
}

#[derive(Debug, Default, Serialize)]
pub struct AlignmentPolicySummary {
    pub baseline_duplicates: usize,
    pub current_duplicates: usize,
    /// New/changed duplicate families without an active exception.
    pub regressions: usize,
    pub unreviewed: usize,
    pub exceptions_active: usize,
    pub reduced: usize,
    pub resolved: usize,
}

#[derive(Debug, Serialize)]
pub struct AlignmentPolicyResult {
    pub schema_version: u32,
    pub baseline_graph_digest: String,
    pub graph_digest: String,
    pub policy_digest: String,
    pub as_of: String,
    pub scope: String,
    /// Complete version inventories and identical manifest/lock domains.
    pub complete: bool,
    pub non_regression_pass: bool,
    /// Every remaining split has a valid exception; does not audit pins or CVEs.
    pub reviewed_alignment_pass: bool,
    pub baseline_coverage: AlignmentCoverage,
    pub coverage: AlignmentCoverage,
    pub summary: AlignmentPolicySummary,
    pub findings: Vec<AlignmentPolicyFinding>,
    pub problems: Vec<String>,
    pub limitations: Vec<String>,
}

impl AlignmentPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_ALIGNMENT_POLICY_BYTES,
            "Politique d'alignement supérieure à 4 Mio"
        );
        // Typed structures reject duplicate fields and unknown keys at every level.
        Ok(serde_json::from_slice(bytes)?)
    }
}

fn instant(value: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| invalid("Date RFC3339 invalide dans la politique d'alignement".into()))
}

fn text(value: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 8192 && !value.chars().any(char::is_control),
        "Champ d'exception vide, trop long ou contenant des caractères de contrôle"
    );
    Ok(())
}

fn versions(group: Option<&&VersionGroup>) -> BTreeSet<String> {
    group
        .into_iter()
        .flat_map(|g| g.versions.iter().map(|v| v.version.clone()))
        .collect()
}

fn indexed(report: &Alignment) -> Result<BTreeMap<String, &VersionGroup>> {
    report
        .groups
        .iter()
        .map(|group| {
            let id = files::hash(&serde_json::to_vec(&(
                &group.domain,
                &group.identity,
                &group.source,
            ))?);
            Ok((id, group))
        })
        .collect()
}

fn scope(report: &Alignment) -> BTreeMap<&str, BTreeSet<&str>> {
    report
        .domains
        .iter()
        .map(|d| {
            (
                d.id.as_str(),
                d.manifests.iter().map(String::as_str).collect(),
            )
        })
        .collect()
}

// A source replacement must not make a duplicate appear resolved by splitting
// it across providers. Qualifiers remain evidence, not interchangeable identities.
fn providers(report: &Alignment) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    for group in &report.groups {
        let purl = group
            .identity
            .parse::<packageurl::PackageUrl>()
            .map_err(|e| invalid(format!("PURL invalide : {e}")))?;
        let key =
            serde_json::to_string(&(&group.domain, purl.ty(), purl.namespace(), purl.name()))?;
        result
            .entry(key)
            .or_default()
            .insert(serde_json::to_string(&(&group.identity, &group.source))?);
    }
    Ok(result)
}

fn exceptions<'a>(
    policy: &'a AlignmentPolicy,
    current: &BTreeMap<String, &VersionGroup>,
    as_of: OffsetDateTime,
) -> Result<BTreeMap<&'a str, (&'a AlignmentException, bool)>> {
    ensure!(
        policy.exceptions.len() <= MAX_EXCEPTIONS,
        "Trop d'exceptions d'alignement"
    );
    let mut result = BTreeMap::new();
    for exception in &policy.exceptions {
        text(&exception.finding_id)?;
        text(&exception.owner)?;
        text(&exception.reason)?;
        let issued = instant(&exception.issued_at)?;
        let expires = instant(&exception.expires_at)?;
        ensure!(
            issued <= as_of && expires > issued && expires - issued <= time::Duration::days(365),
            "Exception future ou période invalide (maximum 365 jours)"
        );
        let group = current
            .get(&exception.finding_id)
            .ok_or_else(|| invalid("Exception hors périmètre : famille absente".into()))?;
        let selected: BTreeSet<_> = exception.versions.iter().cloned().collect();
        ensure!(
            group.duplicate
                && selected.len() == exception.versions.len()
                && selected == versions(Some(group)),
            "Exception périmée : ensemble exact de versions divergent ou famille résolue"
        );
        ensure!(
            result
                .insert(exception.finding_id.as_str(), (exception, as_of < expires))
                .is_none(),
            "Exception d'alignement dupliquée"
        );
    }
    Ok(result)
}

/// Compare inventories without resolving packages or evaluating platform conditions.
/// Incomplete references are reportable but can never grant a passing result.
pub fn check_alignment_policy(
    current: &Graph,
    baseline: &Graph,
    policy: &AlignmentPolicy,
    as_of: &str,
) -> Result<AlignmentPolicyResult> {
    ensure!(
        policy.schema_version == 1,
        "Version de politique d'alignement inconnue"
    );
    let policy_bytes = serde_json::to_vec(policy)?;
    ensure!(
        policy_bytes.len() <= MAX_ALIGNMENT_POLICY_BYTES,
        "Politique d'alignement supérieure à 4 Mio"
    );
    let date = instant(as_of)?;
    let baseline_digest = graph_digest(baseline)?;
    ensure!(
        baseline_digest == policy.baseline_graph_digest,
        "Digest de référence divergent"
    );
    let before = alignment(baseline)?;
    let after = alignment(current)?;
    let mut problems = Vec::new();
    if !before.coverage.versions_complete {
        problems
            .push("baseline_incomplete: couverture des versions de référence incomplète".into());
    }
    if !after.coverage.versions_complete {
        problems.push("current_incomplete: couverture des versions courantes incomplète".into());
    }
    if scope(&before) != scope(&after) {
        problems.push(
            "scope_changed: périmètre des manifests/verrous différent ; revue de référence requise"
                .into(),
        );
    }
    let complete = problems.is_empty();
    let previous_providers = providers(&before)?;
    for (key, selected) in providers(&after)? {
        if previous_providers
            .get(&key)
            .is_some_and(|old| !selected.is_subset(old))
        {
            problems.push(format!(
                "source_changed: nouveau fournisseur pour {key} ; revue de référence requise"
            ));
        }
    }
    let old = indexed(&before)?;
    let new = indexed(&after)?;
    let exceptions = exceptions(policy, &new, date)?;
    let ids: BTreeSet<_> = old
        .iter()
        .chain(&new)
        .filter(|(_, g)| g.duplicate)
        .map(|(id, _)| id)
        .collect();
    let mut summary = AlignmentPolicySummary {
        baseline_duplicates: old.values().filter(|g| g.duplicate).count(),
        current_duplicates: new.values().filter(|g| g.duplicate).count(),
        ..Default::default()
    };
    let mut findings = Vec::with_capacity(ids.len());
    for id in ids {
        let previous = old.get(id);
        let next = new.get(id);
        let group = next
            .or(previous)
            .ok_or_else(|| invalid("Famille d'alignement absente".into()))?;
        let previous_versions = versions(previous);
        let next_versions = versions(next);
        let change = if next_versions.len() < 2 {
            AlignmentChange::Resolved
        } else if previous_versions.len() < 2 {
            AlignmentChange::New
        } else if previous_versions == next_versions {
            AlignmentChange::Unchanged
        } else if next_versions.is_subset(&previous_versions) {
            AlignmentChange::Reduced
        } else {
            AlignmentChange::Changed
        };
        let regression = matches!(change, AlignmentChange::New | AlignmentChange::Changed);
        let (review, exception) = if let Some((exception, active)) = exceptions.get(id.as_str()) {
            if *active {
                summary.exceptions_active += 1;
                (AlignmentReview::Accepted, Some((*exception).clone()))
            } else {
                problems.push(format!("exception_expired: {id}"));
                (AlignmentReview::Expired, Some((*exception).clone()))
            }
        } else if change == AlignmentChange::Resolved {
            (AlignmentReview::Resolved, None)
        } else if regression {
            (AlignmentReview::Required, None)
        } else {
            (AlignmentReview::Backlog, None)
        };
        if regression && review != AlignmentReview::Accepted {
            summary.regressions += 1;
        }
        if next_versions.len() > 1 && review != AlignmentReview::Accepted {
            summary.unreviewed += 1;
        }
        if change == AlignmentChange::Resolved {
            summary.resolved += 1;
        }
        if change == AlignmentChange::Reduced {
            summary.reduced += 1;
        }
        findings.push(AlignmentPolicyFinding {
            id: id.clone(),
            domain: group.domain.clone(),
            identity: group.identity.clone(),
            source: group.source.clone(),
            name: group.name.clone(),
            before: previous_versions.into_iter().collect(),
            after: next_versions.into_iter().collect(),
            change,
            review,
            exception,
        });
    }
    let non_regression_pass = complete && problems.is_empty() && summary.regressions == 0;
    let report = AlignmentPolicyResult {
        schema_version: 1, baseline_graph_digest: baseline_digest, graph_digest: graph_digest(current)?,
        policy_digest: files::hash(&policy_bytes), as_of: as_of.into(), scope: "all_locked_versions".into(),
        complete, non_regression_pass,
        reviewed_alignment_pass: non_regression_pass && summary.unreviewed == 0,
        baseline_coverage: before.coverage, coverage: after.coverage,
        summary, findings, problems,
        limitations: vec![
            "Une référence constate une dette ; elle ne l'approuve pas. Renouveler la référence nécessite une revue explicite.".into(),
            "Toutes les plateformes du verrou sont inventoriées ; l'activation des features, cibles et profils n'est pas évaluée.".into(),
            "Cette politique contrôle les divergences de versions. Les pins/concordances restent contrôlés par graph alignment --check ; les CVE demandent un audit distinct.".into(),
            "Une exception consigne une décision humaine, sans établir sa justesse, la compatibilité ni la sécurité.".into(),
        ],
    };
    ensure!(
        serde_json::to_vec(&report)?.len() <= MAX_BYTES,
        "Rapport de politique supérieur à 128 Mio"
    );
    Ok(report)
}
