use super::{
    digest, instant, osv, Assessment, Coverage, Finding, MatchStatus, Snapshot, MAX_FINDINGS,
    MAX_INPUT_BYTES, MAX_RECORDS,
};
use crate::{
    deps::{cyclonedx, invalid, Component, Project, Report},
    error::{ensure, Result},
};
use packageurl::PackageUrl;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

/// Assess a static inventory against an explicit, immutable OSV snapshot.
/// `complete` concerns lookup coverage only, never exploitability or absence of risk.
pub fn assess(
    report: &Report,
    snapshot: &Snapshot,
    as_of: &str,
    max_age_seconds: u64,
) -> Result<Assessment> {
    report.validate()?;
    osv::validate_snapshot(snapshot)?;
    ensure!(
        (1..=31_536_000).contains(&max_age_seconds),
        "Âge maximal des avis hors limites"
    );
    ensure!(
        serde_json::to_vec(report)?.len() <= MAX_INPUT_BYTES,
        "Rapport de vulnérabilités trop volumineux"
    );
    let now = instant(as_of)?;
    let fetched = instant(&snapshot.fetched_at)?;
    ensure!(fetched <= now, "Instantané OSV daté dans le futur");
    let mut coverage = Coverage {
        inventory_complete: report.complete && !report.projects.is_empty(),
        advisories_complete: snapshot.complete,
        identities_complete: true,
        matching_complete: true,
        fresh: now - fetched <= time::Duration::seconds(max_age_seconds as i64),
        components: 0,
        assessed_components: 0,
        withdrawn_advisories: 0,
        limitations: Vec::new(),
    };
    if !coverage.inventory_complete {
        coverage
            .limitations
            .push("Inventaire vide ou analyse statique partielle".into());
    }
    if !snapshot.complete {
        coverage
            .limitations
            .push("La complétude de l’instantané OSV n’est pas déclarée".into());
    }
    if !coverage.fresh {
        coverage.limitations.push("Instantané OSV périmé".into());
    }

    let groups = alias_groups(&snapshot.advisories)?;
    let record_sizes = snapshot
        .advisories
        .iter()
        .map(|r| serde_json::to_vec(r).map(|b| b.len()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut index: BTreeMap<(String, String), BTreeSet<usize>> = BTreeMap::new();
    for (i, record) in snapshot.advisories.iter().enumerate() {
        if record.get("withdrawn").is_some() {
            coverage.withdrawn_advisories += 1;
            continue;
        }
        let keys = osv::index_keys(record);
        if keys.is_empty() {
            coverage.matching_complete = false;
            coverage.limitations.push(format!(
                "{} : avis actif sans paquet identifiable ; applicabilité inconnue",
                record["id"].as_str().unwrap_or_default()
            ));
        }
        for key in keys {
            index.entry(key).or_default().insert(i);
        }
    }
    let mut findings: BTreeMap<(String, String), Finding> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut comparisons = 0usize;
    let mut compared_bytes = 0usize;
    let mut retained_bytes = 0usize;
    for project in &report.projects {
        if !project.locked && !project.requirements.is_empty() {
            coverage.inventory_complete = false;
            coverage.limitations.push(format!(
                "{} : exigences sans verrou pris en charge",
                project.manifest
            ));
        }
        if project.components_from.is_some() {
            continue;
        }
        for component in &project.components {
            let reference = cyclonedx::component_reference(project, component)?;
            if !seen.insert(reference.clone()) {
                continue;
            }
            coverage.components += 1;
            ensure!(
                coverage.components <= MAX_RECORDS,
                "Trop de composants à analyser"
            );
            let Some((ecosystem, name)) = public_identity(project, component) else {
                coverage.identities_complete = false;
                coverage.limitations.push(format!(
                    "{reference} : identité publique non vérifiée ({}, {}, {})",
                    project.manifest, component.name, component.context
                ));
                continue;
            };
            if !snapshot.ecosystems.iter().any(|e| e == ecosystem) {
                coverage.advisories_complete = false;
                coverage.limitations.push(format!(
                    "{reference} : écosystème {ecosystem} absent de l’instantané"
                ));
                continue;
            }
            coverage.assessed_components += 1;
            let mut candidates = index
                .get(&(ecosystem.into(), name.clone()))
                .cloned()
                .unwrap_or_default();
            if let Some(wildcards) = index.get(&(ecosystem.into(), "*".into())) {
                candidates.extend(wildcards);
            }
            for i in candidates {
                comparisons += 1;
                ensure!(
                    comparisons <= 1_000_000,
                    "Limite de comparaisons OSV dépassée"
                );
                compared_bytes = compared_bytes.saturating_add(record_sizes[i]);
                ensure!(
                    compared_bytes <= 8 * MAX_INPUT_BYTES,
                    "Budget de comparaison OSV dépassé"
                );
                let record = &snapshot.advisories[i];
                let matched = osv::match_record(record, ecosystem, &name, &component.version)?;
                let Some(status) = matched.status else {
                    continue;
                };
                if status == MatchStatus::Unknown || !matched.limitations.is_empty() {
                    coverage.matching_complete = false;
                }
                let id = record["id"]
                    .as_str()
                    .ok_or_else(|| invalid("Identifiant OSV absent".into()))?;
                let (canonical, aliases) = groups
                    .get(id)
                    .ok_or_else(|| invalid("Groupe d’alias OSV absent".into()))?;
                let key = (reference.clone(), canonical.clone());
                retained_bytes = retained_bytes.saturating_add(record_sizes[i]);
                if !findings.contains_key(&key) {
                    retained_bytes = retained_bytes
                        .saturating_add(aliases.iter().map(String::len).sum::<usize>());
                }
                ensure!(
                    retained_bytes <= MAX_INPUT_BYTES,
                    "Preuves OSV trop volumineuses"
                );
                let finding = findings.entry(key).or_insert_with(|| Finding {
                    id: String::new(),
                    component_ref: reference.clone(),
                    purl: component.purl.clone(),
                    ecosystem: ecosystem.into(),
                    name: component.name.clone(),
                    version: component.version.clone(),
                    manifest: project.manifest.clone(),
                    lockfile: project.lockfile.clone(),
                    context: component.context.clone(),
                    status,
                    advisory_ids: Vec::new(),
                    aliases: aliases.as_ref().clone(),
                    fixed_versions: Vec::new(),
                    evidence: Vec::new(),
                    limitations: Vec::new(),
                });
                if status == MatchStatus::Matched {
                    finding.status = status;
                }
                finding.advisory_ids.push(id.into());
                finding.fixed_versions.extend(matched.fixed_versions);
                finding.evidence.push(record.clone());
                finding.limitations.extend(matched.limitations);
                ensure!(
                    findings.len() <= MAX_FINDINGS,
                    "Trop de correspondances OSV"
                );
            }
        }
    }
    if coverage.components == 0 {
        coverage.inventory_complete = false;
        coverage
            .limitations
            .push("Aucun composant verrouillé à évaluer".into());
    }
    let mut findings = findings
        .into_iter()
        .map(|((component, alias), mut finding)| {
            finding.id = format!("findings/{}", digest(&(component, alias))?);
            finding.advisory_ids.sort();
            finding.advisory_ids.dedup();
            finding.fixed_versions.sort();
            finding.fixed_versions.dedup();
            finding
                .evidence
                .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
            finding.limitations.sort();
            finding.limitations.dedup();
            Ok(finding)
        })
        .collect::<Result<Vec<_>>>()?;
    findings.sort_by(|a, b| a.id.cmp(&b.id));
    coverage.limitations.sort();
    coverage.limitations.dedup();
    let assessment = Assessment {
        schema_version: 1,
        report_digest: digest(report)?,
        snapshot_digest: digest(snapshot)?,
        sbom_serial: cyclonedx::document_serial(report)?,
        as_of: as_of.into(),
        snapshot_fetched_at: snapshot.fetched_at.clone(),
        snapshot_source: snapshot.source.clone(),
        max_age_seconds,
        complete: coverage.inventory_complete
            && coverage.advisories_complete
            && coverage.identities_complete
            && coverage.matching_complete
            && coverage.fresh,
        coverage,
        findings,
    };
    ensure!(
        serde_json::to_vec(&assessment)?.len() <= MAX_INPUT_BYTES,
        "Analyse de vulnérabilités trop volumineuse"
    );
    Ok(assessment)
}

pub(crate) fn public_identity(
    project: &Project,
    component: &Component,
) -> Option<(&'static str, String)> {
    let (ecosystem, ty, trusted) = match project.ecosystem.as_str() {
        "rust" => (
            "crates.io",
            "cargo",
            component.source.as_str()
                == Some("registry+https://github.com/rust-lang/crates.io-index"),
        ),
        "npm" => (
            "npm",
            "npm",
            component
                .source
                .as_str()
                .is_some_and(|s| s.starts_with("https://registry.npmjs.org/")),
        ),
        "python" => (
            "PyPI",
            "pypi",
            !crate::deps::python::local::is_local(project, component)
                && component
                    .source
                    .as_object()
                    .filter(|source| source.len() == 1)
                    .and_then(|source| source.get("registry"))
                    .and_then(Value::as_str)
                    .is_some_and(|s| {
                        matches!(s, "https://pypi.org/simple" | "https://pypi.org/simple/")
                    }),
        ),
        _ => return None,
    };
    if !trusted || !osv::supported_version(ecosystem, &component.version) {
        return None;
    }
    let purl = PackageUrl::from_str(component.purl.as_deref()?).ok()?;
    if purl.ty() != ty
        || purl.version() != Some(component.version.as_str())
        || !purl.qualifiers().is_empty()
        || purl.subpath().is_some()
    {
        return None;
    }
    let purl_name = purl.namespace().map_or_else(
        || purl.name().to_string(),
        |ns| format!("{ns}/{}", purl.name()),
    );
    let name = osv::normalize_package(ecosystem, &component.name);
    if name != osv::normalize_package(ecosystem, &purl_name) {
        return None;
    }
    Some((ecosystem, name))
}

type AliasGroups = BTreeMap<String, (String, Arc<Vec<String>>)>;

fn alias_groups(records: &[Value]) -> Result<AliasGroups> {
    let mut parents = BTreeMap::<String, String>::new();
    for record in records {
        if record.get("withdrawn").is_some() {
            continue;
        }
        let id = record["id"]
            .as_str()
            .ok_or_else(|| invalid("Identifiant OSV absent".into()))?;
        parents.entry(id.into()).or_insert_with(|| id.into());
        for alias in record["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            parents.entry(alias.into()).or_insert_with(|| alias.into());
            let left = root(&mut parents, id);
            let right = root(&mut parents, alias);
            let (small, big) = if left < right {
                (left, right)
            } else {
                (right, left)
            };
            parents.insert(big, small);
            ensure!(parents.len() <= 500_000, "Trop d’alias OSV");
        }
    }
    let mut groups = BTreeMap::<String, Vec<String>>::new();
    let keys: Vec<_> = parents.keys().cloned().collect();
    for id in keys {
        groups.entry(root(&mut parents, &id)).or_default().push(id);
    }
    let mut result = BTreeMap::new();
    for (canonical, ids) in groups {
        let shared = Arc::new(ids);
        for id in shared.iter() {
            result.insert(id.clone(), (canonical.clone(), shared.clone()));
        }
    }
    Ok(result)
}

fn root(parents: &mut BTreeMap<String, String>, id: &str) -> String {
    let mut current = id.to_owned();
    let mut path = Vec::new();
    while let Some(parent) = parents.get(&current) {
        if parent == &current {
            break;
        }
        path.push(current.clone());
        current = parent.clone();
    }
    for ancestor in path {
        parents.insert(ancestor, current.clone());
    }
    current
}
