//! Static locked-version alignment, independent of conditional build activation.
mod pins;
pub use pins::{PinFinding, PinStatus};

use super::{Graph, NodeRef, MAX_BYTES, MAX_COMPONENTS, MAX_EDGES};
use crate::{
    deps::{invalid, Component, Project},
    error::{ensure, Result},
    files,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct Alignment {
    pub schema_version: u32,
    pub aligned: Option<bool>,
    pub pins_compliant: Option<bool>,
    /// Whether all exact declarations have distinct matching projected roots.
    pub pin_lock_consistent: Option<bool>,
    pub coverage: AlignmentCoverage,
    pub domains: Vec<ResolutionDomain>,
    pub groups: Vec<VersionGroup>,
    pub cross_domain: Vec<CrossDomainDifference>,
    pub source_variants: Vec<SourceVariants>,
    pub pins: Vec<PinFinding>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct AlignmentCoverage {
    /// Nonempty, fully parsed inventory in every lock domain; stricter than Report::complete.
    pub inventory_complete: bool,
    pub versions_complete: bool,
    pub pin_audit_complete: bool,
    pub activation_known: bool,
    pub inventory_components: usize,
    pub projected_components: usize,
    pub unidentified_components: usize,
    pub unprojected_components: usize,
    pub unmapped_nodes: usize,
}

#[derive(Debug, Serialize)]
pub struct ResolutionDomain {
    pub id: String,
    pub ecosystem: String,
    pub lockfile: Option<String>,
    pub manifests: Vec<String>,
    pub graphs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VersionGroup {
    pub domain: String,
    /// Canonical PURL with only its version removed.
    pub identity: String,
    pub source: Value,
    pub name: String,
    pub versions: Vec<VersionOccurrences>,
    pub duplicate: bool,
}

#[derive(Debug, Serialize)]
pub struct VersionOccurrences {
    pub version: String,
    pub nodes: Vec<NodeRef>,
}

#[derive(Debug, Serialize)]
pub struct CrossDomainDifference {
    pub identity: String,
    pub source: Value,
    pub domains: Vec<DomainVersions>,
}

#[derive(Debug, Serialize)]
pub struct DomainVersions {
    pub domain: String,
    pub versions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SourceVariants {
    pub domain: String,
    pub name: String,
    pub identities: Vec<String>,
    pub sources: Vec<SourceEvidence>,
}

#[derive(Debug, Serialize)]
pub struct SourceEvidence {
    pub identity: Option<String>,
    pub version: String,
    pub source: Value,
    pub context: String,
}

pub fn alignment(graph: &Graph) -> Result<Alignment> {
    graph.validate()?;
    let component_count = graph
        .inventory
        .projects
        .iter()
        .try_fold(0usize, |count, p| {
            count
                .checked_add(p.components.len())
                .ok_or_else(|| invalid("Limite de composants dépassée".into()))
        })?;
    let requirement_count = graph
        .inventory
        .projects
        .iter()
        .try_fold(0usize, |count, p| {
            count
                .checked_add(p.requirements.len())
                .ok_or_else(|| invalid("Limite de déclarations dépassée".into()))
        })?;
    ensure!(
        component_count <= MAX_COMPONENTS,
        "Limite de composants dépassée"
    );
    ensure!(
        requirement_count <= MAX_EDGES,
        "Limite de déclarations dépassée"
    );

    let locals = crate::deps::npm::local::LocalPackages::new(&graph.inventory);
    let python_locals = crate::deps::python::local::LocalPackages::new(&graph.inventory);
    let mut domains = BTreeMap::<String, ResolutionDomain>::new();
    let mut manifest_domains = BTreeMap::<String, Option<String>>::new();
    let mut project_domains = BTreeMap::new();
    for project in &graph.inventory.projects {
        // Unlocked projects remain separate unknown domains. A shared lock has
        // one stable identity, independently of its owning member manifest.
        let key = serde_json::to_vec(&(
            &project.ecosystem,
            &project.lockfile,
            project.lockfile.is_none().then_some(&project.manifest),
        ))?;
        let id = format!("domains/{}", files::hash(&key));
        let domain = domains
            .entry(id.clone())
            .or_insert_with(|| ResolutionDomain {
                id: id.clone(),
                ecosystem: project.ecosystem.clone(),
                lockfile: project.lockfile.clone(),
                manifests: Vec::new(),
                graphs: Vec::new(),
            });
        domain.manifests.push(project.manifest.clone());
        register_manifest(&mut manifest_domains, project.manifest.clone(), &id);
        if let Some(manifest) = lock_manifest(project) {
            register_manifest(&mut manifest_domains, manifest, &id);
        }
        project_domains.insert(project.manifest.as_str(), id);
    }
    let mut context_domains = BTreeMap::new();
    for (path, context) in &graph.contexts {
        if let Some(Some(domain)) = manifest_domains.get(&context.manifest) {
            context_domains.insert(path.as_str(), domain.as_str());
            if let Some(resolution) = domains.get_mut(domain) {
                resolution.graphs.push(path.clone());
            }
        }
    }
    for domain in domains.values_mut() {
        domain.manifests.sort();
        domain.manifests.dedup();
    }

    // Index the original evidence once, rather than scanning every inventory for
    // every projected occurrence or cloning shared-lock inventories per member.
    let mut records = Vec::with_capacity(component_count);
    let mut evidence_index = BTreeMap::<(String, String), Option<usize>>::new();
    for project in &graph.inventory.projects {
        let domain = project_domains
            .get(project.manifest.as_str())
            .ok_or_else(|| invalid("Domaine du projet absent".into()))?;
        for component in &project.components {
            let purl = if project.ecosystem == "npm" && crate::deps::npm::local::is_local(component)
            {
                locals
                    .qualified(project, component)
                    .map(|identity| identity.purl())
                    .transpose()?
            } else if project.ecosystem == "python"
                && crate::deps::python::local::is_local(project, component)
            {
                python_locals
                    .qualified(project, component)
                    .map(|identity| identity.purl())
                    .transpose()?
            } else {
                projected_purl(project, component)?
            };
            let identity = purl
                .as_deref()
                .map(|p| package_identity(p, component))
                .transpose()?;
            let evidence = component_evidence(component, purl.as_deref())?;
            let index = records.len();
            // Duplicate, indistinguishable evidence cannot establish which
            // inventory occurrence was projected.
            evidence_index
                .entry((domain.clone(), evidence))
                .and_modify(|previous| *previous = None)
                .or_insert(Some(index));
            records.push(InventoryOccurrence {
                domain: domain.clone(),
                component,
                identity,
                source: locals
                    .qualified(project, component)
                    .map(|identity| identity.source())
                    .or_else(|| {
                        python_locals
                            .qualified(project, component)
                            .map(|identity| identity.source())
                    })
                    .unwrap_or_else(|| {
                        normalized_source(
                            &project.ecosystem,
                            &component.name,
                            &component.version,
                            &component.source,
                        )
                    }),
                nodes: BTreeSet::new(),
            });
        }
    }
    let mut unmapped_nodes = 0;
    for node in &graph.components {
        package_identity(&node.key.purl, &node.component)?;
        let matched = if let Some(domain) = context_domains.get(node.key.graph.as_str()) {
            let evidence = component_evidence(&node.component, node.component.purl.as_deref())?;
            evidence_index
                .get(&(String::from(*domain), evidence))
                .copied()
                .flatten()
        } else {
            None
        };
        if let Some(index) = matched {
            records[index].nodes.insert(node.key.clone());
        } else {
            unmapped_nodes += 1;
        }
    }
    let projected_components = records.iter().filter(|r| !r.nodes.is_empty()).count();
    let unidentified_components = records.iter().filter(|r| r.identity.is_none()).count();
    let supported = graph
        .inventory
        .projects
        .iter()
        .all(|p| matches!(p.ecosystem.as_str(), "rust" | "npm" | "python"));
    let empty_domains = graph
        .inventory
        .projects
        .iter()
        .filter(|p| p.components_from.is_none() && p.components.is_empty())
        .count();
    let inventory_complete = graph.inventory.complete
        && !graph.inventory.projects.is_empty()
        && component_count > 0
        && empty_domains == 0
        && graph.inventory.projects.iter().all(|p| p.locked);
    let versions_complete = inventory_complete
        && supported
        && unidentified_components == 0
        && projected_components == component_count
        && unmapped_nodes == 0;
    let activation_known = versions_complete
        && graph.complete()
        && !graph
            .inventory
            .projects
            .iter()
            .any(|p| p.ecosystem == "rust");

    let mut grouped = BTreeMap::<(String, String, String), GroupBuilder>::new();
    let mut named = BTreeMap::<(String, String), Vec<usize>>::new();
    for (index, record) in records.iter().enumerate() {
        named
            .entry((record.domain.clone(), record.component.name.clone()))
            .or_default()
            .push(index);
        let Some(identity) = &record.identity else {
            continue;
        };
        let source_key = serde_json::to_string(&record.source)?;
        let group = grouped
            .entry((record.domain.clone(), identity.clone(), source_key))
            .or_insert_with(|| GroupBuilder {
                name: record.component.name.clone(),
                source: record.source.clone(),
                versions: BTreeMap::new(),
            });
        // The public label remains deterministic even for equivalent PURLs
        // carrying differently spelled native package names.
        if record.component.name < group.name {
            group.name.clone_from(&record.component.name);
        }
        group
            .versions
            .entry(record.component.version.clone())
            .or_default()
            .extend(record.nodes.iter().cloned());
    }
    let groups: Vec<_> = grouped
        .into_iter()
        .map(|((domain, identity, _), group)| VersionGroup {
            domain,
            identity,
            source: group.source,
            name: group.name,
            duplicate: group.versions.len() > 1,
            versions: group
                .versions
                .into_iter()
                .map(|(version, nodes)| VersionOccurrences {
                    version,
                    nodes: nodes.into_iter().collect(),
                })
                .collect(),
        })
        .collect();
    let mut source_variants = Vec::new();
    for ((domain, name), indices) in named {
        let mut providers = BTreeSet::new();
        for index in &indices {
            let record = &records[*index];
            providers.insert((&record.identity, serde_json::to_string(&record.source)?));
        }
        if providers.len() < 2 {
            continue;
        }
        let identities = indices
            .iter()
            .filter_map(|i| records[*i].identity.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut sources = BTreeMap::new();
        for index in indices {
            let record = &records[index];
            let evidence = SourceEvidence {
                identity: record.identity.clone(),
                version: record.component.version.clone(),
                source: record.component.source.clone(),
                context: record.component.context.clone(),
            };
            sources.insert(serde_json::to_string(&evidence)?, evidence);
        }
        source_variants.push(SourceVariants {
            domain,
            name,
            identities,
            sources: sources.into_values().collect(),
        });
    }
    let mut cross = BTreeMap::<(String, String), (Value, Vec<DomainVersions>)>::new();
    for group in &groups {
        let entry = cross
            .entry((
                group.identity.clone(),
                serde_json::to_string(&group.source)?,
            ))
            .or_insert_with(|| (group.source.clone(), Vec::new()));
        entry.1.push(DomainVersions {
            domain: group.domain.clone(),
            versions: group.versions.iter().map(|v| v.version.clone()).collect(),
        });
    }
    let cross_domain = cross
        .into_iter()
        .filter_map(|((identity, _), (source, domains))| {
            let first = domains.first()?;
            domains
                .iter()
                .any(|domain| domain.versions != first.versions)
                .then_some(CrossDomainDifference {
                    identity,
                    source,
                    domains,
                })
        })
        .collect();
    let pins = pins::audit_pins(&graph.inventory);
    let pin_lock_consistent =
        pin_lock_consistency(graph, &pins, &project_domains, &context_domains)?;
    let pin_audit_complete = graph.inventory.complete
        && !graph.inventory.projects.is_empty()
        && supported
        && pins.iter().all(|p| p.status != PinStatus::Unsupported);
    let pins_compliant = if pins
        .iter()
        .any(|p| matches!(p.status, PinStatus::Range | PinStatus::Unconstrained))
    {
        Some(false)
    } else if pin_audit_complete
        && !pins.is_empty()
        && pins.iter().all(|p| p.status == PinStatus::ExactVersion)
    {
        Some(true)
    } else {
        None
    };
    let coverage = AlignmentCoverage {
        inventory_complete,
        versions_complete,
        pin_audit_complete,
        activation_known,
        inventory_components: component_count,
        projected_components,
        unidentified_components,
        unprojected_components: component_count - projected_components,
        unmapped_nodes,
    };
    let aligned = if groups.iter().any(|group| group.duplicate) {
        Some(false)
    } else {
        versions_complete.then_some(true)
    };
    let mut limitations = Vec::new();
    if !coverage.inventory_complete {
        limitations.push(
            "Inventaire verrouillé absent, vide ou incomplet : alignement global non démontré"
                .into(),
        );
    }
    if empty_domains > 0 {
        limitations.push(format!(
            "{empty_domains} domaines de résolution sans composant inventorié"
        ));
    }
    if !supported {
        limitations
            .push("Au moins un écosystème n'a pas de projection de versions qualifiée".into());
    }
    if unidentified_components > 0 {
        limitations.push(format!(
            "{unidentified_components} composants sans identité de paquet qualifiée"
        ));
    }
    if coverage.unprojected_components > 0 {
        limitations.push(format!(
            "{} composants de l'inventaire sans occurrence projetée correspondante",
            coverage.unprojected_components
        ));
    }
    if unmapped_nodes > 0 {
        limitations.push(format!(
            "{unmapped_nodes} occurrences projetées sans preuve correspondante dans leur domaine"
        ));
    }
    if !activation_known {
        limitations.push("Activation des paquets, fonctionnalités et cibles non entièrement établie par l'analyse statique".into());
    }
    if !graph.limitations.is_empty() {
        limitations.push(format!(
            "{} limites de projection conservées dans le graphe source",
            graph.limitations.len()
        ));
    }
    if !pin_audit_complete {
        limitations.push("Classification des déclarations directes incomplète".into());
    }
    if pins.iter().any(|p| p.status == PinStatus::SourceOverride) {
        limitations.push("Les sélections de sources sont classifiées séparément ; elles ne prouvent pas un pin de version".into());
    }
    if !pins.is_empty()
        && pins.iter().all(|p| p.status == PinStatus::ExactVersion)
        && pin_lock_consistent != Some(true)
    {
        limitations
            .push("Concordance des pins exacts avec les cibles verrouillées non établie".into());
    }
    let result = Alignment {
        schema_version: 1,
        aligned,
        pins_compliant,
        pin_lock_consistent,
        coverage,
        domains: domains.into_values().collect(),
        groups,
        cross_domain,
        source_variants,
        pins,
        limitations,
    };
    ensure!(
        serde_json::to_vec(&result)?.len() <= MAX_BYTES,
        "Rapport d'alignement supérieur à 128 Mio"
    );
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PinVersion {
    Semver(semver::Version),
    Python(pep440_rs::Version),
}
impl PinVersion {
    fn parse(ecosystem: &str, value: &str) -> Option<Self> {
        match ecosystem {
            "rust" | "npm" => value.parse::<semver::Version>().ok().map(|mut version| {
                // SemVer requirement matching ignores build metadata.
                version.build = semver::BuildMetadata::EMPTY;
                Self::Semver(version)
            }),
            "python" => value.parse().ok().map(Self::Python),
            _ => None,
        }
    }
}

// A multiset retains separate declarations even when they point at one node.
// Cargo conditions carry the complete declaration, including renamed imports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PinRootKey {
    manifest: String,
    kind: String,
    name: String,
    installed_name: String,
    version: PinVersion,
    declaration: String,
}

fn python_name(name: &str) -> String {
    name.split(['-', '_', '.'])
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("-")
}

fn pin_lock_consistency(
    graph: &Graph,
    pins: &[PinFinding],
    project_domains: &BTreeMap<&str, String>,
    context_domains: &BTreeMap<&str, &str>,
) -> Result<Option<bool>> {
    if pins.is_empty() || pins.iter().any(|pin| pin.status != PinStatus::ExactVersion) {
        return Ok(None);
    }
    let projects: BTreeMap<_, _> = graph
        .inventory
        .projects
        .iter()
        .map(|p| (p.manifest.as_str(), p))
        .collect();
    let nodes: BTreeMap<_, _> = graph
        .components
        .iter()
        .map(|n| (&n.key, &n.component))
        .collect();
    let mut roots = BTreeMap::<PinRootKey, Vec<usize>>::new();
    for (index, root) in graph.roots.iter().enumerate() {
        let Some(project) = projects.get(root.manifest.as_str()) else {
            continue;
        };
        let Some(component) = nodes.get(&root.to) else {
            continue;
        };
        let domain = project_domains
            .get(root.manifest.as_str())
            .map(String::as_str);
        if domain.is_none() || domain != context_domains.get(root.to.graph.as_str()).copied() {
            continue;
        }
        if project.ecosystem == "rust"
            && component.source.as_str()
                != Some("registry+https://github.com/rust-lang/crates.io-index")
        {
            continue;
        }
        let Some(version) = PinVersion::parse(&project.ecosystem, &component.version) else {
            continue;
        };
        let key = PinRootKey {
            manifest: root.manifest.clone(),
            kind: root.kind.clone(),
            name: if project.ecosystem == "python" {
                python_name(&component.name)
            } else {
                component.name.clone()
            },
            installed_name: if project.ecosystem == "npm" {
                component
                    .context
                    .rsplit_once("node_modules/")
                    .map_or_else(String::new, |(_, name)| name.into())
            } else {
                String::new()
            },
            version,
            declaration: if project.ecosystem == "rust" {
                serde_json::to_string(&root.condition)?
            } else {
                String::new()
            },
        };
        // PEP 440 equality without a local label also accepts a local build.
        // Both lookup keys share a root index, so it can still be consumed once.
        if let PinVersion::Python(version) = &key.version {
            if !version.local().is_empty() {
                let mut public_key = key.clone();
                public_key.version = PinVersion::Python(version.clone().without_local());
                roots.entry(public_key).or_default().push(index);
            }
        }
        roots.entry(key).or_default().push(index);
    }
    let mut consumed = BTreeSet::new();
    for pin in pins {
        let Some(version) = pin
            .pin
            .as_deref()
            .and_then(|v| PinVersion::parse(&pin.ecosystem, v))
        else {
            return Ok(None);
        };
        let requirement = &pin.requirement;
        let name = if pin.ecosystem == "python" {
            python_name(&requirement.name)
        } else if pin.ecosystem == "npm" {
            if let Some(alias) = requirement.constraint.trim().strip_prefix("npm:") {
                let Some((name, _)) = alias.rsplit_once('@') else {
                    return Ok(None);
                };
                name.into()
            } else {
                requirement.name.clone()
            }
        } else {
            requirement.name.clone()
        };
        let key = PinRootKey {
            manifest: pin.manifest.clone(),
            kind: requirement.kind.clone(),
            name,
            installed_name: if pin.ecosystem == "npm" {
                requirement.name.clone()
            } else {
                String::new()
            },
            version,
            declaration: if pin.ecosystem == "rust" {
                serde_json::to_string(&serde_json::to_value(requirement)?)?
            } else {
                String::new()
            },
        };
        let Some(candidates) = roots.get_mut(&key) else {
            return Ok(None);
        };
        loop {
            let Some(index) = candidates.pop() else {
                return Ok(None);
            };
            if consumed.insert(index) {
                break;
            }
        }
    }
    Ok(Some(true))
}

struct InventoryOccurrence<'a> {
    domain: String,
    component: &'a Component,
    identity: Option<String>,
    source: Value,
    nodes: BTreeSet<NodeRef>,
}

struct GroupBuilder {
    name: String,
    source: Value,
    versions: BTreeMap<String, BTreeSet<NodeRef>>,
}

fn register_manifest(index: &mut BTreeMap<String, Option<String>>, manifest: String, domain: &str) {
    index
        .entry(manifest)
        .and_modify(|previous| {
            if previous.as_deref() != Some(domain) {
                *previous = None;
            }
        })
        .or_insert_with(|| Some(domain.into()));
}

fn lock_manifest(project: &Project) -> Option<String> {
    let basename = match project.ecosystem.as_str() {
        "rust" => "Cargo.toml",
        "npm" => "package.json",
        _ => return None,
    };
    let lockfile = project.lockfile.as_deref()?;
    Some(lockfile.rsplit_once('/').map_or_else(
        || basename.into(),
        |(parent, _)| format!("{parent}/{basename}"),
    ))
}

fn projected_purl(project: &Project, component: &Component) -> Result<Option<String>> {
    if component.purl.is_some() {
        return Ok(component.purl.clone());
    }
    if project.ecosystem != "rust"
        || !component.source.is_null()
        || component.context != "workspace"
        || !component.metadata.get("source").is_none_or(Value::is_null)
        || component.metadata["name"] != component.name
        || component.metadata["version"] != component.version
    {
        return Ok(None);
    }
    let mut purl = packageurl::PackageUrl::new("generic", &component.name)
        .map_err(|e| invalid(e.to_string()))?;
    purl.with_namespace("cargo-local")
        .map_err(|e| invalid(e.to_string()))?;
    purl.with_version(&component.version)
        .map_err(|e| invalid(e.to_string()))?;
    Ok(Some(purl.to_string()))
}

fn package_identity(purl: &str, component: &Component) -> Result<String> {
    let mut parsed = purl
        .parse::<packageurl::PackageUrl>()
        .map_err(|e| invalid(format!("PURL invalide : {e}")))?;
    ensure!(
        purl.len() <= 8192 && parsed.to_string() == purl,
        "PURL canonique requise"
    );
    ensure!(
        parsed.version() == Some(component.version.as_str()) && !component.version.is_empty(),
        "Version du composant divergente de sa PURL"
    );
    Ok(parsed.without_version().to_string())
}

fn component_evidence(component: &Component, purl: Option<&str>) -> Result<String> {
    Ok(serde_json::to_string(&(
        &component.name,
        &component.version,
        purl,
        &component.context,
        &component.source,
        &component.artifacts,
        &component.metadata,
    ))?)
}

pub(super) fn normalized_source(
    ecosystem: &str,
    name: &str,
    version: &str,
    raw_source: &Value,
) -> Value {
    if ecosystem != "npm" {
        return raw_source.clone();
    }
    let Some(source) = raw_source.as_str() else {
        return raw_source.clone();
    };
    if !source.starts_with("https://") && !source.starts_with("http://") {
        return raw_source.clone();
    }
    let split = source.find(['?', '#']).unwrap_or(source.len());
    let (location, selectors) = source.split_at(split);
    let Some((prefix, filename)) = location.rsplit_once("/-/") else {
        return raw_source.clone();
    };
    let basename = name.rsplit('/').next().unwrap_or(name);
    if filename != format!("{basename}-{version}.tgz") {
        return raw_source.clone();
    }
    Value::String(format!("{prefix}/-/{selectors}"))
}
