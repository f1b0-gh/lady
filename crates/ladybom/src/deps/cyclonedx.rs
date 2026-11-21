//! Deterministic CycloneDX projection of the inventory and established static relations.
use super::{invalid, Component as InventoryComponent, Project, Report};
use crate::{
    error::{ensure, Error, Result},
    files,
};
use cyclonedx_bom::{
    errors::JsonWriteError,
    external_models::uri::Uri,
    models::{
        bom::{Bom, SpecVersion},
        component::{Classification, Component, Components},
        composition::{AggregateType, Composition, Compositions},
        dependency::{Dependencies, Dependency},
        external_reference::{ExternalReference, ExternalReferenceType, ExternalReferences},
        hash::{Hash, HashAlgorithm, HashValue, Hashes},
        license::{LicenseChoice, Licenses},
        metadata::Metadata,
        property::{Properties, Property},
        tool::{Tool, Tools},
    },
    prelude::{NormalizedString, UrnUuid, Validate},
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

/// Native evidence is private unless the caller deliberately selects the detailed profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ExportProfile {
    #[default]
    Public,
    PrivateDetailed,
}

impl ExportProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::PrivateDetailed => "private-detailed",
        }
    }
}

fn digest(value: &impl serde::Serialize) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(value)?))
}

/// Stable reference shared by the inventory export and vulnerability assessment.
pub fn component_reference(project: &Project, component: &InventoryComponent) -> Result<String> {
    let identity = serde_json::to_vec(&(
        &project.ecosystem,
        project.lockfile.as_deref().unwrap_or(&project.manifest),
        component,
    ))?;
    Ok(format!("ladybom:{}", files::hash(&identity)))
}

/// Deterministic UUIDv8 (custom SHA-256 layout) for one immutable document.
pub fn serial_from_digest(digest: &str) -> Result<String> {
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "Empreinte de document invalide"
    );
    let mut hex = digest[..32].to_ascii_lowercase().into_bytes();
    hex[12] = b'8';
    let variant = u8::from_str_radix(&digest[16..17], 16)
        .map_err(|_| invalid("Empreinte de document invalide".into()))?;
    hex[16] = b"0123456789abcdef"[usize::from((variant & 3) | 8)];
    let hex = String::from_utf8(hex)?;
    Ok(format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

pub fn document_serial(report: &Report) -> Result<String> {
    document_serial_with_profile(report, ExportProfile::Public)
}

pub fn document_serial_with_profile(report: &Report, profile: ExportProfile) -> Result<String> {
    unsigned_serial(&unsigned_report(report, profile)?)
}

fn unsigned_serial(bom: &Bom) -> Result<String> {
    let mut bytes = Vec::new();
    bom.clone()
        .output_as_json_v1_5(&mut bytes)
        .map_err(json_error)?;
    // Canonical JSON object key ordering, excluding only the document's own serial.
    let content: Value = serde_json::from_slice(&bytes)?;
    serial_from_digest(&files::hash(&serde_json::to_vec(&content)?))
}

fn json_error(error: JsonWriteError) -> Error {
    match error {
        JsonWriteError::JsonElementWriteError { error } => Error::Json(error),
        other => invalid(format!("Sérialisation CycloneDX impossible : {other}")),
    }
}

/// Convert a validated report to CycloneDX 1.5 without executing or resolving anything.
///
/// Shared locks are emitted once; identical PURLs in different lockfiles or native
/// contexts remain distinct. Public exports retain fingerprints of private native
/// evidence; detailed exports retain its content. No versions are fabricated. Parsing coverage does
/// not establish SBOM completeness. Relations are potential static inventory
/// relations, never evidence of activation or runtime reachability.
pub fn from_report(report: &Report) -> Result<Bom> {
    from_report_with_profile(report, ExportProfile::Public)
}

pub fn from_report_with_profile(report: &Report, profile: ExportProfile) -> Result<Bom> {
    let mut bom = unsigned_report(report, profile)?;
    bom.serial_number = Some(
        UrnUuid::new(unsigned_serial(&bom)?)
            .map_err(|error| invalid(format!("Identité CycloneDX invalide : {error:?}")))?,
    );
    Ok(bom)
}

fn unsigned_report(report: &Report, profile: ExportProfile) -> Result<Bom> {
    report.validate()?;
    let mut components = BTreeMap::new();
    let mut projects = Vec::new();
    for project in &report.projects {
        let mut context = serde_json::to_value(project)?;
        if let Some(object) = context.as_object_mut() {
            object.remove("components");
        }
        projects.push(context);
        // Report validation already checked every shared-lock reference.
        if project.components_from.is_some() {
            continue;
        }
        for component in &project.components {
            let reference = component_reference(project, component)?;
            let converted = convert_component(project, component, reference.clone(), profile)?;
            components.insert(reference, converted);
        }
    }
    // Graph projection is shared with native graph operations and needs no engine.
    // Identical records collapse just as they do in the component export above.
    let mut inventory = report.clone();
    for project in &mut inventory.projects {
        let mut seen = BTreeSet::new();
        let mut unique = Vec::new();
        for component in std::mem::take(&mut project.components) {
            if seen.insert(serde_json::to_string(&component)?) {
                unique.push(component);
            }
        }
        project.components = unique;
    }
    let (graph, origins) = match super::graph::project_with_origins(inventory) {
        Ok(projected) => (projected.graph, projected.origins),
        // Graph qualification is stricter than inventory validation. A failure
        // must not discard valid inventory occurrences or imply absent edges.
        Err(error) => (
            super::graph::Graph {
                schema_version: 1,
                inventory: report.clone(),
                contexts: BTreeMap::new(),
                components: Vec::new(),
                dependencies: Vec::new(),
                roots: Vec::new(),
                limitations: vec![format!(
                    "Projection du graphe indisponible ; relations inconnues : {error}"
                )],
            },
            BTreeMap::new(),
        ),
    };
    let owners: BTreeMap<_, _> = graph
        .inventory
        .projects
        .iter()
        .map(|project| (project.manifest.as_str(), project))
        .collect();
    let references: BTreeMap<_, _> = origins
        .iter()
        .map(|(key, (manifest, index))| {
            let project = owners
                .get(manifest.as_str())
                .ok_or_else(|| invalid("Provenance du graphe absente".into()))?;
            let component = project
                .components
                .get(*index)
                .ok_or_else(|| invalid("Composant du graphe absent".into()))?;
            Ok((key.clone(), component_reference(project, component)?))
        })
        .collect::<Result<_>>()?;
    let root_reference = "ladybom:application";
    let mut root = Component::new(
        Classification::Application,
        "ladybom-inventory",
        "",
        Some(root_reference.into()),
    );
    root.version = None;
    root.properties = Some(Properties(vec![Property::new(
        "ladybom:role",
        "synthetic inventory scope; not an observed build",
    )]));
    let mut dependencies: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut evidence_roots = Vec::new();
    let mut evidence_edges = Vec::new();
    for declared in &graph.roots {
        let target = references
            .get(&declared.to)
            .ok_or_else(|| invalid("Référence racine CycloneDX absente".into()))?;
        dependencies
            .entry(root_reference.into())
            .or_default()
            .insert(target.clone());
        evidence_roots.push(if profile == ExportProfile::PrivateDetailed {
            json!({"ref":root_reference,"dependsOn":target,"manifest":declared.manifest,"kind":declared.kind,"condition":declared.condition})
        } else {
            json!({"ref":root_reference,"dependsOn":target,"conditional":!declared.condition.is_null(),"evidence_sha256":digest(declared)?})
        });
    }
    for edge in &graph.dependencies {
        let from = references
            .get(&edge.from)
            .ok_or_else(|| invalid("Origine CycloneDX absente".into()))?;
        let to = references
            .get(&edge.to)
            .ok_or_else(|| invalid("Cible CycloneDX absente".into()))?;
        dependencies
            .entry(from.clone())
            .or_default()
            .insert(to.clone());
        evidence_edges.push(if profile == ExportProfile::PrivateDetailed {
            json!({"ref":from,"dependsOn":to,"kind":edge.kind,"condition":edge.condition,"evidence":edge.evidence})
        } else {
            json!({"ref":from,"dependsOn":to,"conditional":!edge.condition.is_null(),"evidence_sha256":digest(edge)?})
        });
    }
    let coverage = json!({
        "inventory_parsed":report.complete,
        "graph_complete":graph.complete(),
        "composition":if report.complete {"unknown"} else {"incomplete"},
        "limitations_count":graph.limitations.len(),
        "limitations_sha256":digest(&graph.limitations)?,
        "diagnostics_count":report.diagnostics.len(),
        "diagnostics_sha256":digest(&report.diagnostics)?,
    });
    let coverage_properties = vec![
        Property::new("ladybom:export_profile", profile.name()),
        Property::new("ladybom:provenance:report_sha256", &digest(report)?),
        Property::new("ladybom:coverage:scope", "document"),
        Property::new(
            "ladybom:coverage:inventory_parsed",
            &report.complete.to_string(),
        ),
        Property::new(
            "ladybom:coverage:graph_complete",
            &graph.complete().to_string(),
        ),
        Property::new(
            "ladybom:coverage:composition",
            if report.complete {
                "unknown"
            } else {
                "incomplete"
            },
        ),
        Property::new("ladybom:coverage:sha256", &digest(&coverage)?),
        Property::new("ladybom:coverage", &serde_json::to_string(&coverage)?),
    ];
    for component in components.values_mut().chain(std::iter::once(&mut root)) {
        component
            .properties
            .get_or_insert_with(|| Properties(Vec::new()))
            .0
            .extend(coverage_properties.clone());
    }
    let mut properties = coverage_properties;
    properties.extend([
        Property::new("ladybom:schema_version", &report.schema_version.to_string()),
        Property::new("ladybom:complete", &report.complete.to_string()),
        Property::new("ladybom:graph:semantics", "Potential static inventory relationships; conditions are unevaluated; no activation or runtime reachability claim. Missing relationships are unknown, not absent."),
        Property::new("ladybom:graph:evidence", &serde_json::to_string(&json!({"roots":evidence_roots,"dependencies":evidence_edges}))?),
        Property::new("ladybom:provenance:inputs_sha256", &digest(&report.inputs)?),
    ]);
    if profile == ExportProfile::PrivateDetailed {
        properties.extend([
            Property::new(
                "ladybom:graph:limitations",
                &serde_json::to_string(&graph.limitations)?,
            ),
            Property::new("ladybom:inputs", &serde_json::to_string(&report.inputs)?),
            Property::new("ladybom:projects", &serde_json::to_string(&projects)?),
            Property::new(
                "ladybom:diagnostics",
                &serde_json::to_string(&report.diagnostics)?,
            ),
        ]);
    }
    let bom = Bom {
        spec_version: SpecVersion::V1_5,
        serial_number: None,
        metadata: Some(Metadata {
            component: Some(root),
            tools: Some(Tools::List(vec![Tool {
                name: Some(NormalizedString::new("ladybom")),
                version: Some(NormalizedString::new(env!("CARGO_PKG_VERSION"))),
                ..Tool::default()
            }])),
            ..Metadata::default()
        }),
        components: Some(Components(components.into_values().collect())),
        dependencies: Some(Dependencies(
            dependencies
                .into_iter()
                .map(|(dependency_ref, dependencies)| Dependency {
                    dependency_ref,
                    dependencies: dependencies.into_iter().collect(),
                })
                .collect(),
        )),
        compositions: Some(Compositions(vec![Composition {
            bom_ref: None,
            aggregate: if report.complete {
                AggregateType::Unknown
            } else {
                AggregateType::Incomplete
            },
            assemblies: None,
            dependencies: None,
            vulnerabilities: None,
            signature: None,
        }])),
        properties: Some(Properties(properties)),
        ..Bom::default()
    };
    let validation = bom.validate_version(SpecVersion::V1_5);
    ensure!(
        validation.passed(),
        "Export CycloneDX invalide : {validation:?}"
    );
    Ok(bom)
}

fn convert_component(
    project: &Project,
    source: &InventoryComponent,
    reference: String,
    profile: ExportProfile,
) -> Result<Component> {
    // cyclonedx-bom silently normalizes these characters. Reject them instead of
    // exporting a different package identity or native resolution context.
    for (field, value) in [
        ("name", source.name.as_str()),
        ("version", source.version.as_str()),
        ("context", source.context.as_str()),
        ("ecosystem", project.ecosystem.as_str()),
        ("manifest", project.manifest.as_str()),
        ("lockfile", project.lockfile.as_deref().unwrap_or("")),
    ] {
        ensure!(
            !value.contains(['\r', '\n', '\t']),
            "Champ CycloneDX {field} non normalisé : retour à la ligne ou tabulation"
        );
    }
    if profile == ExportProfile::Public {
        ensure!(
            !source.name.is_empty() && source.name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-/@".contains(&c))
                && source.version.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-+!".contains(&c)),
            "Identité de composant non publiable ; utiliser le profil privé sans réécrire son identité"
        );
    }
    let mut component = Component::new(
        Classification::Library,
        &source.name,
        &source.version,
        Some(reference),
    );
    if source.version.is_empty() {
        component.version = None;
    }
    if let Some(purl) = &source.purl {
        purl.parse::<packageurl::PackageUrl>().map_err(|_| {
            invalid("PURL native invalide même si omise de la projection publique".into())
        })?;
    }
    component.purl = source
        .purl
        .as_deref()
        .filter(|_| {
            profile == ExportProfile::PrivateDetailed
                || super::vuln::public_identity(project, source).is_some()
        })
        .map(|purl| {
            purl.parse()
                .map_err(|_| invalid("PURL CycloneDX invalide".into()))
        })
        .transpose()?;
    let mut distributions = Vec::new();
    for artifact in &source.artifacts {
        if profile == ExportProfile::Public {
            continue;
        }
        // Only qualified absolute network locations become standard references.
        // Other native strings remain available verbatim in ladybom:artifacts.
        if !(artifact.url.starts_with("https://") || artifact.url.starts_with("http://")) {
            continue;
        }
        let authority = artifact
            .url
            .split_once("://")
            .map_or("", |(_, rest)| rest.split('/').next().unwrap_or(""));
        if authority.is_empty() || authority.contains('@') || artifact.url.contains(['?', '#']) {
            continue;
        }
        let mut distribution =
            ExternalReference::new(ExternalReferenceType::Distribution, Uri::new(&artifact.url));
        if !distribution.validate_version(SpecVersion::V1_5).passed() {
            continue;
        }
        if let Some((algorithm, value)) = artifact
            .hash
            .as_deref()
            .and_then(|hash| hash.split_once(':'))
        {
            let algorithm = match algorithm {
                "sha256" if value.len() == 64 => Some(HashAlgorithm::SHA_256),
                "sha384" if value.len() == 96 => Some(HashAlgorithm::SHA_384),
                "sha512" if value.len() == 128 => Some(HashAlgorithm::SHA_512),
                _ => None,
            };
            if let Some(alg) =
                algorithm.filter(|_| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                distribution.hashes = Some(Hashes(vec![Hash {
                    alg,
                    content: HashValue(value.to_ascii_lowercase()),
                }]));
            }
        }
        distributions.push(distribution);
    }
    if !distributions.is_empty() {
        component.external_references = Some(ExternalReferences(distributions));
    }
    // package-lock's license field is a package declaration. Cargo/uv metadata
    // has no equivalent qualified field in this inventory model.
    if project.ecosystem == "npm" {
        if let Some(expression) = source.metadata.get("license").and_then(Value::as_str) {
            let license = LicenseChoice::expression(expression);
            if !expression.contains(['\r', '\n', '\t'])
                && (profile == ExportProfile::PrivateDetailed
                    || !expression.contains("LicenseRef-"))
                && license.validate_version(SpecVersion::V1_5).passed()
            {
                component.licenses = Some(Licenses(vec![license]));
            }
        }
    }
    let mut properties = vec![
        Property::new(
            "ladybom:coverage:identity_qualified",
            &super::vuln::public_identity(project, source)
                .is_some()
                .to_string(),
        ),
        Property::new("ladybom:provenance:component_sha256", &digest(source)?),
        Property::new(
            "ladybom:provenance:resolution_sha256",
            &digest(&(
                &project.ecosystem,
                &project.manifest,
                &project.lockfile,
                &source.context,
                &source.source,
            ))?,
        ),
    ];
    if profile == ExportProfile::PrivateDetailed {
        properties.extend([
            Property::new("ladybom:ecosystem", &project.ecosystem),
            Property::new("ladybom:manifest", &project.manifest),
            Property::new("ladybom:context", &source.context),
            Property::new("ladybom:source", &serde_json::to_string(&source.source)?),
            Property::new(
                "ladybom:artifacts",
                &serde_json::to_string(&source.artifacts)?,
            ),
            Property::new(
                "ladybom:metadata",
                &serde_json::to_string(&source.metadata)?,
            ),
        ]);
        if let Some(lockfile) = &project.lockfile {
            properties.push(Property::new("ladybom:lockfile", lockfile));
        }
    }
    component.properties = Some(Properties(properties));
    Ok(component)
}

/// Validate and write a deterministic CycloneDX 1.5 JSON document and trailing newline.
/// Invalid reports produce no output; writer failures retain operational exit code 1.
pub fn write_json(report: &Report, mut writer: impl Write) -> Result<()> {
    write_json_with_profile(report, ExportProfile::Public, &mut writer)
}

pub fn write_json_with_profile(
    report: &Report,
    profile: ExportProfile,
    mut writer: impl Write,
) -> Result<()> {
    from_report_with_profile(report, profile)?
        .output_as_json_v1_5(&mut writer)
        .map_err(json_error)?;
    writeln!(writer)?;
    Ok(())
}
