//! Standalone CycloneDX 1.5 VEX with explicit, report-bound reference profiles.
use super::{digest, policy::qualify, Assessment, DecisionState, Decisions};
use crate::deps::{cyclonedx, Report};
use crate::{
    deps::invalid,
    error::{ensure, Error, Result},
};
use cyclonedx_bom::{
    errors::JsonWriteError,
    models::{
        bom::{Bom, SpecVersion},
        component::Components,
        property::{Properties, Property},
        vulnerability::{Vulnerabilities, Vulnerability},
        vulnerability_analysis::{
            ImpactAnalysisJustification, ImpactAnalysisState, VulnerabilityAnalysis,
        },
        vulnerability_reference::{VulnerabilityReference, VulnerabilityReferences},
        vulnerability_source::VulnerabilitySource,
        vulnerability_target::{VulnerabilityTarget, VulnerabilityTargets},
    },
    prelude::{NormalizedString, UrnUuid, Validate},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};

pub fn from_assessment(assessment: &Assessment, decisions: Option<&Decisions>) -> Result<Bom> {
    from_assessment_with_export_profile(assessment, decisions, cyclonedx::ExportProfile::Public)
}

/// This API retains the assessment's SBOM target. To target a private SBOM,
/// use from_report_with_export_profile, which verifies the exact native report.
pub fn from_assessment_with_export_profile(
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    export_profile: cyclonedx::ExportProfile,
) -> Result<Bom> {
    finalize(build(
        assessment,
        decisions,
        Profile::BomLink,
        export_profile,
        &assessment.sbom_serial,
    )?)
}

fn build(
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    profile: Profile,
    export_profile: cyclonedx::ExportProfile,
    sbom_serial: &str,
) -> Result<Bom> {
    let qualifications = qualify(assessment, decisions)?;
    let private = export_profile == cyclonedx::ExportProfile::PrivateDetailed;
    if !private {
        for value in [&assessment.report_digest, &assessment.snapshot_digest] {
            ensure!(
                value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "Invalid public VEX digest"
            );
        }
    }
    let uuid = sbom_serial
        .strip_prefix("urn:uuid:")
        .ok_or_else(|| invalid("SBOM UUID identity required".into()))?;
    ensure!(
        uuid.len() == 36
            && uuid
                .bytes()
                .enumerate()
                .all(|(index, byte)| if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }),
        "Invalid SBOM UUID identity"
    );
    let coverage = if private {
        serde_json::to_value(&assessment.coverage)?
    } else {
        serde_json::json!({
            "inventory_complete":assessment.coverage.inventory_complete,
            "advisories_complete":assessment.coverage.advisories_complete,
            "identities_complete":assessment.coverage.identities_complete,
            "matching_complete":assessment.coverage.matching_complete,
            "fresh":assessment.coverage.fresh,
            "components":assessment.coverage.components,
            "assessed_components":assessment.coverage.assessed_components,
            "withdrawn_advisories":assessment.coverage.withdrawn_advisories,
            "limitations_count":assessment.coverage.limitations.len(),
            "limitations_sha256":digest(&assessment.coverage.limitations)?,
        })
    };
    let coverage_properties = vec![
        Property::new("ladybom:export_profile", export_profile.name()),
        Property::new("ladybom:assessment_sha256", &digest(assessment)?),
        Property::new("ladybom:coverage_sha256", &digest(&assessment.coverage)?),
        Property::new("ladybom:coverage", &serde_json::to_string(&coverage)?),
        Property::new("ladybom:coverage_scope", "assessment"),
        Property::new("ladybom:sbom_serial", sbom_serial),
    ];
    let mut vulnerabilities = Vec::with_capacity(assessment.findings.len());
    for finding in &assessment.findings {
        if !private {
            ensure!(
                finding
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte)),
                "Result identifier cannot be published without rewriting"
            );
            ensure!(
                finding
                    .component_ref
                    .strip_prefix("ladybom:")
                    .is_some_and(|suffix| !suffix.is_empty()
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))),
                "Unqualified public component reference"
            );
            for id in finding.advisory_ids.iter().chain(&finding.aliases) {
                ensure!(
                    !id.is_empty()
                        && id.len() <= 256
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte)),
                    "Advisory identifier cannot be published without rewriting"
                );
                if profile == Profile::LocalComponents {
                    ensure!(
                        advisory_source(id, assessment, false).name.is_some(),
                        "Unqualified advisory authority for public local VEX references"
                    );
                }
            }
        }
        let qualification = &qualifications[&finding.id];
        ensure!(
            !finding.component_ref.contains(['#', ' ', '\r', '\n', '\t']),
            "Component reference incompatible with BOM-Link"
        );
        let mut vulnerability = Vulnerability::new(Some(finding.id.clone()));
        vulnerability.id = finding
            .advisory_ids
            .first()
            .map(|id| NormalizedString::new(id));
        if let Some(id) = finding.advisory_ids.first() {
            vulnerability.vulnerability_source = Some(advisory_source(id, assessment, private));
            let aliases: BTreeSet<_> = finding
                .advisory_ids
                .iter()
                .chain(&finding.aliases)
                .filter(|alias| *alias != id)
                .collect();
            vulnerability.vulnerability_references = Some(VulnerabilityReferences(
                aliases
                    .into_iter()
                    .map(|alias| {
                        VulnerabilityReference::new(
                            alias,
                            advisory_source(alias, assessment, private),
                        )
                    })
                    .collect(),
            ));
        }
        let state = match qualification.state {
            DecisionState::InTriage => ImpactAnalysisState::InTriage,
            DecisionState::Exploitable => ImpactAnalysisState::Exploitable,
            DecisionState::NotAffected => ImpactAnalysisState::NotAffected,
            DecisionState::FalsePositive => ImpactAnalysisState::FalsePositive,
            DecisionState::Resolved => ImpactAnalysisState::Resolved,
        };
        let mut analysis = VulnerabilityAnalysis::new(Some(state), None, None);
        let mut properties = vec![
            Property::new("ladybom:finding_id", &finding.id),
            Property::new(
                "ladybom:match_status",
                &serde_json::to_string(&finding.status)?,
            ),
            Property::new(
                "ladybom:advisory_ids",
                &serde_json::to_string(&finding.advisory_ids)?,
            ),
            Property::new("ladybom:aliases", &serde_json::to_string(&finding.aliases)?),
            Property::new(
                "ladybom:qualification_reasons_sha256",
                &digest(&qualification.reasons)?,
            ),
            Property::new("ladybom:finding_sha256", &digest(finding)?),
        ];
        properties.extend(coverage_properties.clone());
        if private {
            properties.push(Property::new(
                "ladybom:qualification_reasons",
                &serde_json::to_string(&qualification.reasons)?,
            ));
        }
        if let Some(decision) = qualification.decision {
            if qualification.active && qualification.state == decision.state {
                if private {
                    analysis.detail = Some(decision.detail.clone());
                }
                analysis.justification = decision
                    .justification
                    .as_ref()
                    .map(ImpactAnalysisJustification::new_unchecked);
            }
            // Preserve expired and inapplicable assertions as provenance, never as effective analysis.
            if private {
                properties.push(Property::new(
                    "ladybom:decision",
                    &serde_json::to_string(decision)?,
                ));
            }
            properties.extend([
                Property::new("ladybom:decision_sha256", &digest(decision)?),
                Property::new("ladybom:decision_issued_at", &decision.issued_at),
                Property::new("ladybom:decision_expires_at", &decision.expires_at),
            ]);
            properties.push(Property::new(
                "ladybom:decision_active",
                &qualification.active.to_string(),
            ));
            properties.push(Property::new(
                "ladybom:decision_applied",
                &(qualification.active && qualification.state == decision.state).to_string(),
            ));
        }
        vulnerability.vulnerability_analysis = Some(analysis);
        vulnerability.vulnerability_targets =
            Some(VulnerabilityTargets(vec![VulnerabilityTarget::new(
                match profile {
                    Profile::BomLink => format!("urn:cdx:{uuid}/1#{}", finding.component_ref),
                    Profile::LocalComponents => finding.component_ref.clone(),
                },
            )]));
        vulnerability.properties = Some(Properties(properties));
        vulnerabilities.push(vulnerability);
    }
    let mut properties = coverage_properties;
    properties.extend([
        Property::new(
            "ladybom:vex_profile",
            match profile {
                Profile::BomLink => "bom-link",
                Profile::LocalComponents => "local-components",
            },
        ),
        Property::new("ladybom:report_digest", &assessment.report_digest),
        Property::new("ladybom:snapshot_digest", &assessment.snapshot_digest),
        Property::new("ladybom:as_of", &assessment.as_of),
        Property::new(
            "ladybom:snapshot_source_sha256",
            &digest(&assessment.snapshot_source)?,
        ),
        Property::new(
            "ladybom:snapshot_fetched_at",
            &assessment.snapshot_fetched_at,
        ),
        Property::new(
            "ladybom:evidence_verification",
            "Documented human assertions; evidence truth is not automatically verified",
        ),
    ]);
    if private {
        properties.push(Property::new(
            "ladybom:snapshot_source",
            &assessment.snapshot_source,
        ));
    }
    let bom = Bom {
        spec_version: SpecVersion::V1_5,
        vulnerabilities: Some(Vulnerabilities(vulnerabilities)),
        properties: Some(Properties(properties)),
        ..Bom::default()
    };
    Ok(bom)
}

fn advisory_source(id: &str, assessment: &Assessment, private: bool) -> VulnerabilitySource {
    // Preserve identifier namespaces; the collector is recorded separately.
    // A CVE identifier alone does not establish NVD as the advisory provider.
    let name = if id.starts_with("CVE-") {
        "CVE"
    } else if id.starts_with("GHSA-") {
        "GITHUB"
    } else if id.starts_with("RUSTSEC-") {
        "RUSTSEC"
    } else if id.starts_with("OSV-") {
        "OSV"
    } else if private
        || matches!(
            assessment.snapshot_source.as_str(),
            "INTERNAL" | "NVD" | "OSV" | "GITHUB" | "RUSTSEC" | "CVE"
        )
    {
        &assessment.snapshot_source
    } else {
        return VulnerabilitySource::new(None, None);
    };
    VulnerabilitySource::new(Some(name.into()), None)
}

fn finalize(mut bom: Bom) -> Result<Bom> {
    // Hash the actual exported 1.5 payload, including the explicit profile, with
    // the serial omitted to avoid self-reference. Format changes change identity.
    bom.serial_number = None;
    let mut payload = Vec::new();
    bom.clone()
        .output_as_json_v1_5(&mut payload)
        .map_err(|error| invalid(format!("Cannot serialize VEX: {error}")))?;
    let serial = cyclonedx::serial_from_digest(&crate::files::hash(&payload))?;
    bom.serial_number =
        Some(UrnUuid::new(serial).map_err(|_| invalid("Invalid VEX identity".into()))?);
    let validation = bom.validate_version(SpecVersion::V1_5);
    ensure!(validation.passed(), "Invalid VEX export: {validation:?}");
    Ok(bom)
}

/// Validation precedes output; writer failures remain operational errors (exit 1).
pub fn write_json(
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    mut writer: impl Write,
) -> Result<()> {
    from_assessment(assessment, decisions)?
        .output_as_json_v1_5(&mut writer)
        .map_err(|error| match error {
            JsonWriteError::JsonElementWriteError { error } => Error::Json(error),
            other => invalid(format!("Cannot serialize VEX: {other}")),
        })?;
    writeln!(writer)?;
    Ok(())
}

/// Explicit reference scope for a VEX document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    BomLink,
    LocalComponents,
}

/// Export with exact report linkage and, optionally, embedded local components.
///
/// Local references do not establish consumer interoperability. Refuse a PURL
/// occurring in multiple native contexts because consumers may merge them.
/// Callers supply an assessment produced from trusted source inputs; linkage
/// verification does not independently reproduce the OSV snapshot assessment.
pub fn from_report(
    report: &Report,
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    profile: Profile,
) -> Result<Bom> {
    from_report_with_export_profile(
        report,
        assessment,
        decisions,
        profile,
        cyclonedx::ExportProfile::Public,
    )
}

pub fn from_report_with_export_profile(
    report: &Report,
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    profile: Profile,
    export_profile: cyclonedx::ExportProfile,
) -> Result<Bom> {
    report.validate()?;
    ensure!(
        digest(report)? == assessment.report_digest,
        "Assessment bound to another report"
    );
    ensure!(
        cyclonedx::document_serial(report)? == assessment.sbom_serial,
        "Assessment bound to another SBOM"
    );
    let sbom = cyclonedx::from_report_with_profile(report, export_profile)?;
    let sbom_serial = sbom
        .serial_number
        .as_ref()
        .ok_or_else(|| invalid("Missing SBOM identity".into()))?
        .to_string();
    let mut native = BTreeMap::new();
    let mut purls: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut packages: BTreeMap<(&str, String, &str), BTreeSet<String>> = BTreeMap::new();
    for project in &report.projects {
        if project.components_from.is_some() {
            continue;
        }
        for component in &project.components {
            let reference = cyclonedx::component_reference(project, component)?;
            if let Some(purl) = component.purl.as_deref() {
                purls.entry(purl).or_default().insert(reference.clone());
            }
            let ecosystem = match project.ecosystem.as_str() {
                "rust" => "crates.io",
                "python" => "PyPI",
                other => other,
            };
            packages
                .entry((
                    ecosystem,
                    super::osv::normalize_package(ecosystem, &component.name),
                    &component.version,
                ))
                .or_default()
                .insert(reference.clone());
            native.insert(reference, (project, component));
        }
    }
    let mut selected = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for finding in &assessment.findings {
        let (project, component) = native
            .get(&finding.component_ref)
            .ok_or_else(|| invalid("Result has no component in the report".into()))?;
        ensure!(
            finding.purl == component.purl
                && finding.name == component.name
                && finding.version == component.version
                && finding.context == component.context
                && finding.manifest == project.manifest
                && finding.lockfile == project.lockfile,
            "Result identity differs from the report component"
        );
        let identity = super::assess::public_identity(project, component);
        ensure!(
            identity
                .as_ref()
                .is_some_and(|(ecosystem, _)| *ecosystem == finding.ecosystem),
            "Ambiguous public identity or source for the result"
        );
        if profile == Profile::LocalComponents {
            let key = (
                finding.ecosystem.as_str(),
                super::osv::normalize_package(&finding.ecosystem, &finding.name),
                finding.version.as_str(),
            );
            ensure!(
                packages.get(&key).is_some_and(|refs| refs.len() == 1),
                "Ambiguous package identity: multiple contexts or sources"
            );
            ensure!(
                component
                    .purl
                    .as_deref()
                    .and_then(|purl| purls.get(purl))
                    .is_some_and(|refs| refs.len() == 1),
                "Ambiguous PURL: multiple contexts or sources; separate the inventories"
            );
            ensure!(
                !finding.advisory_ids.is_empty(),
                "Result has no advisory identifier"
            );
            let aliases: BTreeSet<_> = finding
                .advisory_ids
                .iter()
                .chain(&finding.aliases)
                .collect();
            for alias in aliases {
                ensure!(
                    identities.insert((&finding.component_ref, alias)),
                    "Ambiguous results for the same component and advisory"
                );
            }
        }
        selected.insert(finding.component_ref.as_str());
    }
    let mut bom = build(assessment, decisions, profile, export_profile, &sbom_serial)?;
    if profile == Profile::LocalComponents {
        let mut components = sbom
            .components
            .unwrap_or(Components(Vec::new()))
            .0
            .into_iter()
            .filter(|component| {
                component
                    .bom_ref
                    .as_deref()
                    .is_some_and(|r| selected.contains(r))
            })
            .collect::<Vec<_>>();
        ensure!(
            components.len() == selected.len(),
            "Composants VEX locaux incomplets"
        );
        let coverage_properties = bom
            .properties
            .as_ref()
            .map(|properties| {
                properties
                    .0
                    .iter()
                    .filter(|property| {
                        matches!(
                            property.name.as_str(),
                            "ladybom:assessment_sha256"
                                | "ladybom:coverage_sha256"
                                | "ladybom:coverage"
                                | "ladybom:coverage_scope"
                                | "ladybom:sbom_serial"
                        )
                    })
                    .cloned()
                    .map(|mut property| {
                        property.name = match property.name.as_str() {
                            "ladybom:coverage" => "ladybom:vulnerability_coverage".into(),
                            "ladybom:coverage_sha256" => {
                                "ladybom:vulnerability_coverage_sha256".into()
                            }
                            "ladybom:coverage_scope" => {
                                "ladybom:vulnerability_coverage_scope".into()
                            }
                            _ => property.name,
                        };
                        property
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for component in &mut components {
            let properties = component
                .properties
                .get_or_insert_with(|| Properties(Vec::new()));
            // Keep SBOM and vulnerability coverage independently verifiable.
            properties.0.extend(coverage_properties.clone());
        }
        bom.components = Some(Components(components));
    }
    finalize(bom)
}

/// Validate the entire document before writing any bytes.
pub fn write_json_with_profile(
    report: &Report,
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    profile: Profile,
    mut writer: impl Write,
) -> Result<()> {
    write_json_with_export_profile(
        report,
        assessment,
        decisions,
        profile,
        cyclonedx::ExportProfile::Public,
        &mut writer,
    )
}

pub fn write_json_with_export_profile(
    report: &Report,
    assessment: &Assessment,
    decisions: Option<&Decisions>,
    profile: Profile,
    export_profile: cyclonedx::ExportProfile,
    mut writer: impl Write,
) -> Result<()> {
    from_report_with_export_profile(report, assessment, decisions, profile, export_profile)?
        .output_as_json_v1_5(&mut writer)
        .map_err(|error| match error {
            JsonWriteError::JsonElementWriteError { error } => Error::Json(error),
            other => invalid(format!("Cannot serialize VEX: {other}")),
        })?;
    writeln!(writer)?;
    Ok(())
}
