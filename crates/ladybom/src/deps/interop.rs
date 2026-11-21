//! Offline exchange partitions. Native reports remain private; decisions are never inherited.
use super::{cyclonedx, invalid, vuln, Report};
use crate::{
    error::{ensure, Result},
    files,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub struct Scope<'a> {
    pub repository: &'a str,
    pub revision: &'a str,
    pub target_profile: &'a str,
}

#[derive(Debug, Serialize)]
pub struct Bundle {
    pub manifest: Value,
    /// Paths are generated constants and hashes; never taken from input paths.
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

fn artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    total: &mut usize,
    path: String,
    value: &impl Serialize,
) -> Result<Value> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    *total = total.saturating_add(bytes.len());
    ensure!(
        *total <= vuln::MAX_INPUT_BYTES,
        "Interchange bundle exceeds 64 MiB"
    );
    let descriptor = json!({"path":path,"sha256":files::hash(&bytes),"bytes":bytes.len()});
    ensure!(
        artifacts.insert(path, bytes).is_none(),
        "Interchange artifact collision"
    );
    Ok(descriptor)
}

/// Keep independent resolutions in separate consumer projects. A native report is
/// retained per partition so assessments must be recomputed against that exact report.
/// Global inputs/diagnostics remain conservative provenance, not partition completeness.
pub fn bundle(report: &Report, scope: &Scope<'_>) -> Result<Bundle> {
    report.validate()?;
    for field in [scope.repository, scope.revision, scope.target_profile] {
        ensure!(
            !field.trim().is_empty() && field.len() <= 4096,
            "Empty or excessively long interchange identity"
        );
    }
    let source_digest = vuln::digest(report)?;
    let scope_digest = vuln::digest(&(scope.repository, scope.revision, scope.target_profile))?;
    let mut groups = BTreeMap::<(String, Option<String>, Option<String>), Vec<usize>>::new();
    for (index, project) in report.projects.iter().enumerate() {
        groups
            .entry((
                project.ecosystem.clone(),
                project.lockfile.clone(),
                project.lockfile.is_none().then(|| project.manifest.clone()),
            ))
            .or_default()
            .push(index);
    }
    ensure!(
        !groups.is_empty() && groups.len() <= 256,
        "The bundle requires between 1 and 256 independent lockfiles or manifests"
    );
    let mut artifacts = BTreeMap::new();
    let mut partitions = Vec::new();
    let mut total = 0;
    for (key, indexes) in groups {
        let native = Report {
            schema_version: report.schema_version,
            complete: report.complete,
            inputs: report.inputs.clone(),
            projects: indexes
                .into_iter()
                .map(|index| report.projects[index].clone())
                .collect(),
            diagnostics: report.diagnostics.clone(),
        };
        native.validate()?;
        let mut purls = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for (project, component) in native
            .projects
            .iter()
            .flat_map(|p| p.components.iter().map(move |c| (p, c)))
        {
            let name = if project.ecosystem == "python" {
                vuln::osv::normalize_package("PyPI", &component.name)
            } else {
                component.name.clone()
            };
            ensure!(identities.insert((name, &component.version)), "Ambiguous package/version identity within a lockfile: separate export would lose context");
            if let Some(purl) = &component.purl {
                let canonical = purl
                    .parse::<packageurl::PackageUrl<'_>>()
                    .map_err(|_| invalid("Invalid interchange PURL".into()))?
                    .to_string();
                ensure!(
                    purls.insert(canonical),
                    "Ambiguous PURL within a lockfile: separate export would lose context"
                );
            }
        }
        let partition_id = vuln::digest(&(scope.repository, scope.target_profile, &key))?;
        let report_digest = vuln::digest(&native)?;
        let project_name = format!("ladybom-{partition_id}");
        let project_version = vuln::digest(&(scope.revision, &report_digest))?;
        let mut sbom_bytes = Vec::new();
        cyclonedx::write_json(&native, &mut sbom_bytes)?;
        let sbom: Value = serde_json::from_slice(&sbom_bytes)?;
        let sbom_descriptor = artifact(
            &mut artifacts,
            &mut total,
            format!("public/{partition_id}.cdx.json"),
            &sbom,
        )?;
        let native_descriptor = artifact(
            &mut artifacts,
            &mut total,
            format!("private/{partition_id}.report.json"),
            &native,
        )?;
        let coverage = json!({
            "schema_version":1,"partition_id":partition_id,"source_report_digest":source_digest,
            "partition_report_digest":report_digest,"scope_digest":scope_digest,
            "source_complete":report.complete,"global_diagnostics_count":report.diagnostics.len(),
            "global_blocking_diagnostics_count":report.diagnostics.iter().filter(|d|d.blocking).count(),
            "manifest_count":native.projects.len(),"component_count":identities.len(),
            "locked":key.1.is_some(),"activation":"unknown","graph_semantics":"potential_static_dependencies",
            "consumer_losses":["global_properties_and_compositions_may_be_discarded","empty_leaf_dependencies_may_be_added"],
            "decision_policy":"recompute_against_partition_report_no_implicit_transfer",
            "native_inputs_scope":"original_report_global_inputs_and_diagnostics_retained",
            "sbom":sbom_descriptor,
        });
        let coverage_descriptor = artifact(
            &mut artifacts,
            &mut total,
            format!("public/{partition_id}.coverage.json"),
            &coverage,
        )?;
        partitions.push(json!({"partition_id":partition_id,"project_name":project_name,"project_version":project_version,
            "sbom_serial":sbom["serialNumber"],"sbom":sbom_descriptor,"coverage":coverage_descriptor,"native_report":native_descriptor}));
    }
    // Scope labels may contain repository credentials or internal host details.
    artifact(
        &mut artifacts,
        &mut total,
        "private/scope.json".into(),
        &json!({"repository":scope.repository,"revision":scope.revision,"target_profile":scope.target_profile}),
    )?;
    let manifest = json!({"schema_version":1,"source_report_digest":source_digest,"scope_digest":scope_digest,
        "source_complete":report.complete,"activation":"unknown","partitions":partitions,
        "public_artifacts":artifacts.iter().filter(|(path,_)|path.starts_with("public/")).map(|(path,bytes)|json!({"path":path,"sha256":files::hash(bytes),"bytes":bytes.len()})).collect::<Vec<_>>(),
        "private_artifacts":artifacts.iter().filter(|(path,_)|path.starts_with("private/")).map(|(path,bytes)|json!({"path":path,"sha256":files::hash(bytes),"bytes":bytes.len()})).collect::<Vec<_>>(),
        "upload_policy":"explicit_public_artifacts_only_no_directory_upload",
        "decision_policy":"recompute_against_partition_report_no_implicit_transfer"});
    ensure!(
        serde_json::to_vec_pretty(&manifest)?
            .len()
            .saturating_add(1)
            <= vuln::MAX_INPUT_BYTES.saturating_sub(total),
        "Interchange bundle exceeds 64 MiB"
    );
    Ok(Bundle {
        manifest,
        artifacts,
    })
}
