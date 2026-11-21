use super::{evidence::store_name, go::versioned, invalid, Evidence, GoModule};
use crate::{error::Result, files};
use cyclonedx_bom::{
    models::{
        bom::{Bom, SpecVersion},
        component::{Classification, Component, Components},
        composition::{AggregateType, Composition, Compositions},
        dependency::{Dependencies, Dependency},
        hash::{Hash, HashAlgorithm, HashValue, Hashes},
        metadata::Metadata,
        property::{Properties, Property},
        tool::{Tool, Tools},
    },
    prelude::{NormalizedString, UrnUuid, Validate},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

const MAX_OUTPUT: usize = 128 * 1024 * 1024;
const MAX_COMPONENTS: usize = 200_000;

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub scope_complete: bool,
    pub os_composition_complete: bool,
    pub delivered_entries: usize,
    pub nix_outputs: usize,
    pub resolved_nix_outputs: usize,
    pub elf_files: usize,
    pub go_binaries: usize,
    pub gap_counts: BTreeMap<String, usize>,
    pub exclusions: Vec<&'static str>,
}
pub fn coverage(evidence: &Evidence) -> Result<Coverage> {
    evidence.validate()?;
    let mut counts = BTreeMap::new();
    for gap in &evidence.gaps {
        *counts.entry(gap.code.clone()).or_default() += 1;
    }
    Ok(Coverage {
        scope_complete: evidence.gaps.is_empty(),
        os_composition_complete: false,
        delivered_entries: evidence.inventory.files.len(),
        nix_outputs: evidence.nix_outputs.len(),
        resolved_nix_outputs: evidence
            .nix_outputs
            .iter()
            .filter(|n| n.deriver.is_some() && n.derivation_sha256.is_some())
            .count(),
        elf_files: evidence.elf_files.len(),
        go_binaries: evidence.go_binaries.len(),
        gap_counts: counts,
        exclusions: vec![
            "compressed-payload-components-not-enumerated",
            "non-go-static-libraries-not-enumerated",
            "file-integrity-does-not-establish-package-provenance",
            "licenses-and-vulnerabilities-not-assessed",
        ],
    })
}
fn normalize(evidence: &Evidence) -> Result<Evidence> {
    evidence.validate()?;
    let mut value = evidence.clone();
    value.inventory.files.sort_by(|a, b| a.path.cmp(&b.path));
    value
        .nix_outputs
        .sort_by(|a, b| a.store_path.cmp(&b.store_path));
    for output in &mut value.nix_outputs {
        output.references.sort();
    }
    value.tools.sort_by(|a, b| a.role.cmp(&b.role));
    value.go_binaries.sort_by(|a, b| a.path.cmp(&b.path));
    for binary in &mut value.go_binaries {
        binary.dependencies.sort_by(|a, b| a.path.cmp(&b.path));
    }
    value.elf_files.sort_by(|a, b| a.path.cmp(&b.path));
    value
        .gaps
        .sort_by(|a, b| (&a.code, &a.path, &a.message).cmp(&(&b.code, &b.path, &b.message)));
    Ok(value)
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(value)?))
}
fn reference(kind: &str, value: &impl Serialize) -> Result<String> {
    Ok(format!("ladybom:{kind}:{}", digest(value)?))
}
fn component(
    kind: Classification,
    name: &str,
    version: Option<&str>,
    reference: String,
) -> Component {
    let mut value = Component::new(kind, name, version.unwrap_or(""), Some(reference));
    if version.is_none() {
        value.version = None;
    }
    value
}
fn hashes(value: &str) -> Hashes {
    Hashes(vec![Hash {
        alg: HashAlgorithm::SHA_256,
        content: HashValue(value.into()),
    }])
}
fn property(component: &mut Component, name: &str, value: &str) {
    component
        .properties
        .get_or_insert_with(|| Properties(Vec::new()))
        .0
        .push(Property::new(name, value));
}
fn identity(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 4096
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-/+~".contains(&c))
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid(
            "Identity cannot be exported publicly without exposing opaque metadata",
        ));
    }
    Ok(())
}
fn purl(
    kind: &str,
    name: &str,
    namespace: Option<&str>,
    version: Option<&str>,
    output: Option<&str>,
) -> Result<String> {
    let mut value = packageurl::PackageUrl::new(kind, name).map_err(|e| invalid(e.to_string()))?;
    if let Some(namespace) = namespace {
        value
            .with_namespace(namespace)
            .map_err(|e| invalid(e.to_string()))?;
    }
    if let Some(version) = version {
        value
            .with_version(version)
            .map_err(|e| invalid(e.to_string()))?;
    }
    if let Some(output) = output {
        value
            .add_qualifier("output", output)
            .map_err(|e| invalid(e.to_string()))?;
    }
    Ok(value.to_string())
}
fn add(
    components: &mut BTreeMap<String, Component>,
    reference: String,
    value: Component,
) -> Result<()> {
    if components.len() >= MAX_COMPONENTS || components.insert(reference, value).is_some() {
        return Err(invalid("Component budget exceeded or duplicate identity"));
    }
    Ok(())
}
fn module_component(binary: &str, module: &GoModule) -> Result<(String, Component)> {
    identity(&module.path)?;
    let effective = module.replacement.as_deref().unwrap_or(module);
    let resolved = versioned(&effective.version);
    let name = if resolved {
        &effective.path
    } else {
        &module.path
    };
    identity(name)?;
    let reference = reference("go-module", &(binary, module))?;
    let mut value = component(
        Classification::Library,
        name,
        resolved.then_some(effective.version.as_str()),
        reference.clone(),
    );
    if resolved {
        let (namespace, short) = name
            .rsplit_once('/')
            .map_or((None, name.as_str()), |(ns, n)| (Some(ns), n));
        value.purl = Some(
            purl("golang", short, namespace, Some(&effective.version), None)?
                .parse()
                .map_err(|_| invalid("Invalid Go PURL"))?,
        );
    }
    property(
        &mut value,
        "ladybom:go:resolution",
        if resolved { "versioned" } else { "unresolved" },
    );
    property(
        &mut value,
        "ladybom:go:module-evidence-sha256",
        &digest(module)?,
    );
    property(
        &mut value,
        "ladybom:go:replacement",
        &module.replacement.is_some().to_string(),
    );
    Ok((reference, value))
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_OUTPUT.saturating_sub(self.0.len()) {
            return Err(io::Error::other("CycloneDX output exceeds 128 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(bom: Bom) -> Result<Vec<u8>> {
    let mut output = Bounded(Vec::new());
    bom.output_as_json_v1_5(&mut output)
        .map_err(|e| invalid(format!("CycloneDX serialization failed: {e}")))?;
    Ok(output.0)
}

/// Export validated collector evidence offline. This checks evidence consistency;
/// it does not authenticate its producer or reopen the original image.
pub fn write_cyclonedx(evidence: &Evidence, mut writer: impl Write) -> Result<()> {
    let evidence = normalize(evidence)?;
    let coverage = coverage(&evidence)?;
    let potential = evidence
        .inventory
        .files
        .len()
        .saturating_add(evidence.nix_outputs.len())
        .saturating_add(
            evidence
                .go_binaries
                .iter()
                .map(|b| b.dependencies.len() + 3)
                .sum::<usize>(),
        );
    if potential > MAX_COMPONENTS {
        return Err(invalid("Artifact component budget exceeded"));
    }
    let root_ref = reference("image", &evidence.archive.sha256)?;
    let mut root = component(
        Classification::OperatingSystem,
        &evidence.archive.name,
        None,
        root_ref.clone(),
    );
    root.hashes = Some(hashes(&evidence.archive.sha256));
    property(
        &mut root,
        "ladybom:artifact:archive-bytes",
        &evidence.archive.bytes.to_string(),
    );
    property(
        &mut root,
        "ladybom:artifact:inventory-sha256",
        &evidence.inventory.manifest_sha256,
    );
    let mut components = BTreeMap::new();
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut nix_refs = BTreeMap::new();
    for output in &evidence.nix_outputs {
        let name = store_name(&output.store_path)?;
        let reference = reference("nix-output", &(&output.store_path, &output.nar_hash))?;
        nix_refs.insert(output.store_path.clone(), reference.clone());
        if let Some(version) = &output.version {
            let candidate = version
                .strip_prefix("unstable-")
                .or_else(|| version.strip_prefix('v'))
                .unwrap_or(version);
            if !candidate.as_bytes().first().is_some_and(u8::is_ascii_digit)
                || !version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._+~-".contains(&b))
            {
                return Err(invalid(
                    "Nix version contains opaque metadata; public export refused",
                ));
            }
        }
        let display = output.name.as_deref().unwrap_or(name);
        identity(display)?;
        let mut value = component(
            if output.name.is_some() {
                Classification::Library
            } else {
                Classification::File
            },
            display,
            output.version.as_deref(),
            reference.clone(),
        );
        value.purl = Some(
            purl(
                "generic",
                display,
                Some("nix"),
                output.version.as_deref(),
                Some(name),
            )?
            .parse()
            .map_err(|_| invalid("Invalid Nix PURL"))?,
        );
        property(&mut value, "ladybom:nix:output", name);
        if let Some(hash) = &output.nar_hash {
            property(&mut value, "ladybom:nix:nar-hash", hash);
        }
        if let Some(hash) = &output.derivation_sha256 {
            property(&mut value, "ladybom:nix:derivation-evidence-sha256", hash);
        }
        edges
            .entry(root_ref.clone())
            .or_default()
            .insert(reference.clone());
        add(&mut components, reference, value)?;
    }
    for output in &evidence.nix_outputs {
        let source = nix_refs
            .get(&output.store_path)
            .ok_or_else(|| invalid("Missing Nix component"))?;
        for target in &output.references {
            if target == &output.store_path {
                continue;
            }
            if let Some(target) = nix_refs.get(target) {
                edges
                    .entry(source.clone())
                    .or_default()
                    .insert(target.clone());
            }
        }
    }
    let store_prefix = format!("{}/", evidence.store_relative);
    for file in &evidence.inventory.files {
        if file.kind == "directory" || file.path.starts_with(&store_prefix) {
            continue;
        }
        let reference = reference("file", file)?;
        let mut value = component(Classification::File, &file.path, None, reference.clone());
        if let Some(hash) = &file.sha256 {
            value.hashes = Some(hashes(hash));
        }
        property(&mut value, "ladybom:file:kind", &file.kind);
        property(
            &mut value,
            "ladybom:file:mode",
            &format!("{:04o}", file.mode),
        );
        if let Some(target) = &file.target {
            property(
                &mut value,
                "ladybom:file:link-target-sha256",
                &files::hash(target.as_bytes()),
            );
        }
        edges
            .entry(root_ref.clone())
            .or_default()
            .insert(reference.clone());
        add(&mut components, reference, value)?;
    }
    for binary in &evidence.go_binaries {
        let binary_ref = reference("go-binary", &(&binary.path, &binary.sha256))?;
        let mut value = component(Classification::File, &binary.path, None, binary_ref.clone());
        value.hashes = Some(hashes(&binary.sha256));
        property(
            &mut value,
            "ladybom:go:buildinfo-sha256",
            &binary.metadata_sha256,
        );
        property(
            &mut value,
            "ladybom:go:settings-sha256",
            &binary.settings_sha256,
        );
        if binary
            .go_version
            .strip_prefix("go")
            .is_some_and(|v| semver::Version::parse(v).is_ok())
        {
            property(&mut value, "ladybom:go:compiler", &binary.go_version);
        } else {
            property(
                &mut value,
                "ladybom:go:compiler-evidence-sha256",
                &files::hash(binary.go_version.as_bytes()),
            );
        }
        let owner = binary
            .path
            .strip_prefix(&store_prefix)
            .and_then(|s| s.split('/').next())
            .and_then(|s| nix_refs.get(&format!("/nix/store/{s}")))
            .unwrap_or(&root_ref);
        edges
            .entry(owner.clone())
            .or_default()
            .insert(binary_ref.clone());
        add(&mut components, binary_ref.clone(), value)?;
        for module in binary.main.iter().chain(&binary.dependencies) {
            let (reference, value) = module_component(&binary.path, module)?;
            edges
                .entry(binary_ref.clone())
                .or_default()
                .insert(reference.clone());
            add(&mut components, reference, value)?;
        }
        if let Some(version) = binary
            .go_version
            .strip_prefix("go")
            .filter(|v| semver::Version::parse(v).is_ok())
        {
            let reference = reference("go-stdlib", &(&binary.path, version))?;
            let mut value = component(
                Classification::Library,
                "Go standard library",
                Some(version),
                reference.clone(),
            );
            value.purl = Some(
                purl("golang", "stdlib", None, Some(version), None)?
                    .parse()
                    .map_err(|_| invalid("Invalid stdlib PURL"))?,
            );
            property(
                &mut value,
                "ladybom:go:version-evidence",
                "compiler build metadata; individual standard packages are not enumerated",
            );
            edges
                .entry(binary_ref.clone())
                .or_default()
                .insert(reference.clone());
            add(&mut components, reference, value)?;
        }
    }
    let mut bom=Bom {serial_number:None,spec_version:SpecVersion::V1_5,metadata:Some(Metadata {component:Some(root),
        tools:Some(Tools::List(vec![Tool {name:Some(NormalizedString::new("ladybom")),version:Some(NormalizedString::new(env!("CARGO_PKG_VERSION"))),..Tool::default()}])),..Metadata::default()}),
        components:Some(Components(components.into_values().collect())),
        dependencies:Some(Dependencies(edges.into_iter().map(|(dependency_ref,dependencies)|Dependency {dependency_ref,dependencies:dependencies.into_iter().collect()}).collect())),
        compositions:Some(Compositions(vec![Composition {bom_ref:None,aggregate:if coverage.scope_complete{AggregateType::Unknown}else{AggregateType::Incomplete},assemblies:None,dependencies:None,vulnerabilities:None,signature:None}])),
        properties:Some(Properties(vec![Property::new("ladybom:artifact:evidence-sha256",&digest(&evidence)?),
            Property::new("ladybom:artifact:coverage",&serde_json::to_string(&coverage)?),
            Property::new("ladybom:artifact:semantics","Collector-observed file integrity, Nix references and Go build metadata. Evidence producer is not authenticated. No global OS completeness or vulnerability claim.")])),..Bom::default()};
    let validation = bom.validate_version(SpecVersion::V1_5);
    if !validation.passed() {
        return Err(invalid(format!(
            "Invalid artifact CycloneDX: {validation:?}"
        )));
    }
    let content = encode(bom.clone())?;
    let serial = crate::deps::cyclonedx::serial_from_digest(&files::hash(&content))?;
    bom.serial_number = Some(
        UrnUuid::new(serial).map_err(|e| invalid(format!("Invalid CycloneDX serial: {e:?}")))?,
    );
    writer.write_all(&encode(bom)?)?;
    Ok(())
}
