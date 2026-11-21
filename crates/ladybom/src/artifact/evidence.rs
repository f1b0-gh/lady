use super::{
    filesystem::{is_digest, relative, validate_entry},
    invalid, InspectedRoot,
};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub rootfs: PathBuf,
    pub manifest: PathBuf,
    pub archive: PathBuf,
    pub store_relative: PathBuf,
    pub nix: PathBuf,
    pub go_reader: PathBuf,
    pub archive_checker: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    pub name: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gap {
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NixOutput {
    pub store_path: String,
    pub nar_hash: Option<String>,
    pub observed_nar_hash: Option<String>,
    pub deriver: Option<String>,
    pub derivation_sha256: Option<String>,
    pub output_name: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub role: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCheck {
    pub archive_sha256: String,
    pub manifest_sha256: String,
    pub tool_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema_version: u32,
    pub archive: ArtifactFile,
    pub inventory: InspectedRoot,
    pub store_relative: String,
    pub nix_outputs: Vec<NixOutput>,
    pub go_binaries: Vec<super::GoBinary>,
    pub elf_files: Vec<super::ElfFile>,
    pub tools: Vec<Tool>,
    pub archive_check: ArchiveCheck,
    pub gaps: Vec<Gap>,
}

pub(super) fn text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(invalid("Invalid artifact identity text"));
    }
    Ok(())
}

pub(super) fn store_name(path: &str) -> Result<&str> {
    let name = path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| invalid("Expected Nix store path"))?;
    let Some((hash, suffix)) = name.split_once('-') else {
        return Err(invalid("Malformed Nix store member"));
    };
    if hash.len() != 32
        || !hash
            .bytes()
            .all(|c| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&c))
        || suffix.is_empty()
        || name.len() > 255
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-._?=".contains(&b))
    {
        return Err(invalid("Malformed Nix store member"));
    }
    Ok(name)
}

pub(super) fn nar(value: &str) -> bool {
    value.strip_prefix("sha256-").is_some_and(|s| {
        s.len() == 44
            && s.ends_with('=')
            && s.as_bytes()[..43]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
    })
}

impl Evidence {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.inventory.files.len() > 200_000
            || self.nix_outputs.len() > 10_000
            || self.gaps.len() > 200_000
            || self.archive.bytes > 32 * 1024 * 1024 * 1024
            || !is_digest(&self.archive.sha256)
            || !is_digest(&self.inventory.manifest_sha256)
        {
            return Err(invalid(
                "Invalid artifact evidence version, bounds or hashes",
            ));
        }
        text(&self.archive.name)?;
        relative(&self.archive.name)?;
        if self.archive.name.contains('/') {
            return Err(invalid("Archive name must not contain a host path"));
        }
        relative(&self.store_relative)?;
        relative(&self.inventory.manifest_path)?;
        let mut paths = BTreeSet::new();
        let mut members = BTreeSet::new();
        let mut bytes = 0u64;
        let prefix = format!("{}/", self.store_relative);
        for entry in &self.inventory.files {
            validate_entry(entry)?;
            if entry.path == self.inventory.manifest_path || !paths.insert(entry.path.as_str()) {
                return Err(invalid("Duplicate or excluded artifact path"));
            }
            bytes = bytes
                .checked_add(entry.bytes.unwrap_or(0))
                .ok_or_else(|| invalid("Byte budget overflow"))?;
            if bytes > 32 * 1024 * 1024 * 1024 {
                return Err(invalid("Artifact evidence byte budget exceeded"));
            }
            if let Some(member) = entry.path.strip_prefix(&prefix) {
                if !member.contains('/') {
                    if entry.kind != "directory" && entry.kind != "file" {
                        return Err(invalid("Linked Nix store member"));
                    }
                    let path = format!("/nix/store/{member}");
                    store_name(&path)?;
                    members.insert(path);
                }
            }
        }
        if bytes != self.inventory.content_bytes {
            return Err(invalid("Inconsistent artifact byte total"));
        }
        let mut seen = BTreeSet::new();
        let mut budget = super::budget::Budget::default();
        for output in &self.nix_outputs {
            store_name(&output.store_path)?;
            if !members.contains(&output.store_path) || !seen.insert(output.store_path.clone()) {
                return Err(invalid("Missing or duplicate delivered Nix output"));
            }
            let resolved = output.nar_hash.is_some()
                && output.deriver.is_some()
                && output.derivation_sha256.is_some()
                && output.output_name.is_some();
            if resolved {
                if !output.nar_hash.as_deref().is_some_and(nar)
                    || output.nar_hash != output.observed_nar_hash
                    || !output.derivation_sha256.as_deref().is_some_and(is_digest)
                {
                    return Err(invalid("Inconsistent Nix content binding"));
                }
                let deriver = output
                    .deriver
                    .as_deref()
                    .ok_or_else(|| invalid("Missing deriver"))?;
                store_name(deriver)?;
                if !deriver.ends_with(".drv") {
                    return Err(invalid("Invalid derivation path"));
                }
            } else if output.name.is_some()
                || output.version.is_some()
                || !self
                    .gaps
                    .iter()
                    .any(|g| g.path == output.store_path && g.code == "nix_metadata_unavailable")
            {
                return Err(invalid("Unresolved Nix identity without coverage gap"));
            }
            for value in [&output.output_name, &output.name, &output.version]
                .into_iter()
                .flatten()
            {
                text(value)?;
            }
            if output.name.is_some()
                && output.version.is_none()
                && !self
                    .gaps
                    .iter()
                    .any(|g| g.path == output.store_path && g.code == "nix_version_unknown")
            {
                return Err(invalid("Unknown Nix version without coverage gap"));
            }
            if output.references.len() > 10_000 {
                return Err(invalid("Too many Nix references"));
            }
            let mut refs = BTreeSet::new();
            for reference in &output.references {
                budget.reference()?;
                store_name(reference)?;
                if !refs.insert(reference) {
                    return Err(invalid("Duplicate Nix reference"));
                }
                if !members.contains(reference)
                    && !self
                        .gaps
                        .iter()
                        .any(|g| g.path == *reference && g.code == "nix_reference_not_delivered")
                {
                    return Err(invalid("External Nix reference without coverage gap"));
                }
            }
        }
        if seen != members {
            return Err(invalid("Nix evidence omits delivered members"));
        }
        if self.go_binaries.len() > 10_000 || self.elf_files.len() > 200_000 {
            return Err(invalid("Go/ELF evidence count limit"));
        }
        let file_map: std::collections::BTreeMap<_, _> = self
            .inventory
            .files
            .iter()
            .map(|f| (f.path.as_str(), f))
            .collect();
        let mut elf_map = std::collections::BTreeMap::new();
        for elf in &self.elf_files {
            let file = file_map
                .get(elf.path.as_str())
                .ok_or_else(|| invalid("ELF not delivered"))?;
            if file.kind != "file"
                || file.sha256.as_deref() != Some(elf.sha256.as_str())
                || !["go", "non-go", "unsupported", "go-unresolved"]
                    .contains(&elf.classification.as_str())
                || elf_map
                    .insert(elf.path.as_str(), elf.classification.as_str())
                    .is_some()
            {
                return Err(invalid("Invalid ELF content binding or classification"));
            }
            let required = match elf.classification.as_str() {
                "unsupported" => Some("elf_format_unsupported"),
                "go-unresolved" => Some("go_metadata_unavailable"),
                _ => None,
            };
            if required.is_some_and(|code| {
                !self
                    .gaps
                    .iter()
                    .any(|g| g.path == elf.path && g.code == code)
            }) {
                return Err(invalid("Unqualified ELF without coverage gap"));
            }
        }
        let mut binary_paths = BTreeSet::new();
        let mut module_count = 0usize;
        for binary in &self.go_binaries {
            if elf_map.get(binary.path.as_str()) != Some(&"go")
                || !binary_paths.insert(binary.path.as_str())
                || !is_digest(&binary.sha256)
                || !is_digest(&binary.metadata_sha256)
                || !is_digest(&binary.settings_sha256)
                || file_map
                    .get(binary.path.as_str())
                    .and_then(|f| f.sha256.as_deref())
                    != Some(binary.sha256.as_str())
            {
                return Err(invalid("Invalid Go binary content binding"));
            }
            text(&binary.go_version)?;
            text(&binary.import_path)?;
            module_count = module_count
                .checked_add(binary.dependencies.len() + 1)
                .ok_or_else(|| invalid("Go module count overflow"))?;
            if binary.dependencies.len() > 10_000 || module_count > 200_000 {
                return Err(invalid("Go module budget exceeded"));
            }
            let mut required = Vec::new();
            if binary.main.is_none() {
                required.push(Gap {
                    code: "go_main_module_unknown".into(),
                    path: binary.path.clone(),
                    message: String::new(),
                });
            }
            let mut modules = BTreeSet::new();
            for module in binary.main.iter().chain(&binary.dependencies) {
                if !modules.insert(module.path.as_str()) {
                    return Err(invalid("Duplicate module identity"));
                }
                super::go::module_gaps(module, &binary.path, &mut required)?;
            }
            if !binary
                .go_version
                .strip_prefix("go")
                .is_some_and(|v| semver::Version::parse(v).is_ok())
            {
                required.push(Gap {
                    code: "go_compiler_unknown".into(),
                    path: binary.path.clone(),
                    message: String::new(),
                });
            }
            for gap in required {
                if !self
                    .gaps
                    .iter()
                    .any(|g| g.code == gap.code && g.path == gap.path)
                {
                    return Err(invalid("Unknown Go resolution without coverage gap"));
                }
            }
        }
        if elf_map
            .iter()
            .any(|(path, class)| *class == "go" && !binary_paths.contains(path))
        {
            return Err(invalid("Go ELF classification without module evidence"));
        }
        let mut roles = BTreeSet::new();
        for tool in &self.tools {
            if !["nix", "go-reader", "archive-checker"].contains(&tool.role.as_str())
                || !roles.insert(tool.role.as_str())
                || !is_digest(&tool.sha256)
                || tool.bytes > 256 * 1024 * 1024
            {
                return Err(invalid("Invalid collector tool evidence"));
            }
        }
        if roles.len() != 3 {
            return Err(invalid("Missing collector tools"));
        }
        let checker = self
            .tools
            .iter()
            .find(|t| t.role == "archive-checker")
            .ok_or_else(|| invalid("Missing archive checker"))?;
        if self.archive_check.archive_sha256 != self.archive.sha256
            || self.archive_check.manifest_sha256 != self.inventory.manifest_sha256
            || self.archive_check.tool_sha256 != checker.sha256
        {
            return Err(invalid("Archive check does not bind these inputs"));
        }
        let mut gap_bytes = 0usize;
        for gap in &self.gaps {
            gap_bytes = gap_bytes
                .saturating_add(gap.code.len())
                .saturating_add(gap.path.len())
                .saturating_add(gap.message.len());
            if gap_bytes > 16 * 1024 * 1024 {
                return Err(invalid("Artifact diagnostic byte budget exceeded"));
            }
            if ![
                "nix_metadata_unavailable",
                "nix_version_unknown",
                "nix_reference_not_delivered",
                "elf_format_unsupported",
                "go_metadata_unavailable",
                "go_module_version_unknown",
                "go_main_module_unknown",
                "go_local_replacement",
                "go_compiler_unknown",
            ]
            .contains(&gap.code.as_str())
            {
                return Err(invalid("Unknown artifact coverage diagnostic"));
            }

            text(&gap.code)?;
            text(&gap.path)?;
            text(&gap.message)?;
        }
        Ok(())
    }
}
