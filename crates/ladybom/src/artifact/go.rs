use super::{collect::ToolRunner, evidence::text, invalid, CollectOptions, Gap, InspectedRoot};
use crate::{
    error::{Error, Result},
    files, json,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
    time::Instant,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoModule {
    pub path: String,
    pub version: String,
    pub sum: String,
    pub replacement: Option<Box<GoModule>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoBinary {
    pub path: String,
    pub sha256: String,
    pub metadata_sha256: String,
    pub go_version: String,
    pub import_path: String,
    pub main: Option<GoModule>,
    pub dependencies: Vec<GoModule>,
    pub settings_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfFile {
    pub path: String,
    pub sha256: String,
    pub classification: String,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "PascalCase")]
struct RawModule {
    path: String,
    version: String,
    sum: String,
    replace: Option<Box<RawModule>>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct Setting {
    key: String,
    value: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
struct BuildInfo {
    go_version: String,
    path: String,
    #[serde(default)]
    main: RawModule,
    deps: Option<Vec<RawModule>>,
    settings: Option<Vec<Setting>>,
}
impl RawModule {
    fn convert(self, nested: bool) -> Result<GoModule> {
        text(&self.path)?;
        if self.version.len() > 4096
            || self.sum.len() > 4096
            || self.version.chars().any(char::is_control)
            || self.sum.chars().any(char::is_control)
            || (nested && self.replace.is_some())
        {
            return Err(invalid("Invalid Go module metadata or replacement chain"));
        }
        Ok(GoModule {
            path: self.path,
            version: self.version,
            sum: self.sum,
            replacement: self
                .replace
                .map(|m| m.convert(true).map(Box::new))
                .transpose()?,
        })
    }
}

fn region(file: &mut File, offset: u64, size: u64, max: u64) -> Result<Vec<u8>> {
    if size > max
        || offset
            .checked_add(size)
            .is_none_or(|end| end > file.metadata().map(|m| m.len()).unwrap_or(0))
    {
        return Err(invalid("Truncated or oversized ELF section"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0u8; size as usize];
    file.read_exact(&mut data)?;
    Ok(data)
}
fn u16le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}
fn u32le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
fn u64le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
/// Classification only. The explicit trusted reader parses Go's section payload.
fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(
            std::io::Error::new(std::io::ErrorKind::TimedOut, "ELF inspection time limit").into(),
        );
    }
    Ok(())
}
fn has_go_section(file: &mut File, deadline: Instant) -> Result<bool> {
    check_deadline(deadline)?;
    let header = region(file, 0, 64, 64)?;
    if header.get(..7) != Some(b"\x7fELF\x02\x01\x01")
        || u16le(&header, 18) != 62
        || u32le(&header, 20) != 1
        || u16le(&header, 52) != 64
        || u16le(&header, 58) != 64
    {
        return Err(invalid(
            "Only ELF64 little-endian x86_64 section tables are qualified",
        ));
    }
    let count = u16le(&header, 60) as usize;
    let strings = u16le(&header, 62) as usize;
    if count == 0 || count > 4096 || strings == 0 || strings >= count {
        return Err(invalid("Unsupported ELF section table"));
    }
    let sections = region(file, u64le(&header, 40), (count * 64) as u64, 4096 * 64)?;
    let names_header = &sections[strings * 64..(strings + 1) * 64];
    if u32le(names_header, 4) != 3 {
        return Err(invalid("Invalid ELF section-name table"));
    }
    let names = region(
        file,
        u64le(names_header, 24),
        u64le(names_header, 32),
        1024 * 1024,
    )?;
    // One bounded scan proves every offset up to the last NUL has a terminator.
    // Do not rescan the 1 MiB name table once per section.
    let last_terminator = names
        .iter()
        .rposition(|b| *b == 0)
        .ok_or_else(|| invalid("Unterminated ELF section names"))?;
    let mut found = false;
    for section in sections.as_chunks::<64>().0 {
        check_deadline(deadline)?;
        let start = u32le(section, 0) as usize;
        let bytes = names
            .get(start..)
            .ok_or_else(|| invalid("Invalid ELF section name offset"))?;
        if start > last_terminator {
            return Err(invalid("Unterminated ELF section name"));
        }
        if bytes.starts_with(b".go.buildinfo\0") {
            if found
                || u64le(section, 8) & 0x800 != 0
                || u64le(section, 32) < 32
                || u64le(section, 32) > 1024 * 1024
                || u64le(section, 24)
                    .checked_add(u64le(section, 32))
                    .is_none_or(|end| end > file.metadata().map(|m| m.len()).unwrap_or(0))
            {
                return Err(invalid("Unsupported, duplicate or truncated Go section"));
            }
            found = true;
        }
    }
    Ok(found)
}

pub(super) fn versioned(version: &str) -> bool {
    version
        .strip_prefix('v')
        .is_some_and(|v| semver::Version::parse(v).is_ok())
}
pub(super) fn module_gaps(module: &GoModule, binary: &str, gaps: &mut Vec<Gap>) -> Result<()> {
    text(&module.path)?;
    if module.version.len() > 4096
        || module.sum.len() > 4096
        || module.version.chars().any(char::is_control)
        || module.sum.chars().any(char::is_control)
    {
        return Err(invalid("Invalid Go module value"));
    }
    if let Some(replacement) = &module.replacement {
        if replacement.replacement.is_some() {
            return Err(invalid("Chained Go replacement"));
        }
        // Validate all replacement fields even when no version is resolved.
        let mut replacement_gaps = Vec::new();
        module_gaps(replacement, binary, &mut replacement_gaps)?;
        if replacement.version.is_empty() {
            gaps.push(Gap {
                code: "go_local_replacement".into(),
                path: binary.into(),
                message: format!(
                    "Local replacement for module {} has no resolved version",
                    module.path
                ),
            });
        } else {
            gaps.extend(replacement_gaps);
        }
    } else if !versioned(&module.version) {
        gaps.push(Gap {
            code: "go_module_version_unknown".into(),
            path: binary.into(),
            message: format!("Module {} has no qualified version", module.path),
        });
    }
    Ok(())
}

pub(super) fn collect_binaries(
    options: &CollectOptions,
    inventory: &InspectedRoot,
    runner: &ToolRunner,
    budget: &mut super::budget::Budget,
) -> Result<(Vec<GoBinary>, Vec<ElfFile>, Vec<Gap>)> {
    let deadline = runner.inspection_deadline();
    let mut binaries = Vec::new();
    let mut metadata_bytes = 0usize;
    let mut module_count = 0usize;
    let mut elves = Vec::new();
    let mut gaps = Vec::new();
    for entry in &inventory.files {
        check_deadline(deadline)?;
        if entry.kind != "file" {
            continue;
        }
        let path = options.rootfs.join(&entry.path);
        let mut file = files::open_regular(&path)?;
        let mut magic = [0; 4];
        let n = file.read(&mut magic)?;
        if n != 4 || magic != *b"\x7fELF" {
            continue;
        }
        let sha256 = entry
            .sha256
            .clone()
            .ok_or_else(|| invalid("Missing ELF digest"))?;
        let mut elf = ElfFile {
            path: entry.path.clone(),
            sha256: sha256.clone(),
            classification: "non-go".into(),
        };
        let go = match has_go_section(&mut file, deadline) {
            Ok(go) => go,
            Err(Error::InvalidInput { .. }) => {
                elf.classification = "unsupported".into();
                budget.push_gap(
                    &mut gaps,
                    Gap {
                        code: "elf_format_unsupported".into(),
                        path: entry.path.clone(),
                        message: "ELF section layout is unsupported or malformed".into(),
                    },
                )?;
                elves.push(elf);
                continue;
            }
            Err(error) => return Err(error),
        };
        if !go {
            elves.push(elf);
            continue;
        }
        let bytes = match runner.call(
            &options.go_reader,
            vec![path.into_os_string()],
            1024 * 1024,
            deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .min(30),
        ) {
            Ok(bytes) => bytes,
            Err(Error::ProcessExit { .. }) => {
                elf.classification = "go-unresolved".into();
                budget.push_gap(
                    &mut gaps,
                    Gap {
                        code: "go_metadata_unavailable".into(),
                        path: entry.path.clone(),
                        message: "Go section found but trusted reader could not decode it".into(),
                    },
                )?;
                elves.push(elf);
                continue;
            }
            Err(error) => return Err(error),
        };
        check_deadline(deadline)?;
        metadata_bytes = metadata_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| invalid("Go metadata byte overflow"))?;
        if metadata_bytes > 64 * 1024 * 1024 {
            return Err(invalid("Total Go metadata byte budget exceeded"));
        }
        let info: BuildInfo = serde_json::from_value(json::parse(&bytes)?)?;
        text(&info.go_version)?;
        text(&info.path)?;
        let dependencies = info.deps.unwrap_or_default();
        let settings = info.settings.unwrap_or_default();
        module_count = module_count
            .checked_add(dependencies.len() + 1)
            .ok_or_else(|| invalid("Go module count overflow"))?;
        if module_count > 200_000 {
            return Err(invalid("Total Go module count budget exceeded"));
        }

        if dependencies.len() > 10_000 || settings.len() > 1024 {
            return Err(invalid("Go metadata count budget exceeded"));
        }
        let settings_hash = files::hash(&serde_json::to_vec(&settings)?);
        let mut binary_gaps = Vec::new();
        let main = if info.main.path.is_empty()
            && info.main.version.is_empty()
            && info.main.sum.is_empty()
            && info.main.replace.is_none()
        {
            budget.push_gap(
                &mut gaps,
                Gap {
                    code: "go_main_module_unknown".into(),
                    path: entry.path.clone(),
                    message: "Binary has no main module identity in Go build metadata".into(),
                },
            )?;
            None
        } else {
            Some(info.main.convert(false)?)
        };
        let mut seen = BTreeSet::new();
        if let Some(main) = &main {
            module_gaps(main, &entry.path, &mut binary_gaps)?;
            seen.insert(main.path.clone());
        }
        let mut modules = Vec::new();
        for raw in dependencies {
            let module = raw.convert(false)?;
            if !seen.insert(module.path.clone()) {
                return Err(invalid("Duplicate Go module identity in binary"));
            }
            module_gaps(&module, &entry.path, &mut binary_gaps)?;
            modules.push(module);
        }
        for gap in binary_gaps {
            budget.push_gap(&mut gaps, gap)?;
        }
        modules.sort_by(|a, b| a.path.cmp(&b.path));
        if !info
            .go_version
            .strip_prefix("go")
            .is_some_and(|v| semver::Version::parse(v).is_ok())
        {
            budget.push_gap(
                &mut gaps,
                Gap {
                    code: "go_compiler_unknown".into(),
                    path: entry.path.clone(),
                    message: "Go compiler version is not a qualified release".into(),
                },
            )?;
        }
        elf.classification = "go".into();
        elves.push(elf);
        binaries.push(GoBinary {
            path: entry.path.clone(),
            sha256,
            metadata_sha256: files::hash(&bytes),
            go_version: info.go_version,
            import_path: info.path,
            main,
            dependencies: modules,
            settings_sha256: settings_hash,
        });
    }
    Ok((binaries, elves, gaps))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_elf_inspection_is_an_operational_refusal() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        assert!(
            matches!(has_go_section(&mut file, expired), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        Ok(())
    }
}
