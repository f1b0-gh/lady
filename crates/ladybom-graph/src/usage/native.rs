//! Explicit import of native JSON reports. Never launches a tool or loads its config.
//! Accepted shapes follow cargo-machete --json, Knip's json reporter and deptry --json-output.
//! Report paths must be relative to the analyzed project root (optional leading ./).
//! Absolute paths are rejected: this API cannot attest a host path or remap tool working directories.
use super::{invalid, UsageReport};
use crate::ensure;
use ladybom::{error::Result, files};
use serde_json::Value;

struct Hint {
    manifest: String,
    name: String,
    kind: Option<&'static str>,
}
fn string(value: &Value) -> Result<&str> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid("Native report: string required".into()))?;
    ensure!(
        !text.is_empty() && text.len() <= 4096 && !text.chars().any(char::is_control),
        "Native report: invalid string"
    );
    Ok(text)
}
fn array(value: &Value) -> Result<&Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| invalid("Native report: array required".into()))
}
fn path(value: &Value) -> Result<String> {
    let raw = string(value)?;
    let path = raw.strip_prefix("./").unwrap_or(raw);
    ladybom::sources::relative_path(path)?;
    Ok(path.into())
}
/// Attach bounded, explicitly supplied evidence without promoting uncertainty or
/// overriding a local source reference. Imports are not attested to the snapshot.
/// Paths must be relative to the analyzed root; absolute native paths require
/// explicit normalization by the caller. Validation is atomic: malformed input
/// leaves the report unchanged.
pub fn enrich(report: &mut UsageReport, tool: &str, raw: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(raw)?;
    ensure!(
        bytes.len() <= 8 * 1024 * 1024,
        "Native report exceeds 8 MiB"
    );
    ensure!(report.schema_version == 1, "Unknown usage report version");
    let mut hints = Vec::new();
    match tool {
        "cargo-machete" => {
            let crates = match raw.get("crates") {
                Some(value) => array(value)?.as_slice(),
                None if raw.as_object().is_some_and(|object| object.is_empty()) => &[],
                _ => {
                    return Err(invalid(
                        "cargo-machete report: crates object or empty object required".into(),
                    ))
                }
            };
            for entry in crates {
                let manifest = path(&entry["manifest_path"])?;
                for name in array(&entry["unused"])? {
                    hints.push(Hint {
                        manifest: manifest.clone(),
                        name: string(name)?.into(),
                        kind: None,
                    });
                }
            }
        }
        "knip" => {
            for entry in array(&raw["issues"])? {
                let manifest = path(&entry["file"])?;
                for (field, kind) in [
                    ("dependencies", "runtime"),
                    ("devDependencies", "dev"),
                    ("optionalPeerDependencies", "peer"),
                ] {
                    if let Some(values) = entry.get(field) {
                        for value in array(values)? {
                            hints.push(Hint {
                                manifest: manifest.clone(),
                                name: string(&value["name"])?.into(),
                                kind: Some(kind),
                            });
                        }
                    }
                }
            }
        }
        "deptry" => {
            for entry in array(raw)? {
                let code = string(&entry["error"]["code"])?;
                let manifest = path(&entry["location"]["file"])?;
                let name = string(&entry["module"])?;
                if code == "DEP002" {
                    hints.push(Hint {
                        manifest,
                        name: name.into(),
                        kind: None,
                    });
                }
            }
        }
        _ => return Err(invalid(format!("Unsupported usage tool: {tool}"))),
    }
    ensure!(hints.len() <= 20000, "Maximum 20000 indices natifs");
    let mut matches = Vec::new();
    for hint in &hints {
        let indices: Vec<_> = report
            .findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                f.declaration.manifest == hint.manifest
                    && f.declaration.name == hint.name
                    && hint.kind.is_none_or(|kind| kind == f.declaration.kind)
            })
            .map(|(i, _)| i)
            .collect();
        ensure!(
            !indices.is_empty(),
            "Native lead without a selected declaration: {}: {}",
            hint.manifest,
            hint.name
        );
        matches.extend(indices);
    }
    matches.sort();
    matches.dedup();
    let hash = files::hash(&bytes);
    for index in matches {
        let finding = &mut report.findings[index];
        let evidence = format!("{tool}: absence of references reported (report sha256 {hash})");
        if !finding.evidence.contains(&evidence) {
            finding.evidence.push(evidence);
        }
        let limitation="External report is not attested to the sources; lead requires confirmation and does not override local references".to_owned();
        if !finding.limitations.contains(&limitation) {
            finding.limitations.push(limitation);
        }
    }
    report.complete = false;
    Ok(())
}
