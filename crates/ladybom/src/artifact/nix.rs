use super::{
    collect::ToolRunner,
    evidence::{nar, store_name, text},
    invalid, CollectOptions, Gap, InspectedRoot, NixOutput,
};
use crate::{error::Result, files, json};
use serde_json::Value;
use std::{collections::BTreeSet, ffi::OsString};

fn required<'a>(row: &'a Value, key: &str) -> Result<&'a str> {
    row.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("Missing Nix string field: {key}")))
}
fn optional(row: &Value, key: &str) -> Result<Option<String>> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => {
            text(s)?;
            Ok(Some(s.clone()))
        }
        _ => Err(invalid(format!("Invalid Nix identity field: {key}"))),
    }
}
fn arguments(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

pub(super) fn collect_outputs(
    options: &CollectOptions,
    inventory: &InspectedRoot,
    runner: &ToolRunner,
    budget: &mut super::budget::Budget,
) -> Result<(Vec<NixOutput>, Vec<Gap>)> {
    let prefix = format!(
        "{}/",
        options
            .store_relative
            .to_str()
            .ok_or_else(|| invalid("Non-UTF8 store location"))?
    );
    let mut members = BTreeSet::new();
    for file in &inventory.files {
        if let Some(name) = file.path.strip_prefix(&prefix) {
            if !name.contains('/') {
                if file.kind != "file" && file.kind != "directory" {
                    return Err(invalid("Linked Nix store member"));
                }
                let path = format!("/nix/store/{name}");
                store_name(&path)?;
                members.insert(path);
            }
        }
    }
    if members.is_empty() || members.len() > 10_000 {
        return Err(invalid("Empty or oversized embedded Nix store"));
    }
    let mut outputs = Vec::new();
    let mut gaps = Vec::new();
    for path in &members {
        let mut output = NixOutput {
            store_path: path.clone(),
            nar_hash: None,
            observed_nar_hash: None,
            deriver: None,
            derivation_sha256: None,
            output_name: None,
            name: None,
            version: None,
            references: Vec::new(),
        };
        let query = runner.nix(arguments(&[
            "path-info",
            "--offline",
            "--json",
            "--json-format",
            "1",
            path,
        ]));
        let bytes = match query {
            Ok(bytes) => bytes,
            Err(crate::error::Error::ProcessExit { .. }) => {
                budget.push_gap(&mut gaps, Gap {
                    code: "nix_metadata_unavailable".into(),
                    path: path.clone(),
                    message:
                        "Native store metadata unavailable; delivered output remains unidentified"
                            .into(),
                })?;
                outputs.push(output);
                continue;
            }
            Err(error) => return Err(error),
        };
        let value = json::parse(&bytes)?;
        let rows = value
            .as_object()
            .ok_or_else(|| invalid("Expected Nix path-info object"))?;
        if rows.len() != 1 {
            return Err(invalid("Unexpected Nix path-info result count"));
        }
        let row = rows
            .get(path)
            .ok_or_else(|| invalid("Nix path-info returned a different path"))?;
        let hash = required(row, "narHash")?;
        if !nar(hash) {
            return Err(invalid("Expected SHA-256 NAR hash"));
        }
        let Some(deriver) = row
            .get("deriver")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && *v != "unknown-deriver")
        else {
            budget.push_gap(
                &mut gaps,
                Gap {
                    code: "nix_metadata_unavailable".into(),
                    path: path.clone(),
                    message: "Native derivation unavailable".into(),
                },
            )?;
            outputs.push(output);
            continue;
        };
        store_name(deriver)?;
        if !deriver.ends_with(".drv") {
            return Err(invalid("Invalid Nix derivation path"));
        }
        let drv_bytes = match runner.nix(arguments(&["derivation", "show", "--offline", path])) {
            Ok(bytes) => bytes,
            Err(crate::error::Error::ProcessExit { .. }) => {
                budget.push_gap(
                    &mut gaps,
                    Gap {
                        code: "nix_metadata_unavailable".into(),
                        path: path.clone(),
                        message: "Native derivation cannot be read".into(),
                    },
                )?;
                outputs.push(output);
                continue;
            }
            Err(error) => return Err(error),
        };
        let document = json::parse(&drv_bytes)?;
        if document.get("version").and_then(Value::as_u64) != Some(4) {
            return Err(invalid(
                "Unsupported Nix derivation JSON format; expected version 4",
            ));
        }
        let derivations = document
            .get("derivations")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Missing Nix derivations"))?;
        if derivations.len() != 1 {
            return Err(invalid("Unexpected Nix derivation count"));
        }
        // Resolve through the delivered output. A cached historical deriver may
        // be absent while Nix knows another valid derivation for the same output.
        let (drv_name, derivation) = derivations
            .iter()
            .next()
            .ok_or_else(|| invalid("Missing resolved derivation"))?;
        let resolved_deriver = format!("/nix/store/{drv_name}");
        store_name(&resolved_deriver)?;
        if !resolved_deriver.ends_with(".drv") {
            return Err(invalid("Invalid resolved derivation path"));
        }
        let native_outputs = derivation
            .get("outputs")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Missing derivation outputs"))?;
        let name = store_name(path)?;
        let matching: Vec<_> = native_outputs
            .iter()
            .filter(|(_, v)| v.get("path").and_then(Value::as_str) == Some(name))
            .collect();
        if matching.len() != 1 {
            return Err(invalid("Derivation does not uniquely declare this output"));
        }
        let copied = options.rootfs.join(&options.store_relative).join(name);
        let hash_bytes = runner.nix(vec![
            "hash".into(),
            "path".into(),
            "--type".into(),
            "sha256".into(),
            copied.into_os_string(),
        ])?;
        let observed = std::str::from_utf8(&hash_bytes)
            .map_err(|_| invalid("Invalid Nix hash output"))?
            .trim();
        if observed != hash {
            return Err(invalid(format!(
                "Embedded Nix output differs from native NAR: {path}"
            )));
        }
        output.nar_hash = Some(hash.into());
        output.observed_nar_hash = Some(observed.into());
        output.deriver = Some(resolved_deriver);
        output.derivation_sha256 = Some(files::hash(&drv_bytes));
        output.output_name = Some(matching[0].0.clone());
        let attrs = derivation
            .get("structuredAttrs")
            .filter(|v| v.is_object())
            .or_else(|| derivation.get("env"))
            .ok_or_else(|| invalid("Missing derivation attributes"))?;
        output.name = optional(attrs, "pname")?;
        output.version = optional(attrs, "version")?;
        if output.name.is_some() && output.version.is_none() {
            budget.push_gap(
                &mut gaps,
                Gap {
                    code: "nix_version_unknown".into(),
                    path: path.clone(),
                    message: "Package derivation has no observed version".into(),
                },
            )?;
        }
        let refs = row
            .get("references")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Missing Nix references"))?;
        if refs.len() > 10_000 {
            return Err(invalid("Nix reference budget exceeded"));
        }
        let mut unique = BTreeSet::new();
        for value in refs {
            let reference = value
                .as_str()
                .ok_or_else(|| invalid("Invalid Nix reference"))?;
            store_name(reference)?;
            budget.reference()?;
            if !unique.insert(reference.to_owned()) {
                return Err(invalid("Duplicate Nix reference"));
            }
            if !members.contains(reference) {
                budget.push_gap(
                    &mut gaps,
                    Gap {
                        code: "nix_reference_not_delivered".into(),
                        path: reference.into(),
                        message: "Native reference absent from delivered store".into(),
                    },
                )?;
            }
        }
        output.references = unique.into_iter().collect();
        outputs.push(output);
    }
    Ok((outputs, gaps))
}
