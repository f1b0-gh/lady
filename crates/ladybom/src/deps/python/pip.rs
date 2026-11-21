//! Flat pip pin inventories. Hashes are declarations, not verified artifacts.
use super::{diagnostic, purl, requirement, Component, Diagnostic, Project, Requirement};
use crate::error::Result;
use serde_json::json;
use std::collections::BTreeMap;

struct Line {
    number: usize,
    text: String,
    ambiguous_continuation: bool,
}

struct Pin {
    requirement: Requirement,
    version: String,
    hashes: Vec<String>,
}

pub(super) fn try_parse(
    name: &str,
    content: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<Option<Project>> {
    let lines = logical_lines(content);
    let inventory = name.ends_with(".lock")
        || lines.iter().any(|line| {
            option_start(&line.text).is_some_and(|start| {
                line.text[start..].split_whitespace().any(|token| {
                    token == "--require-hashes" || token == "--hash" || token.starts_with("--hash=")
                })
            })
        });
    if !inventory {
        return Ok(None);
    }
    let mut project = Project::new("python", "pip", name);
    project.lockfile = Some(name.into());
    project.locked = true;
    project.workspace = json!({"format":"pip-requirements", "inventory_only":true});
    diagnostic(
        diagnostics,
        "pip_inventory_incomplete",
        name,
        "Inventaire pip plat : provenance, sélection des artefacts et dépendances transitives non vérifiées ; les marqueurs ne sont pas évalués",
        true,
    );
    let mut seen = BTreeMap::<(String, String, Option<String>), usize>::new();
    for line in lines {
        let reject = |diagnostics: &mut Vec<Diagnostic>, code: &str, message: &str| {
            diagnostic(
                diagnostics,
                code,
                name,
                format!("Ligne {} : {message}", line.number),
                true,
            );
        };
        if line.ambiguous_continuation {
            reject(
                diagnostics,
                "unsupported_requirement_continuation",
                "Continuation pip ambiguë non interprétée",
            );
            continue;
        }
        if line.text.contains("${") {
            reject(
                diagnostics,
                "unsupported_requirement_environment",
                "Expansion d'environnement non autorisée dans le scan",
            );
            continue;
        }
        if line.text == "--require-hashes" {
            continue;
        }
        if line.text.starts_with('-') {
            reject(
                diagnostics,
                "unsupported_requirement_option",
                "Directive pip non appliquée ; aucun fichier ni index n'est suivi",
            );
            continue;
        }
        let pin = match parse_pin(&line.text) {
            Ok(pin) => pin,
            Err(message) => {
                reject(diagnostics, "invalid_pip_requirement", message);
                continue;
            }
        };
        let key = (
            pin.requirement.name.clone(),
            pin.version.clone(),
            pin.requirement.marker.clone(),
        );
        let record = json!({"line":line.number, "hashes":pin.hashes,
                            "extras":pin.requirement.extras, "constraint":pin.requirement.constraint});
        if let Some(index) = seen.get(&key) {
            if let Some(records) =
                project.components[*index].metadata["pip"]["records"].as_array_mut()
            {
                records.push(record);
            }
            continue;
        }
        let mut metadata = json!({"pip":{"records":[record], "source_verified":false,
                                           "dependency_graph_recorded":false}});
        if let Some(marker) = &pin.requirement.marker {
            metadata["resolution-markers"] = json!([marker]);
        }
        seen.insert(key, project.components.len());
        project.components.push(Component {
            purl: Some(purl("pypi", &pin.requirement.name, &pin.version)?),
            name: pin.requirement.name,
            version: pin.version,
            context: serde_json::to_string(&json!({"pip-marker":pin.requirement.marker}))?,
            source: json!({"pip-index":"unverified"}),
            artifacts: Vec::new(),
            metadata,
        });
    }
    Ok(Some(project))
}

fn parse_pin(text: &str) -> std::result::Result<Pin, &'static str> {
    let start = option_start(text).ok_or("Empreinte de distribution absente")?;
    let requirement =
        requirement(text[..start].trim(), "runtime").map_err(|_| "Exigence PEP 508 invalide")?;
    if !requirement.source.is_null() {
        return Err("Source directe non qualifiée comme identité registry");
    }
    let specifiers = requirement
        .constraint
        .parse::<pep440_rs::VersionSpecifiers>()
        .map_err(|_| "Contrainte PEP 440 invalide")?;
    if specifiers.len() != 1 || *specifiers[0].operator() != pep440_rs::Operator::Equal {
        return Err("Une égalité PEP 440 concrète sans joker est requise");
    }
    let version = specifiers[0].version().to_string();
    let mut options = text[start..].split_whitespace();
    let mut hashes = Vec::new();
    while let Some(option) = options.next() {
        let value = if option == "--hash" {
            options.next().ok_or("Valeur de hash absente")?
        } else {
            option
                .strip_prefix("--hash=")
                .ok_or("Option de ligne pip non prise en charge")?
        };
        let (algorithm, digest) = value.split_once(':').ok_or("Hash sans algorithme")?;
        let length = match algorithm {
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => return Err("Algorithme de hash non pris en charge"),
        };
        if digest.len() != length || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Empreinte de longueur ou syntaxe invalide");
        }
        hashes.push(format!("{algorithm}:{}", digest.to_ascii_lowercase()));
    }
    if hashes.is_empty() {
        return Err("Empreinte de distribution absente");
    }
    Ok(Pin {
        requirement,
        version,
        hashes,
    })
}

/// Find options without treating quoted PEP 508 marker values as arguments.
fn option_start(text: &str) -> Option<usize> {
    let mut quote = None;
    let mut boundary = true;
    for (index, character) in text.char_indices() {
        if let Some(open) = quote {
            if character == open {
                quote = None;
            }
        } else if matches!(character, '\'' | '"') {
            quote = Some(character);
        } else if boundary && character == '-' {
            return Some(index);
        }
        boundary = character.is_whitespace();
    }
    None
}

fn logical_lines(content: &str) -> Vec<Line> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    let mut first = 1;
    let mut ambiguous = false;
    for (index, raw) in content.lines().enumerate() {
        if pending.is_empty() {
            first = index + 1;
        }
        let comment = raw.trim_start().starts_with('#');
        if !comment {
            if let Some(part) = raw.strip_suffix('\\') {
                ambiguous |= part.ends_with('\\') || part.starts_with('\\');
                pending.push_str(part);
                continue;
            }
        } else {
            // A full-line comment terminates a pending continuation in pip.
            pending.push(' ');
        }
        pending.push_str(raw);
        finish_line(&mut lines, first, &pending, ambiguous);
        pending.clear();
        ambiguous = false;
    }
    if !pending.is_empty() {
        finish_line(&mut lines, first, &pending, ambiguous);
    }
    lines
}

fn finish_line(lines: &mut Vec<Line>, number: usize, text: &str, ambiguous: bool) {
    let mut boundary = true;
    let end = text
        .char_indices()
        .find_map(|(index, character)| {
            let comment = boundary && character == '#';
            boundary = character.is_whitespace();
            comment.then_some(index)
        })
        .unwrap_or(text.len());
    let text = text[..end].trim();
    if !text.is_empty() {
        lines.push(Line {
            number,
            text: text.into(),
            ambiguous_continuation: ambiguous,
        });
    }
}
