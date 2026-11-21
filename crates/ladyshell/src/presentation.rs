use crate::error::Result;
use serde_json::Value;
use std::io::Write;
fn visible(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
pub fn sync(value: &Value, out: &mut impl Write) -> Result<()> {
    let changes = value["changes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    for change in changes {
        if let Some(path) = change.as_str() {
            writeln!(out, "Exporté  {}", visible(path))?;
            continue;
        }
        let label = match change["action"].as_str() {
            Some("add") => "Ajouté  ",
            Some("delete") => "Supprimé",
            _ => "Modifié ",
        };
        writeln!(
            out,
            "{label} {}",
            visible(change["path"].as_str().unwrap_or("?"))
        )?;
    }
    if let Some(deletions) = value["deletions"].as_array() {
        for path in deletions {
            writeln!(
                out,
                "Supprimé {} (dans la sandbox)",
                visible(path.as_str().unwrap_or("?"))
            )?;
        }
    }
    if let Some(conflicts) = value["conflicts"].as_array().filter(|v| !v.is_empty()) {
        for path in conflicts {
            writeln!(out, "Conflit  {}", visible(path.as_str().unwrap_or("?")))?;
        }
        writeln!(
            out,
            "\nApplication bloquée : {} conflit(s). Aucun fichier hôte modifié.",
            conflicts.len()
        )?;
    } else if value["applied"] == true {
        if changes.is_empty() {
            writeln!(out, "Projet déjà à jour.")?;
        } else {
            writeln!(
                out,
                "\n{} changement{} appliqué{}.",
                changes.len(),
                if changes.len() == 1 { "" } else { "s" },
                if changes.len() == 1 { "" } else { "s" }
            )?;
        }
    } else if value.get("conflicts").is_some() {
        writeln!(
            out,
            "\n{} changement(s) prévu(s). Aucun fichier hôte modifié.",
            changes.len()
        )?;
    } else {
        writeln!(out, "\nExport conservé. Aucun fichier hôte modifié.")?;
    }
    if value["pending"] == true {
        writeln!(
            out,
            "Application interrompue : relancer ladyshell sync pour la reprendre."
        )?;
    }
    if let Some(backup) = value["backup"].as_str() {
        writeln!(out, "Sauvegarde conservée : {}", visible(backup))?;
    }
    if let Some(export) = value["export"].as_str() {
        writeln!(out, "Export : {}", visible(export))?;
    }
    Ok(())
}
