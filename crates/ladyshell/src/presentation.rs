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
            writeln!(out, "Exported {}", visible(path))?;
            continue;
        }
        let label = match change["action"].as_str() {
            Some("add") => "Added   ",
            Some("delete") => "Deleted ",
            _ => "Modified",
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
                "Deleted {} (in the sandbox)",
                visible(path.as_str().unwrap_or("?"))
            )?;
        }
    }
    if let Some(conflicts) = value["conflicts"].as_array().filter(|v| !v.is_empty()) {
        for path in conflicts {
            writeln!(out, "Conflict {}", visible(path.as_str().unwrap_or("?")))?;
        }
        writeln!(
            out,
            "\nApplication blocked: {} conflict(s). No host files changed.",
            conflicts.len()
        )?;
    } else if value["applied"] == true {
        if changes.is_empty() {
            writeln!(out, "Project is already up to date.")?;
        } else {
            writeln!(
                out,
                "\n{} change{} applied.",
                changes.len(),
                if changes.len() == 1 { "" } else { "s" }
            )?;
        }
    } else if value.get("conflicts").is_some() {
        writeln!(
            out,
            "\n{} change(s) planned. No host files changed.",
            changes.len()
        )?;
    } else {
        writeln!(out, "\nExport retained. No host files changed.")?;
    }
    if value["pending"] == true {
        writeln!(
            out,
            "Application interrupted: run ladyshell sync again to resume."
        )?;
    }
    if let Some(backup) = value["backup"].as_str() {
        writeln!(out, "Backup retained: {}", visible(backup))?;
    }
    if let Some(export) = value["export"].as_str() {
        writeln!(out, "Export: {}", visible(export))?;
    }
    Ok(())
}
