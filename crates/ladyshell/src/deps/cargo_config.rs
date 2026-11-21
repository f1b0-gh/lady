//! Only static command aliases are allowed; no Cargo process is launched here.
use super::invalid;
use crate::{
    error::{ensure, Result},
    files,
};
use std::path::Path;

pub(super) fn validate(root: &Path, name: &str) -> Result<()> {
    crate::config::relative_path(name)?;
    let content = String::from_utf8(files::read_limited(&root.join(name), 1024 * 1024)?)?;
    let value = super::parse_toml(&content)?;
    let table = value
        .as_table()
        .ok_or_else(|| invalid(format!("Invalid Cargo configuration: {name}")))?;
    ensure!(
        table.len() == 1 && table.contains_key("alias"),
        "Only the alias section is allowed in Cargo configuration: {name}"
    );
    let aliases = table["alias"]
        .as_table()
        .ok_or_else(|| invalid(format!("A Cargo alias table is required: {name}")))?;
    ensure!(!aliases.is_empty(), "Empty Cargo alias table: {name}");
    for (alias, value) in aliases {
        ensure!(
            !alias.is_empty() && !alias.chars().any(|c| c.is_whitespace() || c.is_control()),
            "Invalid Cargo alias name: {name}"
        );
        let command = match value {
            toml::Value::String(command) => {
                ensure!(valid_argument(command), "Invalid Cargo alias: {name}");
                command.trim_start()
            }
            toml::Value::Array(arguments) => {
                ensure!(
                    arguments
                        .iter()
                        .all(|value| value.as_str().is_some_and(valid_argument)),
                    "Invalid Cargo alias arguments: {name}"
                );
                let command = arguments
                    .first()
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| invalid(format!("Empty Cargo alias: {name}")))?;
                ensure!(
                    !command.chars().any(char::is_whitespace),
                    "Invalid Cargo alias command: {name}"
                );
                command
            }
            _ => return Err(invalid(format!("Invalid Cargo alias: {name}"))),
        };
        ensure!(
            !command.starts_with('!'),
            "Cargo shell aliases are not allowed: {name}"
        );
    }
    Ok(())
}

fn valid_argument(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}
