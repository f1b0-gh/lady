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
        .ok_or_else(|| invalid(format!("Configuration Cargo invalide : {name}")))?;
    ensure!(
        table.len() == 1 && table.contains_key("alias"),
        "Seule la section alias est autorisée dans la configuration Cargo : {name}"
    );
    let aliases = table["alias"]
        .as_table()
        .ok_or_else(|| invalid(format!("Table alias Cargo requise : {name}")))?;
    ensure!(!aliases.is_empty(), "Table alias Cargo vide : {name}");
    for (alias, value) in aliases {
        ensure!(
            !alias.is_empty() && !alias.chars().any(|c| c.is_whitespace() || c.is_control()),
            "Nom d’alias Cargo invalide : {name}"
        );
        let command = match value {
            toml::Value::String(command) => {
                ensure!(valid_argument(command), "Alias Cargo invalide : {name}");
                command.trim_start()
            }
            toml::Value::Array(arguments) => {
                ensure!(
                    arguments
                        .iter()
                        .all(|value| value.as_str().is_some_and(valid_argument)),
                    "Arguments d’alias Cargo invalides : {name}"
                );
                let command = arguments
                    .first()
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| invalid(format!("Alias Cargo vide : {name}")))?;
                ensure!(
                    !command.chars().any(char::is_whitespace),
                    "Commande d’alias Cargo invalide : {name}"
                );
                command
            }
            _ => return Err(invalid(format!("Alias Cargo invalide : {name}"))),
        };
        ensure!(
            !command.starts_with('!'),
            "Alias shell Cargo interdit : {name}"
        );
    }
    Ok(())
}

fn valid_argument(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}
