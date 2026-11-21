//! Read-only installation discovery; no installation token or publication.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

use anyhow::{Context, Result, ensure};
use jjpr::forge::{AuthScheme, ForgeClient, PaginationStyle};
use ladyhost::app::{GitHubApp, SystemClock};
use serde_json::{Value, json};
use std::path::PathBuf;

fn repository_path(owner: &str, repo: &str) -> Result<String> {
    for name in [owner, repo] {
        ensure!(
            !name.is_empty()
                && name.len() <= 100
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid repository identity"
        );
    }
    Ok(format!("/repos/{owner}/{repo}/installation"))
}

fn validate_discovery(
    app_id: u64,
    slug: &str,
    owner: &str,
    metadata: &Value,
    installed: &Value,
) -> Result<u64> {
    ensure!(
        metadata["id"].as_u64() == Some(app_id) && metadata["slug"].as_str() == Some(slug),
        "App identity mismatch"
    );
    ensure!(
        installed["app_id"].as_u64() == Some(app_id)
            && installed["app_slug"].as_str() == Some(slug),
        "installed App identity mismatch"
    );
    ensure!(
        installed["account"]["login"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(owner))
            && installed.get("suspended_at").is_some_and(Value::is_null),
        "installation owner or suspension mismatch"
    );
    let id = installed["id"]
        .as_u64()
        .context("installation ID missing")?;
    ensure!(id > 0, "installation ID is zero");
    Ok(id)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 6,
        "usage: discover_app APP_ID SLUG KEY_PATH OWNER REPO"
    );
    let app_id: u64 = args[1].parse()?;
    ensure!(app_id > 0, "App ID is zero");
    let path = repository_path(&args[4], &args[5])?;
    let key = PathBuf::from(&args[3]);
    ensure!(key.is_absolute(), "host key path must be absolute");
    let app = GitHubApp {
        app_id,
        slug: args[2].clone(),
        private_key: key,
        openssl: PathBuf::from("/usr/bin/openssl"),
        // Discovery does not mint a token; this field is not used by jwt().
        installation_id: 0,
        workflow_write: false,
        ci_read: false,
    };
    let client = ForgeClient::new(
        "https://api.github.com",
        app.jwt(&SystemClock)?,
        AuthScheme::Bearer,
        PaginationStyle::LinkHeader,
    );
    let metadata = client
        .get("/app")
        .map_err(|_| anyhow::anyhow!("App metadata lookup failed"))?;
    ensure!(
        metadata["id"].as_u64() == Some(app_id)
            && metadata["slug"].as_str() == Some(args[2].as_str()),
        "App identity mismatch"
    );
    let installed = match client.get(&path) {
        Ok(value) => value,
        Err(_) => {
            let installations = client
                .get_paginated("/app/installations")
                .map_err(|_| anyhow::anyhow!("repository and installation-list lookups failed"))?;
            let selected: Vec<_> = installations.iter()
                .filter(|i| i["account"]["login"].as_str().is_some_and(|v| v.eq_ignore_ascii_case(&args[4])))
                .map(|i| json!({"id":i["id"],"repository_selection":i["repository_selection"],"suspended_at":i["suspended_at"]}))
                .collect();
            anyhow::bail!(
                "App authenticated, but repository installation lookup failed; selected account installations: {}",
                json!(selected)
            );
        }
    };
    let id = validate_discovery(app_id, &args[2], &args[4], &metadata, &installed)?;
    println!(
        "{}",
        json!({"app_id":app_id,"slug":args[2],"installation_id":id,
        "repository":format!("{}/{}",args[4],args[5]),"permissions":installed["permissions"],
        "repository_selection":installed["repository_selection"],"scope":"read-only discovery; token scope checked by preflight"})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovery_only_accepts_the_selected_app_and_repository_owner() {
        let metadata = json!({"id":123,"slug":"publisher"});
        let installed = json!({"id":456,"app_id":123,"app_slug":"publisher","account":{"login":"owner"},"suspended_at":null});
        assert_eq!(
            validate_discovery(123, "publisher", "owner", &metadata, &installed).unwrap(),
            456
        );
        for (field, value) in [
            ("app_id", json!(999)),
            ("id", json!(0)),
            ("account", json!({"login":"other"})),
            ("suspended_at", json!("suspended")),
        ] {
            let mut changed = installed.clone();
            changed[field] = value;
            assert!(validate_discovery(123, "publisher", "owner", &metadata, &changed).is_err());
        }
        assert!(validate_discovery(124, "publisher", "owner", &metadata, &installed).is_err());
    }

    #[test]
    fn repository_path_cannot_select_another_api_route() {
        assert_eq!(
            repository_path("owner", "repo.lab").unwrap(),
            "/repos/owner/repo.lab/installation"
        );
        for value in ["../other", "a/b", "a?b", "", ".", ".."] {
            assert!(repository_path("owner", value).is_err());
            assert!(repository_path(value, "repo").is_err());
        }
    }
}
