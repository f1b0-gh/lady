//! Provider readback and local custody inspection; no repository repair.
use super::*;
use crate::{
    Config,
    ci::Requirement,
    lifecycle::{self, RemovalApi},
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn item(check: &str, status: &str, detail: Value) -> Value {
    json!({"check":check,"status":status,"detail":detail})
}
fn local_custody(config: &Config) -> Result<Value> {
    config.validate_host_paths()?;
    let app = config
        .github_app
        .as_ref()
        .context("App authentication is required")?;
    let metadata = fs::symlink_metadata(&app.private_key)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "App key is not a private regular file"
    );
    let signer = native::git(&config.workspace, &["config", "--local", "user.signingkey"])?;
    let path = Path::new(&signer);
    ensure!(
        path.is_absolute() && !crate::resolved(path)?.starts_with(config.workspace.canonicalize()?),
        "Commit signing key must stay outside project"
    );
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "Commit signing key custody differs"
    );
    ensure!(
        native::git(&config.workspace, &["config", "--local", "gpg.format"])? == "ssh",
        "Selected signer format differs"
    );
    ensure!(
        path.canonicalize()? != app.private_key.canonicalize()?,
        "Commit signer must be separate from App key"
    );
    ensure!(
        native::git(
            &config.workspace,
            &["config", "--local", "--bool", "commit.gpgsign"]
        )
        .context("Git automatic commit signing is not configured")?
            == "true",
        "Git commit signing is disabled"
    );
    Ok(json!({"app_key_private":true,"separate_commit_signer":true,"commit_signing_enabled":true}))
}

pub fn inspect(config_path: &Path, defaults: &Value, workflow: Option<&Value>) -> Result<Value> {
    let config = Config::load_host(config_path)?;
    let target = config
        .stack_base
        .as_deref()
        .context("Target branch missing")?;
    let mut checks = vec![];
    match local_custody(&config) {
        Ok(value) => checks.push(item("local custody", "healthy", value)),
        Err(error) => checks.push(item("local custody", "failed", json!(error.to_string()))),
    }
    match lifecycle::Native::new(&config).and_then(|mut native|native.inventory()) {
        Ok(inventory)=>match lifecycle::validate_inventory(&config,&inventory) {
            Ok(())=>checks.push(item("App and installation","healthy",json!({"repository_count":1,"installation_count":1}))),
            Err(error)=>checks.push(item("App and installation","failed",json!(error.to_string()))),
        },
        Err(_)=>checks.push(item("App and installation","unknown",json!("Authenticated inventory unavailable; credential refusal does not prove App deletion"))),
    }
    let mut client = match native::Client::installation(&config) {
        Ok(client) => client,
        Err(_) => {
            checks.push(item(
                "runtime authentication",
                "unknown",
                json!("Publisher authentication unavailable"),
            ));
            return Ok(
                json!({"status":if checks.iter().any(|v|v["status"]=="failed") {"failed"} else {"unknown"},"checks":checks,"repository":format!("{}/{}",config.owner,config.repository)}),
            );
        }
    };
    let ci: Option<Requirement> = defaults
        .get("ci")
        .filter(|v| !v.is_null())
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?;
    let mut policies = vec![];
    let mut limits = vec![];
    for (key, update) in [("update_ruleset_id", true), ("quality_ruleset_id", false)] {
        let Some(id) = defaults[key].as_u64().filter(|id| *id > 0) else {
            checks.push(item(key, "unknown", json!("Selected ruleset ID missing")));
            continue;
        };
        match client.get(&format!(
            "{}/rulesets/{id}",
            format_args!("/repos/{}/{}", config.owner, config.repository)
        )) {
            Ok(Some(value)) => {
                if value.get("bypass_actors").is_none() {
                    limits.push("Full bypass roster hidden from runtime App; only its current bypass is observed".to_owned());
                }
                match crate::integration::verify_ruleset(
                    &config,
                    target,
                    id,
                    ci.as_ref(),
                    &value,
                    update,
                ) {
                    Ok(()) => {
                        checks.push(item(
                            key,
                            "healthy",
                            json!({"id":id,"caller_bypass":value["current_user_can_bypass"]}),
                        ));
                        policies.push(value);
                    }
                    Err(error) => checks.push(item(key, "failed", json!(error.to_string()))),
                }
            }
            Ok(None) => checks.push(item(key, "failed", json!("Selected ruleset is missing"))),
            _ => checks.push(item(key, "unknown", json!("Ruleset readback unavailable"))),
        }
    }
    if policies.len() == 2 {
        let effective = client.get(&format!(
            "/repos/{}/{}/rules/branches/{}",
            config.owner,
            config.repository,
            crate::integration::encode(target)
        ));
        match effective {
            Ok(Some(value)) => {
                let valid = value.as_array().is_some_and(|rules| {
                    rules.len() == 7
                        && policies.iter().all(|p| {
                            p["rules"].as_array().is_some_and(|selected| {
                                selected.iter().all(|rule| {
                                    rules
                                        .iter()
                                        .filter(|r| {
                                            r["ruleset_id"] == p["id"]
                                                && r["type"] == rule["type"]
                                                && r.get("parameters") == rule.get("parameters")
                                                && r["ruleset_source_type"] == "Repository"
                                                && r["ruleset_source"]
                                                    == format!(
                                                        "{}/{}",
                                                        config.owner, config.repository
                                                    )
                                        })
                                        .count()
                                        == 1
                                })
                            })
                        })
                });
                checks.push(item("effective protection",if valid {"healthy"}else{"failed"},json!(if valid {"Selected profile is effective"} else {"Additional, missing or changed rules require explicit policy adoption; existing rules were preserved"})));
            }
            _ => checks.push(item(
                "effective protection",
                "unknown",
                json!("Effective rules unavailable"),
            )),
        }
    }
    if let Some(expected) = workflow {
        let path = expected["path"].as_str().context("Workflow path missing")?;
        let content = expected["content"]
            .as_str()
            .context("Workflow content missing")?;
        let blob = native::git_input(
            &config.workspace,
            &["hash-object", "--stdin"],
            content.as_bytes(),
        )?;
        match client.get(&format!(
            "/repos/{}/{}/contents/{path}?ref={}",
            config.owner,
            config.repository,
            crate::integration::encode(target)
        )) {
            Ok(Some(value)) => checks.push(item(
                "workflow",
                if value["type"] == "file" && value["sha"] == blob {
                    "healthy"
                } else {
                    "failed"
                },
                json!({"path":path,"expected_blob":blob,"observed_blob":value["sha"]}),
            )),
            Ok(None) => checks.push(item(
                "workflow",
                "failed",
                json!("Selected workflow is missing"),
            )),
            _ => checks.push(item(
                "workflow",
                "unknown",
                json!("Workflow readback unavailable"),
            )),
        }
    } else {
        checks.push(item("workflow","unknown",json!("No retained workflow bytes selected; CI requirement alone does not verify file contents")));
    }
    limits.sort();
    limits.dedup();
    let status = if checks.iter().any(|v| v["status"] == "failed") {
        "failed"
    } else if checks.iter().any(|v| v["status"] == "unknown") {
        "unknown"
    } else {
        "healthy"
    };
    Ok(
        json!({"status":status,"repository":format!("{}/{}",config.owner,config.repository),"target":target,
        "checks":checks,"limits":limits,"merge_admission":"not evaluated; each PR still needs exact signature, fresh native approval and CI"}),
    )
}

pub fn run(store: &Store) -> Result<Value> {
    if store.read("uninstall-complete.json")?.is_some() {
        return Ok(
            json!({"status":"uninstalled","repository":store.spec.repository,"history_preserved":true}),
        );
    }
    if !store.root.join("config.json").exists() {
        let completed = fs::read_dir(&store.root)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json"))
            .collect::<Vec<_>>();
        return Ok(
            json!({"status":"incomplete","retained_steps":completed,"next_action":"Run ladyhost init with the same --state to resume"}),
        );
    }
    let defaults = store
        .read("integration-defaults.json")?
        .unwrap_or_else(|| json!({}));
    let workflow = store.read("workflow.json")?;
    let mut report = inspect(
        &store.root.join("config.json"),
        &defaults,
        workflow.as_ref(),
    )?;
    let binding = (|| -> Result<()> {
        ensure!(
            store.read("tools.json")?.as_ref() == Some(&engine::tools(&store.spec)?),
            "Selected tool binaries changed; review the upgrade before resuming setup"
        );
        let config = Config::load_host(&store.root.join("config.json"))?;
        let signer = store
            .read("signing.json")?
            .context("Signer evidence missing")?;
        let key = signer["key"].as_str().context("Signer path missing")?;
        ensure!(
            native::git(&config.workspace, &["config", "--local", "user.signingkey"])? == key,
            "Selected signing key changed"
        );
        let mut command = native::command("ssh-keygen");
        command.args(["-y", "-f", key]);
        let public = native::output(command, "Read host signing identity")?
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        ensure!(signer["public"] == public, "Signing key bytes changed");
        let allowed = store.root.join("allowed_signers");
        ensure!(
            native::git(
                &config.workspace,
                &["config", "--local", "gpg.ssh.allowedSignersFile"]
            )? == allowed.to_string_lossy(),
            "Allowed signers path changed"
        );
        ensure!(
            fs::read_to_string(&allowed)?
                == format!(
                    "{} {}\n",
                    signer["email"].as_str().context("Signer email missing")?,
                    public
                ),
            "Allowed signers content changed"
        );
        for (name, expected) in [
            ("user.name", signer["name"].as_str()),
            ("user.email", signer["email"].as_str()),
            ("signing.backend", Some("ssh")),
            ("signing.key", Some(key)),
            ("signing.behavior", Some("own")),
        ] {
            let mut command = native::command(&store.spec.jj);
            command
                .current_dir(&config.workspace)
                .args(["config", "get", name]);
            ensure!(
                native::output(command, "Read jj signer configuration")?
                    == expected.context("Signer setting missing")?,
                "jj signer configuration differs"
            );
        }
        Ok(())
    })();
    let (status, detail) = match binding {
        Ok(()) => (
            "healthy",
            json!("Retained tool, Git/jj signer and allowed-signers bindings match"),
        ),
        Err(error) => ("failed", json!(error.to_string())),
    };
    report["checks"]
        .as_array_mut()
        .context("Doctor checks missing")?
        .push(item("managed local bindings", status, detail));
    if status == "failed" {
        report["status"] = json!("failed");
    }
    if store.read("complete.json")?.is_none() {
        report["setup_completed"] = json!(false);
    } else {
        report["setup_completed"] = json!(true);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn custody_refuses_disabled_signing_and_reused_app_key() {
        let root = std::env::temp_dir().join(format!("ladyhost-doctor-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let workspace = root.join("project");
        fs::create_dir(&workspace).unwrap();
        native::git(&workspace, &["init"]).unwrap();
        let pem = root.join("app.pem");
        let key = root.join("signer");
        for path in [&pem, &key] {
            fs::write(path, "fixture").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config:Config=serde_json::from_value(json!({"provider":"github","endpoint":"https://api.github.com","owner":"owner","repository":"project","workspace":workspace,"expected_actor":"host[bot]","expected_repository_id":1,"github_app":{"app_id":123,"installation_id":456,"slug":"host","private_key":pem,"openssl":"/usr/bin/openssl"}})).unwrap();
        native::git(
            &workspace,
            &[
                "config",
                "--local",
                "user.signingkey",
                key.to_str().unwrap(),
            ],
        )
        .unwrap();
        native::git(&workspace, &["config", "--local", "gpg.format", "ssh"]).unwrap();
        native::git(
            &workspace,
            &["config", "--local", "commit.gpgsign", "false"],
        )
        .unwrap();
        assert!(local_custody(&config).is_err());
        native::git(&workspace, &["config", "--local", "commit.gpgsign", "true"]).unwrap();
        assert!(local_custody(&config).is_ok());
        native::git(
            &workspace,
            &[
                "config",
                "--local",
                "user.signingkey",
                pem.to_str().unwrap(),
            ],
        )
        .unwrap();
        assert!(local_custody(&config).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
