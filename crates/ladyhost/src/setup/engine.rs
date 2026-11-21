//! Resumable owner setup; source checkout and existing protection are preserved.
use super::*;
use crate::{Config, app};
use std::fs;

pub fn plan(spec: &Spec) -> Result<Value> {
    spec.validate()?;
    Ok(
        json!({"repository":spec.repository,"target":spec.target,"app_name":spec.app_name,
        "source_checkout_modified":false,"owner_credentials_in_runtime":false,
        "resources":["private GitHub App and selected-repository installation","separate SSH commit signer","signed workflow bootstrap","update and quality rulesets","private host checkout"],
        "required_checks":["fixture/verify",spec.ci_check],"workflow":spec.workflow_path,"checks":spec.checks,
        "human_steps":["authorize owner setup","create App from manifest","install App on only the selected repository","review bootstrap PR if existing protection requires it"],
        "protection":"one fresh native approval, signed linear history, strict checks; no quality bypass",
        "existing_rules":"preserved; additional policy requires explicit adoption before this integration profile is usable"}),
    )
}

pub fn tools(spec: &Spec) -> Result<Value> {
    let mut identities = json!({});
    let mut selected = vec![
        ("gh", spec.gh.clone()),
        ("jj", spec.jj.clone()),
        ("ladyhost", std::env::current_exe()?),
        ("openssl", std::path::PathBuf::from("/usr/bin/openssl")),
    ];
    for name in ["git", "ssh-keygen", "sha256sum"] {
        let path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
            .with_context(|| format!("Required host tool {name} is missing"))?;
        selected.push((name, path));
    }
    for (name, path) in selected {
        let resolved = path
            .canonicalize()
            .with_context(|| format!("{name} executable is missing"))?;
        ensure!(
            fs::metadata(&resolved)?.is_file(),
            "{name} is not a regular executable"
        );
        let mut cmd = native::command("sha256sum");
        cmd.arg(&resolved);
        let line = native::output(cmd, "Tool identity")?;
        let digest = line
            .split_whitespace()
            .next()
            .context("Tool digest missing")?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid tool digest"
        );
        identities[name] = json!({"path":resolved,"sha256":digest});
    }
    Ok(identities)
}

fn waiting(step: &str, message: &str, url: Option<String>) -> Value {
    json!({"status":"pending","step":step,"next_action":message,"url":url,"resume":"Run the same ladyhost init --state PATH --apply"})
}

fn host_checkout(store: &Store, config: &Config, head: &str) -> Result<()> {
    let checkout = &config.workspace;
    let existed = store.read("host-checkout.json")?;
    if existed.is_some() {
        ensure!(
            checkout.join(".jj").is_dir(),
            "Managed host checkout disappeared"
        );
        return Ok(());
    }
    store.record(
        "host-checkout.intent.json",
        &json!({"path":checkout,"initial_head":head}),
    )?;
    crate::lifecycle::private_directory(checkout)?;
    if !checkout.join(".git").exists() {
        native::git(checkout, &["init"])?;
    }
    flow::configure_signing(store, checkout)?;
    app::install_git_helper(config, &store.root.join("config.json"))?;
    let url = format!(
        "https://github.com/{}/{}.git",
        config.owner, config.repository
    );
    native::git(checkout, &["config", "--local", "remote.origin.url", &url])?;
    native::git(
        checkout,
        &[
            "config",
            "--local",
            "remote.origin.fetch",
            "+refs/heads/*:refs/remotes/origin/*",
        ],
    )?;
    native::git(checkout, &["fetch", "--no-tags", "origin"])?;
    // This checkout is owned by setup and has not been handed to a task yet.
    ensure!(
        native::git(checkout, &["status", "--porcelain"])?.is_empty(),
        "Managed checkout has edits; preserving them"
    );
    if !checkout.join(".jj").exists() {
        native::git(checkout, &["checkout", "--detach", head])?;
        let mut cmd = native::command(&store.spec.jj);
        cmd.args(["git", "init", "--colocate"]).arg(checkout);
        native::output(cmd, "Initialize host jj checkout")?;
    }
    let signer = store.read("signing.json")?.context("Signer missing")?;
    for (key, value) in [
        ("user.name", signer["name"].as_str()),
        ("user.email", signer["email"].as_str()),
        ("signing.backend", Some("ssh")),
        ("signing.key", signer["key"].as_str()),
        ("signing.behavior", Some("own")),
    ] {
        let mut cmd = native::command(&store.spec.jj);
        cmd.current_dir(checkout).args([
            "config",
            "set",
            "--repo",
            key,
            value.context("Signer setting missing")?,
        ]);
        native::output(cmd, "Configure host jj signer")?;
    }
    store.record(
        "host-checkout.json",
        &json!({"path":checkout,"initial_head":head}),
    )?;
    Ok(())
}

pub fn init(store: &Store) -> Result<Value> {
    ensure!(
        store.read("uninstall.intent.json")?.is_none(),
        "This setup is being removed; use a new state for a new installation"
    );
    store.record("tools.json", &tools(&store.spec)?)?;
    native::git(&store.spec.workspace, &["rev-parse", "--show-toplevel"])?;
    if store.read("complete.json")?.is_some() {
        native::clear_owner(store)?;
        return doctor::run(store);
    }
    let operation = if let Some(v) = store.read("operation.json")? {
        v
    } else {
        let v = json!({"id":native::nonce()?});
        store.record("operation.json", &v)?;
        v
    };
    let operation = operation["id"]
        .as_str()
        .context("Operation identity missing")?;
    eprintln!("Binding the owner and repository; setup credentials stay on this host.");
    let mut owner = native::owner(store, true)?;
    let repository = flow::bind_owner(store, &mut owner)?;
    let app = if let Some(app) = store.read("app.json")? {
        app
    } else {
        flow::register(store, &repository)?
    };
    if flow::discover(store, &app)?.is_none() {
        return Ok(waiting(
            "installation",
            "Install the App on only the selected repository, then resume.",
            Some(format!(
                "https://github.com/apps/{}/installations/new",
                store.spec.app_name
            )),
        ));
    }
    eprintln!("Preparing the separate commit signer and project CI workflow.");
    flow::signing(store, &mut owner)?;
    let actions_path = format!("{}/actions/permissions", store.spec.endpoint());
    let actions = owner
        .get(&actions_path)?
        .context("Actions permissions unavailable")?;
    if actions["enabled"] != true {
        // Enabling organization-wide policy or changing an allowlist is outside this project setup.
        return Ok(waiting(
            "actions",
            "Enable Actions for this repository in its Actions settings, retaining the organization's action policy; then resume.",
            Some(format!(
                "https://github.com/{}/settings/actions",
                store.spec.repository
            )),
        ));
    }
    let bootstrap_dir = store.directory("bootstrap")?;
    let bootstrap_config: Config =
        serde_json::from_value(flow::config_value(store, &bootstrap_dir, true)?)?;
    let mut publisher = native::Client::installation(&bootstrap_config)?;
    let candidate = bootstrap::prepare(store, &mut owner, operation)?;
    let head = candidate["head"]
        .as_str()
        .context("Bootstrap head missing")?;
    let source = candidate["source"]
        .as_str()
        .context("Bootstrap branch missing")?;
    // In a truly empty repository, GitHub makes the first pushed branch the
    // default. Create the selected target first, never a temporary setup branch.
    if candidate["expected_target"].is_null()
        && store.read("empty-repository.json")?.is_none()
        && store.read("push-source.intent.json")?.is_none()
        && store.read("push-target.intent.json")?.is_none()
    {
        let branches = resources::list(&mut owner, &format!("{}/branches", store.spec.endpoint()))?;
        if branches.is_empty() {
            store.record(
                "empty-repository.json",
                &json!({"first_branch":store.spec.target,"head":head}),
            )?;
        }
    }
    let empty_repository = store.read("empty-repository.json")?.is_some();
    if empty_repository {
        bootstrap::push(
            store,
            &mut publisher,
            "target",
            &store.spec.target,
            head,
            None,
        )?;
        let repo = owner
            .get(&store.spec.endpoint())?
            .context("Repository readback unavailable")?;
        ensure!(
            repo["default_branch"] == store.spec.target,
            "Empty repository default differs; preserve it and reconcile before continuing"
        );
    }
    // A reviewed bootstrap branch may already have been deleted by GitHub.
    // Reconcile its retained PR before requiring any source ref or push evidence.
    if store.read("bootstrap-integrated.json")?.is_none()
        && store.read("bootstrap-pr.intent.json")?.is_some()
    {
        if let Some(integrated) =
            bootstrap::integrate(store, &mut owner, &mut publisher, &candidate)?
        {
            store.record("bootstrap-integrated.json", &integrated)?;
        } else {
            let pr = store
                .read("bootstrap-pr.json")?
                .context("Bootstrap PR missing")?;
            return Ok(waiting(
                "bootstrap review",
                "Review and integrate the existing setup PR, then resume. A closed unmerged PR requires owner reconciliation.",
                pr["html_url"].as_str().map(str::to_owned),
            ));
        }
    }
    if store.read("bootstrap-integrated.json")?.is_none() {
        if !empty_repository {
            bootstrap::push(store, &mut publisher, "source", source, head, None)?;
        }
        let commit = publisher
            .get(&format!("{}/commits/{head}", store.spec.endpoint()))?
            .context("Bootstrap commit unavailable")?;
        ensure!(
            commit["sha"] == head
                && commit["commit"]["verification"]["verified"] == true
                && commit["commit"]["verification"]["reason"] == "valid",
            "GitHub has not verified the host signature; inspect the registered signing key and commit identity, then resume"
        );
        eprintln!("Waiting up to 30 seconds for the exact bootstrap commit's CI check.");
        // Exactly one push workflow for this SHA during bootstrap. In an
        // empty repository it belongs to the selected target, not a temp branch.
        let ci_candidate = if empty_repository {
            json!({"head":head,"source":store.spec.target})
        } else {
            candidate.clone()
        };
        if bootstrap::observe_ci(store, &bootstrap_config, &mut publisher, &ci_candidate)?.is_none()
        {
            return Ok(waiting(
                "ci",
                "Wait for the selected exact-push CI job to succeed, then resume. Check the workflow trigger and job name if it is missing.",
                Some(format!(
                    "https://github.com/{}/actions",
                    store.spec.repository
                )),
            ));
        }
        let Some(integrated) = bootstrap::integrate(store, &mut owner, &mut publisher, &candidate)?
        else {
            let pr = store
                .read("bootstrap-pr.json")?
                .context("Bootstrap PR missing")?;
            return Ok(waiting(
                "bootstrap review",
                "Review and integrate the setup PR using the existing repository policy, then resume.",
                pr["html_url"].as_str().map(str::to_owned),
            ));
        };
        store.record("bootstrap-integrated.json", &integrated)?;
    }
    let integrated = store
        .read("bootstrap-integrated.json")?
        .context("Integration evidence missing")?;
    let target = integrated["target"]
        .as_str()
        .context("Integrated head missing")?;
    if target != head {
        let candidate = json!({"head":target,"source":store.spec.target});
        // Exactly one push workflow for this SHA during bootstrap. In an
        // empty repository it belongs to the selected target, not a temp branch.
        let ci_candidate = if empty_repository {
            json!({"head":head,"source":store.spec.target})
        } else {
            candidate.clone()
        };
        if bootstrap::observe_ci(store, &bootstrap_config, &mut publisher, &ci_candidate)?.is_none()
        {
            return Ok(waiting(
                "target ci",
                "Wait for CI on the integrated target commit, then resume.",
                Some(format!(
                    "https://github.com/{}/actions",
                    store.spec.repository
                )),
            ));
        }
    }
    let ci = store.read("ci.json")?.context("CI binding missing")?;
    let (update, quality) = policies(
        &store.spec,
        operation,
        app["app_id"].as_u64().context("App ID missing")?,
        ci["requirement"]["app_id"]
            .as_u64()
            .context("CI ID missing")?,
    )?;
    store.record("policy.json", &json!({"update":update,"quality":quality}))?;
    eprintln!("Installing and reading back the quality and update rulesets.");
    let quality_id = ensure_ruleset(store, "quality", &quality, &mut owner)?;
    let update_id = ensure_ruleset(store, "update", &update, &mut owner)?;
    store.record("integration-defaults.json",&json!({"target":store.spec.target,"update_ruleset_id":update_id,"quality_ruleset_id":quality_id,"ci":ci["requirement"]}))?;
    let checkout = store.root.join("host");
    crate::lifecycle::private_directory(&checkout)?;
    store.record("config.json", &flow::config_value(store, &checkout, false)?)?;
    let config = Config::load_host(&store.root.join("config.json"))?;
    host_checkout(store, &config, target)?;
    let mut report = doctor::run(store)?;
    if report["status"] == "healthy" {
        store.record(
            "complete.json",
            &json!({"repository":repository["id"],"app":app["app_id"],"target":store.spec.target}),
        )?;
        native::clear_owner(store)?;
        report["config"] = json!(store.root.join("config.json"));
        report["integration_defaults"] = json!(store.root.join("integration-defaults.json"));
        report["host_checkout"] = json!(checkout);
        report["owner_local_credentials_removed"] = json!(true);
    }
    Ok(report)
}

pub fn uninstall_plan(store: &Store) -> Result<Value> {
    Ok(
        json!({"status":"plan","repository":store.spec.repository,"installation":store.read("installation.json")?,
        "owned_rules":[store.read("rules-update.confirmed.json")?.map(|v|v["id"].clone()),store.read("rules-quality.confirmed.json")?.map(|v|v["id"].clone())],
        "preserved":["repository and history","PRs and branches","tracked workflow","signing key and registration","App registration and key until owner deletes the App","changed or unowned rules"],
        "order":["revoke installation access","remove unchanged owned rules","remove local owner credentials"],
        "app_deletion_url":app_deletion_url(store)?,"apply":"Repeat with --apply to uninstall owned integration resources"}),
    )
}
fn app_deletion_url(store: &Store) -> Result<String> {
    let org = store
        .read("repository.json")?
        .is_some_and(|v| v["owner"]["type"] == "Organization");
    let (owner, _) = store.spec.parts()?;
    Ok(if org {
        format!(
            "https://github.com/organizations/{owner}/settings/apps/{}/advanced",
            store.spec.app_name
        )
    } else {
        format!(
            "https://github.com/settings/apps/{}/advanced",
            store.spec.app_name
        )
    })
}

pub fn uninstall(store: &Store) -> Result<Value> {
    let plan = uninstall_plan(store)?;
    if store.read("uninstall.intent.json")?.is_none() {
        store.record("uninstall.intent.json", &plan)?;
    }
    if store.read("uninstall-complete.json")?.is_some() {
        native::clear_owner(store)?;
        return store
            .read("uninstall-complete.json")?
            .context("Removal result missing");
    }
    let mut app = store.read("app.json")?;
    if app.is_none() && store.root.join("registration").exists() {
        let binding = store
            .read("repository.json")?
            .context("Repository binding missing")?;
        let owner = binding["owner"]["login"]
            .as_str()
            .context("Owner identity missing")?;
        app = crate::lifecycle::registration::recover(
            &store.root.join("registration"),
            &store.spec.workspace,
            owner,
            &store.spec.app_name,
            true,
        )?;
        if let Some(value) = &app {
            store.record("app.json", value)?;
        } else {
            native::clear_owner(store)?;
            return Ok(waiting(
                "registration outcome unknown",
                "Manifest flow has no retained conversion response. Inspect and delete any created App in owner settings; local absence cannot prove remote deletion.",
                Some(app_deletion_url(store)?),
            ));
        }
    }
    if let Some(app) = &app
        && store.read("installation.json")?.is_none()
        && store.read("no-installation.json")?.is_none()
    {
        if flow::registration_has_no_installations(store, app)? {
            store.record(
                "no-installation.json",
                &json!({"app_id":app["app_id"],"authenticated_installation_count":0}),
            )?;
        } else {
            ensure!(
                flow::discover(store, app)?.is_some(),
                "App has installations outside the selected repository; preserve them and reconcile owner scope"
            );
        }
    }
    if store.read("installation.json")?.is_some() {
        let config: Config =
            serde_json::from_value(flow::config_value(store, &store.spec.workspace, false)?)?;
        let directory = store.directory("removal")?;
        // Confirmed revocation remains evidence even after the owner deletes the App key/registration.
        if !directory.join("remove-confirmed.json").exists() {
            let mut api = crate::lifecycle::Native::new(&config)?;
            crate::lifecycle::remove_with(&config, &directory, &mut api)?;
        }
    }
    if let Some(policy) = store.read("policy.json")? {
        let mut owner = native::owner(store, true)?;
        flow::bind_owner(store, &mut owner)?;
        // Resolve a create whose reply was lost before considering ownership-based deletion.
        for kind in ["update", "quality"] {
            if store.read(&format!("rules-{kind}.intent.json"))?.is_some()
                && store
                    .read(&format!("rules-{kind}.confirmed.json"))?
                    .is_none()
            {
                ensure_ruleset(store, kind, &policy[kind], &mut owner)?;
            }
            remove_ruleset(store, kind, &policy[kind], &mut owner)?;
        }
    }
    native::clear_owner(store)?;
    let result = json!({"status":"uninstalled","repository":store.spec.repository,"installation_access_revoked":store.read("installation.json")?.is_some(),
        "owned_unchanged_rules_removed":true,"history_preserved":true,"owner_local_credentials_removed":true,
        "app_registration_deleted":false,"next_action":"Delete the App registration in GitHub's Advanced settings if it is no longer needed. Keep the private receipt directory until that step is complete; signing keys and tracked workflows are preserved.","url":app_deletion_url(store)?});
    store.record("uninstall-complete.json", &result)?;
    Ok(result)
}
