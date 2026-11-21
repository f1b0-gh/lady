//! Guided initialization with retained owner and project bindings.
use super::*;
use crate::{
    Config,
    app::{GitHubApp, SystemClock},
    lifecycle::{self, RemovalApi},
};
use jjpr::forge::{AuthScheme, ForgeClient, PaginationStyle};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub fn bind_owner(store: &Store, owner: &mut impl Api) -> Result<Value> {
    let user = owner.get("/user")?.context("Owner identity unavailable")?;
    let actor = json!({"id":user["id"],"login":user["login"]});
    ensure!(
        actor["id"].as_u64().is_some_and(|id| id > 0)
            && actor["login"]
                .as_str()
                .is_some_and(|s| crate::identifier(s, false)),
        "Invalid owner identity"
    );
    let repo = owner
        .get(&store.spec.endpoint())?
        .context("Create the selected GitHub repository before initialization")?;
    ensure!(
        repo["full_name"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(&store.spec.repository))
            && repo["id"].as_u64().is_some_and(|id| id > 0)
            && repo["permissions"]["admin"] == true,
        "Repository identity or owner administration permission differs"
    );
    ensure!(
        matches!(
            repo["owner"]["type"].as_str(),
            Some("User" | "Organization")
        ),
        "Unsupported repository owner type"
    );
    let binding = json!({"id":repo["id"],"full_name":repo["full_name"],"private":repo["private"],
        "owner":{"id":repo["owner"]["id"],"login":repo["owner"]["login"],"type":repo["owner"]["type"]}});
    store.record("owner.json", &actor)?;
    store.record("repository.json", &binding)?;
    Ok(binding)
}

pub fn register(store: &Store, repository: &Value) -> Result<Value> {
    let canonical = repository["full_name"]
        .as_str()
        .context("Canonical repository missing")?;
    let (owner, repo) = canonical
        .split_once('/')
        .context("Invalid canonical repository")?;
    let directory = store.directory("registration")?;
    let app = lifecycle::registration::serve_with(
        &directory,
        &store.spec.workspace,
        owner,
        repo,
        &store.spec.app_name,
        repository["owner"]["type"] == "Organization",
        true,
    )?;
    store.record("app.json", &app)?;
    Ok(app)
}

pub fn discover(store: &Store, registered: &Value) -> Result<Option<Value>> {
    let binding = store
        .read("repository.json")?
        .context("Repository binding missing")?;
    let (owner, repository) = binding["full_name"]
        .as_str()
        .context("Canonical repository missing")?
        .split_once('/')
        .context("Invalid canonical repository")?;
    let app = GitHubApp {
        app_id: registered["app_id"].as_u64().context("App ID missing")?,
        installation_id: 0,
        slug: store.spec.app_name.clone(),
        private_key: store.root.join("registration/app.private-key.pem"),
        openssl: PathBuf::from("/usr/bin/openssl"),
        workflow_write: false,
        ci_read: true,
    };
    let mut client = native::Client(ForgeClient::new(
        "https://api.github.com",
        app.jwt(&SystemClock)?,
        AuthScheme::Bearer,
        PaginationStyle::LinkHeader,
    ));
    let identity = client
        .get("/app")?
        .context("Registered App is unavailable")?;
    ensure!(
        identity["id"] == app.app_id
            && identity["slug"] == app.slug
            && identity["owner"]["login"] == owner,
        "Registered App identity changed"
    );
    let Some(installed) = client.get(&format!("/repos/{owner}/{repository}/installation"))? else {
        return Ok(None);
    };
    ensure!(
        installed["app_id"] == app.app_id
            && installed["app_slug"] == app.slug
            && installed["account"]["login"] == owner
            && installed["repository_selection"] == "selected"
            && installed.get("suspended_at").is_some_and(Value::is_null),
        "Installation identity, scope or suspension differs"
    );
    let id = installed["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("Installation ID missing")?;
    let binding = json!({"id":id,"app_id":app.app_id,"account":installed["account"]["login"],"repository_selection":"selected"});
    store.record("installation.json", &binding)?;
    let config = config_value(store, &store.spec.workspace, false)?;
    let parsed: Config = serde_json::from_value(config)?;
    let inventory = lifecycle::Native::new(&parsed)?.inventory()?;
    lifecycle::validate_inventory(&parsed, &inventory)?;
    Ok(Some(binding))
}

pub fn config_value(store: &Store, workspace: &Path, workflow_write: bool) -> Result<Value> {
    let binding = store
        .read("repository.json")?
        .context("Repository binding missing")?;
    let (owner, repository) = binding["full_name"]
        .as_str()
        .context("Canonical repository missing")?
        .split_once('/')
        .context("Invalid canonical repository")?;
    let app = store.read("app.json")?.context("App is not registered")?;
    let installation = store
        .read("installation.json")?
        .context("App is not installed")?;
    let repo = store
        .read("repository.json")?
        .context("Repository is not bound")?;
    Ok(
        json!({"provider":"github","endpoint":"https://api.github.com","owner":owner,"repository":repository,
        "workspace":workspace,"expected_actor":format!("{}[bot]",store.spec.app_name),"expected_repository_id":repo["id"],
        "visibility":if repo["private"]==true {"private"} else {"public"},"stack_base":store.spec.target,"reviewers":[],
        "github_app":{"app_id":app["app_id"],"installation_id":installation["id"],"slug":store.spec.app_name,
            "private_key":store.root.join("registration/app.private-key.pem"),"openssl":"/usr/bin/openssl",
            "workflow_write":workflow_write,"ci_read":true}}),
    )
}

pub fn signing(store: &Store, owner: &mut impl Api) -> Result<Value> {
    let actor = store.read("owner.json")?.context("Owner is not bound")?;
    let login = actor["login"].as_str().context("Owner login missing")?;
    let actor_id = actor["id"].as_u64().context("Owner ID missing")?;
    let key = store
        .spec
        .signing_key
        .clone()
        .unwrap_or_else(|| store.root.join("signing-key"));
    ensure!(
        !crate::resolved(&key)?.starts_with(store.spec.workspace.canonicalize()?),
        "Signing key must stay outside project"
    );
    let intent = json!({"key":key,"managed":store.spec.signing_key.is_none(),"owner_id":actor_id});
    if store.spec.signing_key.is_none() && key.exists() {
        ensure!(
            store.read("signing-key.intent.json")?.as_ref() == Some(&intent),
            "Existing key has no matching creation intent"
        );
    }
    if !key.exists() {
        ensure!(
            store.read("signing.json")?.is_none()
                && store.read("signing-registration.intent.json")?.is_none(),
            "Previously used signing key is missing; recover it instead of generating a replacement"
        );
        ensure!(
            store.spec.signing_key.is_none(),
            "Selected signing key is missing"
        );
        store.record("signing-key.intent.json", &intent)?;
        let mut cmd = native::command("ssh-keygen");
        cmd.args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&key);
        native::output(cmd, "Host signing key generation")?;
    }
    let metadata = fs::symlink_metadata(&key)?;
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "Signing key custody differs"
    );
    let mut cmd = native::command("ssh-keygen");
    cmd.args(["-y", "-f"]).arg(&key);
    let output = native::output(cmd, "Read public signing key")?;
    let public = output
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    ensure!(
        public.starts_with("ssh-ed25519 ") && public.split_whitespace().count() == 2,
        "Select an Ed25519 SSH signing key"
    );
    let keys = resources::list(owner, &format!("/users/{login}/ssh_signing_keys"))?;
    let matching: Vec<_> = keys.iter().filter(|v| v["key"] == public).collect();
    ensure!(matching.len() <= 1, "Ambiguous signing key registration");
    let remote_id = if let Some(found) = matching.first() {
        found["id"].clone()
    } else {
        let body = json!({"title":format!("Ladyhost {}",store.spec.repository),"key":public});
        ensure!(
            store.read("signing-registration.intent.json")?.is_none(),
            "Signing registration outcome unresolved; inspect account keys before retrying"
        );
        store.record("signing-registration.intent.json", &body)?;
        let registered = owner.post("/user/ssh_signing_keys", &body)?;
        ensure!(
            registered["key"] == public,
            "Registered signing key differs"
        );
        registered["id"].clone()
    };
    ensure!(
        remote_id.as_u64().is_some_and(|id| id > 0),
        "Signing key registration ID missing"
    );
    let email = format!("{actor_id}+{login}@users.noreply.github.com");
    let value = json!({"key":key,"managed":store.spec.signing_key.is_none(),"public":public,"remote_id":remote_id,"name":login,"email":email});
    store.record("signing.json", &value)?;
    let allowed = format!("{email} {public}\n");
    let path = store.root.join("allowed_signers");
    if path.exists() {
        ensure!(
            fs::read(&path)? == allowed.as_bytes(),
            "Allowed signers file changed"
        );
    } else {
        lifecycle::retain(&path, allowed.as_bytes())?;
    }
    Ok(value)
}

pub fn configure_signing(store: &Store, workspace: &Path) -> Result<()> {
    let signer = store.read("signing.json")?.context("Signer unavailable")?;
    for (key, value) in [
        (
            "user.name",
            signer["name"]
                .as_str()
                .context("Signer name missing")?
                .to_owned(),
        ),
        (
            "user.email",
            signer["email"]
                .as_str()
                .context("Signer email missing")?
                .to_owned(),
        ),
        (
            "user.signingkey",
            signer["key"]
                .as_str()
                .context("Signer path missing")?
                .to_owned(),
        ),
        ("gpg.format", "ssh".to_owned()),
        ("commit.gpgsign", "true".to_owned()),
        (
            "gpg.ssh.allowedSignersFile",
            store
                .root
                .join("allowed_signers")
                .to_string_lossy()
                .into_owned(),
        ),
    ] {
        native::git(workspace, &["config", "--local", key, &value])?;
    }
    Ok(())
}

/// An authenticated empty App installation list is evidence, unlike a missing
/// local installation receipt or a refused credential.
pub fn registration_has_no_installations(store: &Store, registered: &Value) -> Result<bool> {
    let binding = store
        .read("repository.json")?
        .context("Repository binding missing")?;
    let app = GitHubApp {
        app_id: registered["app_id"].as_u64().context("App ID missing")?,
        installation_id: 0,
        slug: store.spec.app_name.clone(),
        private_key: store.root.join("registration/app.private-key.pem"),
        openssl: PathBuf::from("/usr/bin/openssl"),
        workflow_write: false,
        ci_read: true,
    };
    let mut client = native::Client(ForgeClient::new(
        "https://api.github.com",
        app.jwt(&SystemClock)?,
        AuthScheme::Bearer,
        PaginationStyle::LinkHeader,
    ));
    let identity = client
        .get("/app")?
        .context("Registered App identity unavailable")?;
    ensure!(
        identity["id"] == app.app_id
            && identity["slug"] == app.slug
            && identity["owner"]["id"] == binding["owner"]["id"],
        "Registered App identity differs"
    );
    Ok(resources::list(&mut client, "/app/installations")?.is_empty())
}
