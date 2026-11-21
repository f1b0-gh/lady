//! Host-owned App setup and teardown; installation removal is not App deletion.
use crate::{Config, app::SystemClock};
use anyhow::{Context, Result, bail, ensure};
use jjpr::forge::http::HttpError;
use jjpr::forge::{AuthScheme, ForgeClient, PaginationStyle};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
pub mod registration;

pub fn validate_inventory(config: &Config, value: &Value) -> Result<()> {
    config.validate()?;
    let app = config
        .github_app
        .as_ref()
        .context("App authentication required")?;
    ensure!(
        value["app"]["id"] == app.app_id
            && value["app"]["slug"] == app.slug
            && value["app"]["owner"]["login"] == config.owner,
        "App identity or owner differs"
    );
    let installations = value["installations"]
        .as_array()
        .context("Installation inventory missing")?;
    ensure!(
        installations.len() == 1,
        "Removal requires exactly the selected installation; inspect additional installations"
    );
    let i = &installations[0];
    ensure!(
        i["id"] == app.installation_id
            && i["app_id"] == app.app_id
            && i["app_slug"] == app.slug
            && i["account"]["login"] == config.owner
            && i["repository_selection"] == "selected"
            && i.get("suspended_at").is_some_and(Value::is_null),
        "Installation scope differs"
    );
    let repositories = value["repositories"]
        .as_array()
        .context("Repository inventory missing")?;
    ensure!(
        repositories.len() == 1,
        "Removal affects additional repositories"
    );
    config.validate_repository(&repositories[0])
}

pub fn callback_code(target: &str, expected: &str) -> Result<String> {
    ensure!(
        target.len() <= 2048
            && expected.len() == 64
            && expected.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid callback size or expected state"
    );
    let query = target
        .strip_prefix("/callback?")
        .context("Invalid callback route")?;
    let mut code = None;
    let mut state = None;
    for field in query.split('&') {
        let (name, value) = field.split_once('=').context("Invalid callback field")?;
        ensure!(
            !value.is_empty()
                && value.len() <= 256
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "Invalid callback literal"
        );
        match name {
            "code" if code.is_none() => code = Some(value),
            "state" if state.is_none() => state = Some(value),
            _ => bail!("Duplicate or unexpected callback field"),
        }
    }
    ensure!(state == Some(expected), "Callback state differs");
    Ok(code.context("Callback code missing")?.to_owned())
}

#[derive(Deserialize)]
struct Registration {
    id: u64,
    name: String,
    slug: String,
    owner: Owner,
    permissions: Value,
    pem: String,
}
#[derive(Deserialize)]
struct Owner {
    login: String,
}
pub fn registration_public(bytes: &[u8], owner: &str, name: &str) -> Result<Value> {
    registration_public_with_ci(bytes, owner, name, false)
}
pub fn registration_permissions(ci_read: bool) -> Value {
    let mut permissions = json!({"contents":"write","pull_requests":"write","statuses":"write","workflows":"write","metadata":"read"});
    if ci_read {
        permissions["actions"] = json!("read");
        permissions["checks"] = json!("read");
    }
    permissions
}
pub fn registration_public_with_ci(
    bytes: &[u8],
    owner: &str,
    name: &str,
    ci_read: bool,
) -> Result<Value> {
    ensure!(bytes.len() <= 65536, "Registration response exceeds limit");
    let r: Registration = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("Invalid registration response; content withheld"))?;
    ensure!(
        r.id > 0 && r.name == name && r.slug == name && r.owner.login == owner,
        "Registered App identity differs; private response retained for owner recovery"
    );
    ensure!(
        r.permissions == registration_permissions(ci_read),
        "Registered App permissions differ"
    );
    ensure!(
        r.pem.len() <= 16384
            && r.pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n")
            && r.pem.trim_end().ends_with("-----END RSA PRIVATE KEY-----"),
        "Registered key format differs"
    );
    Ok(json!({"app_id":r.id,"slug":r.slug,"owner":r.owner.login,"permissions":r.permissions}))
}

pub fn private_directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Private state path must be absolute");
    if !path.exists() {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.permissions().mode() & 0o077 == 0,
        "Private state must be a regular owner-only directory"
    );
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;
pub fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("Missing state parent")?)?.sync_all()?;
    Ok(())
}
pub(crate) fn retained_json(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.len() <= 262144 && m.permissions().mode() & 0o077 == 0,
        "Invalid private receipt"
    );
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub trait RemovalApi {
    fn inventory(&mut self) -> Result<Value>;
    fn delete_installation(&mut self, id: u64) -> Result<()>;
    fn installation_absent(&mut self, id: u64) -> Result<bool>;
}
/// No destructive retry after an uncertain call: inspect the original intent.
pub fn remove_with(config: &Config, directory: &Path, api: &mut impl RemovalApi) -> Result<Value> {
    config.validate_host_paths()?;
    private_directory(directory)?;
    ensure!(
        !directory
            .canonicalize()?
            .starts_with(config.workspace.canonicalize()?),
        "Teardown state must be outside the workspace"
    );
    let app = config
        .github_app
        .as_ref()
        .context("App authentication required")?;
    let binding = json!({"schema_version":1,"app_id":app.app_id,"installation_id":app.installation_id,"slug":app.slug,"repository_id":config.expected_repository_id,"repository":format!("{}/{}",config.owner,config.repository)});
    let intent = directory.join("remove-intent.json");
    if intent.exists() {
        ensure!(
            retained_json(&intent)?["binding"] == binding,
            "Retained removal intent differs"
        );
        ensure!(
            api.installation_absent(app.installation_id)?,
            "Prior removal remains uncertain or installation still exists; no delete replayed"
        );
    } else {
        let snapshot = api.inventory()?;
        validate_inventory(config, &snapshot)?;
        retain(
            &intent,
            &serde_json::to_vec_pretty(&json!({"binding":binding,"inventory":snapshot}))?,
        )?;
        api.delete_installation(app.installation_id).map_err(|_|anyhow::anyhow!("Installation removal outcome uncertain; inspect retained intent, never retry blindly"))?;
        ensure!(
            api.installation_absent(app.installation_id)?,
            "Removal not confirmed by readback"
        );
    }
    let receipt = json!({"binding":binding,"installation_removed":true,"app_registration_deleted":false,"repository_deleted":false});
    let path = directory.join("remove-confirmed.json");
    if path.exists() {
        ensure!(
            retained_json(&path)? == receipt,
            "Removal confirmation differs"
        );
    } else {
        retain(&path, &serde_json::to_vec_pretty(&receipt)?)?;
    }
    Ok(receipt)
}

pub struct Native<'a> {
    config: &'a Config,
    client: ForgeClient,
}
impl<'a> Native<'a> {
    pub fn new(config: &'a Config) -> Result<Self> {
        config.validate_host_paths()?;
        let app = config
            .github_app
            .as_ref()
            .context("App authentication required")?;
        let client = ForgeClient::new(
            "https://api.github.com",
            app.jwt(&SystemClock)?,
            AuthScheme::Bearer,
            PaginationStyle::LinkHeader,
        );
        Ok(Self { config, client })
    }
    fn identity(&self) -> Result<Value> {
        let value = self.client.get("/app").map_err(|_| {
            anyhow::anyhow!("App identity lookup failed; credential may be revoked")
        })?;
        let app = self
            .config
            .github_app
            .as_ref()
            .context("App authentication required")?;
        ensure!(
            value["id"] == app.app_id
                && value["slug"] == app.slug
                && value["owner"]["login"] == self.config.owner,
            "Authenticated App identity differs"
        );
        Ok(value)
    }
}
impl RemovalApi for Native<'_> {
    fn inventory(&mut self) -> Result<Value> {
        let app = self.identity()?;
        let installations = self
            .client
            .get("/app/installations?per_page=100")
            .map_err(|_| anyhow::anyhow!("Installation listing failed"))?;
        let list = installations
            .as_array()
            .context("Invalid installation listing")?;
        ensure!(
            list.len() < 100,
            "Installation pagination requires operator inspection"
        );
        let selected = self
            .config
            .github_app
            .as_ref()
            .context("App authentication required")?
            .installation_id;
        ensure!(
            list.iter().any(|i| i["id"] == selected),
            "Selected installation is absent"
        );
        // No repository narrowing: inventory the installation's complete grant.
        let token = self
            .client
            .post(
                &format!("/app/installations/{selected}/access_tokens"),
                &json!({"permissions":{"metadata":"read"}}),
            )
            .map_err(|_| anyhow::anyhow!("Read-only inventory token unavailable"))?;
        ensure!(
            token["permissions"] == json!({"metadata":"read"}),
            "Inventory token scope differs"
        );
        let secret = token["token"].as_str().context("Inventory token missing")?;
        let reader = ForgeClient::new(
            "https://api.github.com",
            secret.into(),
            AuthScheme::Bearer,
            PaginationStyle::LinkHeader,
        );
        let repositories = reader
            .get("/installation/repositories?per_page=100")
            .map_err(|_| anyhow::anyhow!("Repository grant inventory failed"))?;
        let repos = repositories["repositories"]
            .as_array()
            .context("Repository grant missing")?;
        ensure!(
            repositories["total_count"].as_u64() == Some(repos.len() as u64),
            "Repository grant inventory is incomplete"
        );
        Ok(
            json!({"app":{"id":app["id"],"slug":app["slug"],"owner":app["owner"],"permissions":app["permissions"]},"installations":installations,"repositories":repos}),
        )
    }
    fn delete_installation(&mut self, id: u64) -> Result<()> {
        self.identity()?;
        self.client
            .delete(&format!("/app/installations/{id}"))
            .map_err(|_| anyhow::anyhow!("Removal outcome unknown"))
    }
    fn installation_absent(&mut self, id: u64) -> Result<bool> {
        self.identity()?;
        match self.client.get(&format!("/app/installations/{id}")) {
            Ok(_) => Ok(false),
            Err(e)
                if e.downcast_ref::<HttpError>()
                    .is_some_and(|e| e.status == 404) =>
            {
                Ok(true)
            }
            Err(_) => bail!("Installation readback unavailable"),
        }
    }
}
