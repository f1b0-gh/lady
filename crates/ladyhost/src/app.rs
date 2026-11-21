//! Host GitHub App authentication, separate from publication effects.
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubApp {
    pub app_id: u64,
    pub installation_id: u64,
    pub slug: String,
    pub private_key: PathBuf,
    pub openssl: PathBuf,
    /// Only explicitly selected host CI setup requests this additional scope.
    #[serde(default)]
    pub workflow_write: bool,
    /// Explicit CI observation scopes, also required for private repositories.
    #[serde(default)]
    pub ci_read: bool,
}

use crate::Config;
use anyhow::{Context, Result, bail, ensure};
use jjpr::forge::{AuthScheme, ForgeClient, PaginationStyle};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    io::Write,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64>;
}
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("host clock precedes epoch")?
            .as_secs())
    }
}

/// The injected boundary owns transport only; identity and scope checks stay here.
pub trait AppApi {
    fn get(&mut self, path: &str) -> Result<Value>;
    fn post(&mut self, path: &str, body: &Value) -> Result<Value>;
}
impl AppApi for ForgeClient {
    fn get(&mut self, path: &str) -> Result<Value> {
        ForgeClient::get(self, path)
            .map_err(|_| anyhow::anyhow!("GitHub App metadata request failed"))
    }
    fn post(&mut self, path: &str, body: &Value) -> Result<Value> {
        ForgeClient::post(self, path, body)
            .map_err(|_| anyhow::anyhow!("GitHub App token request failed"))
    }
}

pub struct InstallationToken {
    secret: String,
    actor: String,
    expires_at: u64,
}
impl fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallationToken")
            .field("actor", &self.actor)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl InstallationToken {
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn value(&self, clock: &dyn Clock) -> Result<&str> {
        ensure!(
            clock.now()? < self.expires_at,
            "GitHub App credential expired; start a new invocation after reconciling any unknown effect"
        );
        Ok(&self.secret)
    }
}

fn installation(config: &Config, value: &Value) -> Result<()> {
    let app = config
        .github_app
        .as_ref()
        .context("App authentication not selected")?;
    ensure!(
        value["id"].as_u64() == Some(app.installation_id)
            && value["app_id"].as_u64() == Some(app.app_id)
            && value["app_slug"].as_str() == Some(app.slug.as_str()),
        "GitHub App installation identity mismatch"
    );
    ensure!(
        value["account"]["login"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(&config.owner)),
        "GitHub App installation account mismatch"
    );
    ensure!(
        value.get("suspended_at").is_some_and(Value::is_null),
        "GitHub App installation is suspended or suspension state is missing"
    );
    Ok(())
}

pub fn authenticate(
    config: &Config,
    api: &mut dyn AppApi,
    clock: &dyn Clock,
) -> Result<InstallationToken> {
    config.validate()?;
    let app = config
        .github_app
        .as_ref()
        .context("App authentication not selected")?;
    let metadata = api
        .get("/app")
        .map_err(|_| anyhow::anyhow!("GitHub App identity request failed"))?;
    ensure!(
        metadata["id"].as_u64() == Some(app.app_id)
            && metadata["slug"].as_str() == Some(app.slug.as_str()),
        "GitHub App identity mismatch"
    );
    let selected = api
        .get(&format!("/app/installations/{}", app.installation_id))
        .map_err(|_| anyhow::anyhow!("GitHub App installation request failed"))?;
    installation(config, &selected)?;
    let repository = api
        .get(&format!(
            "/repos/{}/{}/installation",
            config.owner, config.repository
        ))
        .map_err(|_| anyhow::anyhow!("GitHub repository installation request failed"))?;
    installation(config, &repository)?;
    let mut requested = json!({"contents":"write","pull_requests":"write","statuses":"write"});
    if app.workflow_write {
        requested["workflows"] = json!("write");
    }
    if app.ci_read {
        requested["actions"] = json!("read");
        requested["checks"] = json!("read");
    }
    let request = json!({
        "repository_ids": [config.expected_repository_id.context("repository ID missing")?],
        "permissions": requested
    });
    let response = api
        .post(
            &format!("/app/installations/{}/access_tokens", app.installation_id),
            &request,
        )
        .map_err(|_| anyhow::anyhow!("GitHub App token request failed"))?;
    let permissions = response["permissions"]
        .as_object()
        .context("App token permissions missing")?;
    requested["metadata"] = json!("read");
    ensure!(
        Some(permissions) == requested.as_object(),
        "App token permissions differ from exact host selection"
    );
    let repositories = response["repositories"]
        .as_array()
        .context("App token repositories missing")?;
    ensure!(
        repositories.len() == 1,
        "App token must name exactly one repository"
    );
    config.validate_repository(&repositories[0])?;
    let expires_at = parse_expiry(
        response["expires_at"]
            .as_str()
            .context("App token expiration missing")?,
    )?;
    let now = clock.now()?;
    ensure!(
        expires_at > now && expires_at <= now.saturating_add(3600),
        "App token lifetime invalid or expired"
    );
    let secret = response["token"].as_str().context("App token missing")?;
    ensure!(
        !secret.is_empty()
            && secret.len() <= 16_384
            && secret.bytes().all(|b| b.is_ascii_graphic()),
        "invalid App credential"
    );
    Ok(InstallationToken {
        secret: secret.into(),
        actor: format!("{}[bot]", app.slug),
        expires_at,
    })
}

// GitHub emits UTC whole-second RFC3339 timestamps. Reject alternate encodings.
fn parse_expiry(value: &str) -> Result<u64> {
    ensure!(
        value.len() == 20 && value.is_ascii(),
        "invalid App expiration encoding"
    );
    let bytes = value.as_bytes();
    ensure!(
        bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z',
        "invalid App expiration encoding"
    );
    let number = |start: usize, end: usize| -> Result<u64> {
        let part = &value[start..end];
        ensure!(
            part.bytes().all(|b| b.is_ascii_digit()),
            "invalid App expiration encoding"
        );
        Ok(part.parse()?)
    };
    let (year, month, day, hour, minute, second) = (
        number(0, 4)?,
        number(5, 7)?,
        number(8, 10)?,
        number(11, 13)?,
        number(14, 16)?,
        number(17, 19)?,
    );
    ensure!(
        (1970..=9999).contains(&year)
            && (1..=12).contains(&month)
            && hour < 24
            && minute < 60
            && second < 60,
        "invalid App expiration date"
    );
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        day > 0 && day <= months[(month - 1) as usize],
        "invalid App expiration day"
    );
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..(month - 1) as usize].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

pub fn credential_response(
    config: &Config,
    operation: &str,
    input: &str,
    mint: impl FnOnce() -> Result<InstallationToken>,
    clock: &dyn Clock,
) -> Result<String> {
    config.validate()?;
    ensure!(
        config.github_app.is_some(),
        "credential helper requires App authentication"
    );
    ensure!(
        matches!(operation, "get" | "store" | "erase"),
        "invalid credential operation"
    );
    ensure!(
        input.len() <= 32768 && !input.contains('\0') && !input.contains('\r'),
        "invalid credential request"
    );
    let mut fields = BTreeMap::new();
    let mut ended = false;
    for line in input.split('\n') {
        if line.is_empty() {
            ended = true;
            continue;
        }
        ensure!(!ended, "credential data after terminator");
        let (key, value) = line.split_once('=').context("invalid credential field")?;
        // Git passes repeatable HTTP challenges and capability advertisements.
        // This helper always supplies Basic username/password and does not use
        // these hints to select authority or an alternative authentication flow.
        if matches!(key, "wwwauth[]" | "capability[]") {
            continue;
        }
        ensure!(
            matches!(key, "protocol" | "host" | "path" | "username" | "password"),
            "unsupported credential field"
        );
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate credential field"
        );
    }
    ensure!(
        fields.get("protocol") == Some(&"https")
            && fields.get("host") == Some(&"github.com")
            && fields.get("path")
                == Some(&format!("{}/{}.git", config.owner, config.repository).as_str()),
        "credential destination differs from host selection"
    );
    ensure!(
        fields
            .get("username")
            .is_none_or(|v| *v == "x-access-token"),
        "credential username differs from App identity"
    );
    if operation != "get" {
        return Ok(String::new());
    }
    ensure!(
        !fields.contains_key("password"),
        "get request supplied a credential"
    );
    let token = mint()?;
    Ok(format!(
        "username=x-access-token\npassword={}\n\n",
        token.value(clock)?
    ))
}

fn openssl(app: &GitHubApp, args: &[&std::ffi::OsStr], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(&app.openssl)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| anyhow::anyhow!("cannot invoke host OpenSSL"))?;
    let write = child
        .stdin
        .take()
        .context("OpenSSL input unavailable")?
        .write_all(input);
    let output = child
        .wait_with_output()
        .map_err(|_| anyhow::anyhow!("host OpenSSL failed"))?;
    ensure!(
        write.is_ok() && output.status.success(),
        "host OpenSSL failed"
    );
    Ok(output.stdout)
}
fn base64url(app: &GitHubApp, bytes: &[u8]) -> Result<String> {
    let encoded = openssl(app, &["base64".as_ref(), "-A".as_ref()], bytes)?;
    let encoded =
        String::from_utf8(encoded).map_err(|_| anyhow::anyhow!("invalid OpenSSL encoding"))?;
    ensure!(
        encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
        "invalid OpenSSL encoding"
    );
    Ok(encoded
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_"))
}

impl GitHubApp {
    pub fn jwt(&self, clock: &dyn Clock) -> Result<String> {
        let metadata =
            std::fs::symlink_metadata(&self.private_key).context("App private key unavailable")?;
        ensure!(
            metadata.is_file() && metadata.len() <= 65536,
            "App private key must be a bounded regular file"
        );
        let executable =
            std::fs::metadata(&self.openssl).context("OpenSSL executable unavailable")?;
        ensure!(
            self.openssl.is_absolute() && executable.is_file(),
            "OpenSSL must be an absolute existing executable"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "App private key must be private to the host user"
            );
            ensure!(
                executable.permissions().mode() & 0o111 != 0,
                "OpenSSL is not executable"
            );
        }
        // Explicitly enforce RSA before the generic dgst signing command.
        openssl(
            self,
            &[
                "rsa".as_ref(),
                "-in".as_ref(),
                self.private_key.as_os_str(),
                "-check".as_ref(),
                "-noout".as_ref(),
                "-passin".as_ref(),
                "pass:".as_ref(),
            ],
            b"",
        )?;
        let now = clock.now()?;
        let header = base64url(self, br#"{"alg":"RS256","typ":"JWT"}"#)?;
        let payload = base64url(
            self,
            &serde_json::to_vec(
                &json!({"iat":now.saturating_sub(60),"exp":now.checked_add(540).context("invalid host clock")?,"iss":self.app_id}),
            )?,
        )?;
        let message = format!("{header}.{payload}");
        let signature = openssl(
            self,
            &[
                "dgst".as_ref(),
                "-sha256".as_ref(),
                "-sign".as_ref(),
                self.private_key.as_os_str(),
                "-passin".as_ref(),
                "pass:".as_ref(),
            ],
            message.as_bytes(),
        )?;
        Ok(format!("{message}.{}", base64url(self, &signature)?))
    }
}

pub fn mint(config: &Config) -> Result<InstallationToken> {
    config.validate_host_paths()?;
    let app = config
        .github_app
        .as_ref()
        .context("App authentication not selected")?;
    let jwt = app.jwt(&SystemClock)?;
    let mut client = ForgeClient::new(
        "https://api.github.com",
        jwt,
        AuthScheme::Bearer,
        PaginationStyle::LinkHeader,
    );
    authenticate(config, &mut client, &SystemClock)
}

use jjpr::forge::{
    ChecksStatus, Forge, IssueComment, MergeMethod, PrMergeability, PrState, PullRequest,
    ReviewSummary, Stack,
};
use std::sync::Arc;

/// Installation credentials cannot call `/user`. The actor comes from the
/// authenticated App/installation binding; every delegated call checks expiry.
pub struct AppForge {
    inner: Box<dyn Forge>,
    credential: InstallationToken,
    clock: Arc<dyn Clock>,
}
impl AppForge {
    pub fn new(
        inner: Box<dyn Forge>,
        credential: InstallationToken,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            inner,
            credential,
            clock,
        }
    }
    fn call<T>(&self, operation: impl FnOnce(&dyn Forge) -> Result<T>) -> Result<T> {
        self.credential.value(self.clock.as_ref())?;
        operation(self.inner.as_ref()).map_err(|_| {
            anyhow::anyhow!(
                "GitHub App forge operation failed; reconcile any dispatched effect before retry"
            )
        })
    }
}
macro_rules! delegate {
    ($(fn $name:ident(&self $(,$arg:ident:$ty:ty)*) -> $out:ty;)*) => {$(
        fn $name(&self,$($arg:$ty),*) -> Result<$out> {
            self.call(|forge|forge.$name($($arg),*))
        }
    )*};
}
#[allow(clippy::too_many_arguments)]
impl Forge for AppForge {
    delegate! {
        fn list_open_prs(&self,owner:&str,repo:&str)->Vec<PullRequest>;
        fn create_pr(&self,owner:&str,repo:&str,title:&str,body:&str,head:&str,base:&str,draft:bool)->PullRequest;
        fn update_pr_base(&self,owner:&str,repo:&str,number:u64,base:&str)->();
        fn request_reviewers(&self,owner:&str,repo:&str,number:u64,reviewers:&[String])->();
        fn list_comments(&self,owner:&str,repo:&str,number:u64)->Vec<IssueComment>;
        fn create_comment(&self,owner:&str,repo:&str,number:u64,body:&str)->IssueComment;
        fn update_comment(&self,owner:&str,repo:&str,comment_id:u64,body:&str)->();
        fn delete_comment(&self,owner:&str,repo:&str,comment_id:u64)->();
        fn update_pr_body(&self,owner:&str,repo:&str,number:u64,body:&str)->();
        fn mark_pr_ready(&self,owner:&str,repo:&str,number:u64)->();
        fn find_merged_pr(&self,owner:&str,repo:&str,head:&str)->Option<PullRequest>;
        fn list_recently_merged_prs(&self,owner:&str,repo:&str)->Vec<PullRequest>;
        fn get_pr_checks_status(&self,owner:&str,repo:&str,head_ref:&str)->ChecksStatus;
        fn get_pr_reviews(&self,owner:&str,repo:&str,number:u64)->ReviewSummary;
        fn get_pr_mergeability(&self,owner:&str,repo:&str,number:u64)->PrMergeability;
        fn get_pr_state(&self,owner:&str,repo:&str,number:u64)->PrState;
        fn get_stack(&self,owner:&str,repo:&str,number:u64)->Option<Stack>;
        fn base_dismisses_stale_approvals(&self,owner:&str,repo:&str,base:&str)->Option<bool>;
        fn get_pr(&self,owner:&str,repo:&str,number:u64)->(PullRequest,PrState);
        fn get_branch_head(&self,owner:&str,repo:&str,branch:&str)->Option<String>;
    }
    fn get_authenticated_user(&self) -> Result<String> {
        self.credential.value(self.clock.as_ref())?;
        Ok(self.credential.actor().into())
    }
    fn merge_pr(
        &self,
        _owner: &str,
        _repo: &str,
        _number: u64,
        _method: MergeMethod,
    ) -> Result<()> {
        bail!("merge is outside the App publication interface")
    }
}

/// Reset inherited helpers before installing the host-selected App helper.
pub fn install_git_helper(config: &Config, config_path: &std::path::Path) -> Result<()> {
    config.validate_host_paths()?;
    ensure!(
        config.github_app.is_some(),
        "git-helper requires App authentication"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let config_path = config_path.canonicalize()?;
    let quote = |path: &std::path::Path| -> Result<String> {
        let text = path.to_str().context("helper path must be UTF-8")?;
        ensure!(!text.chars().any(char::is_control), "invalid helper path");
        Ok(format!("'{}'", text.replace('\'', "'\\''")))
    };
    let helper = format!(
        "!{} credential {}",
        quote(&executable)?,
        quote(&config_path)?
    );
    for args in [
        vec!["--replace-all", "credential.helper", ""],
        vec!["--add", "credential.helper", helper.as_str()],
        vec!["--replace-all", "credential.useHttpPath", "true"],
    ] {
        let mut command = Command::new("git");
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        let status = command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .arg("-C")
            .arg(&config.workspace)
            .args(["config", "--local"])
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("cannot configure Git credential helper")?;
        ensure!(
            status.success(),
            "Git credential helper configuration failed"
        );
    }
    Ok(())
}
