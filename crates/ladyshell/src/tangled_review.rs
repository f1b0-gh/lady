//! Host-owned Tangled review transport and retained, exact-object review rounds.
//! Authentication is delegated to an explicit trusted host helper, never the sandbox.
use crate::{
    error::{ensure, Error, Result},
    files,
    state::{SessionLock, StateLock},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
mod handoff;
pub use handoff::HandoffInput;

/// Reserve a single successor locally without publishing a provider record.
pub fn handoff(directory: &Path, config_path: &Path, input: &HandoffInput) -> Result<Value> {
    handoff::run(directory, config_path, input)
}

/// Call under the retained state lock before any review or merge dispatch.
pub(crate) fn ensure_review_writable(directory: &Path) -> Result<()> {
    handoff::ensure_writable(directory)?;
    crate::continuous::host::execution_directory(directory)?;
    current_publication(directory)
}

// Historical status stays inspectable, but old epochs cannot authorize actions.
fn current_publication(directory: &Path) -> Result<()> {
    let Some(current) = crate::state::load(directory)? else {
        return Ok(());
    };
    if current.get("continuous").is_none() {
        return Ok(());
    }
    crate::continuous::host::ensure_ready(&current)?;
    let publication = read(&directory.join("publication.json"))?;
    let export = Path::new(text(&publication, "export")?);
    let manifest = read(&export.join("manifest.json"))?;
    crate::continuous::host::verify_export(&current, &manifest)
}

pub(crate) fn ensure_review_recovery(directory: &Path) -> Result<()> {
    handoff::ensure_incoming_committed(directory)
}

const TICKET: &str = "org.tangled.track.ticket";
const PATCH: &str = "org.tangled.review.patch";
const CREATE: &str = "com.atproto.repo.createRecord";
const SUBMIT: &str = "org.tangled.review.submitPatch";
const LIMIT: usize = 4 * 1024 * 1024;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub knot: String,
    pub repository: String,
    pub source_repository: String,
    pub web_url: String,
    pub bobbin: Option<String>,
    pub spindle: Option<String>,
    pub auth_program: Option<PathBuf>,
    pub connector: Option<Connector>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_owner_review: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connector {
    pub program: PathBuf,
    pub config: PathBuf,
    pub account: String,
    pub connection: u64,
    pub generation: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitInput {
    pub ticket_key: String,
    pub created_at: String,
    pub target_base: String,
    pub target_branch: String,
    pub title: String,
    pub body: String,
    pub resubmit: bool,
}
/// Local host metadata, never a Tangled decision or proof of human identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OwnerDecision {
    Approved,
    ChangesRequested,
    Withdrawn,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionInput {
    pub decision: OwnerDecision,
    pub head: String,
    pub base: String,
    pub patch_uri: String,
    pub patch_cid: String,
    pub explanation: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DecisionRound {
    attempt: String,
    repository: String,
    source_repository: String,
    ticket_key: String,
    ticket_uri: String,
    patch_uri: String,
    patch_cid: String,
    source_branch: String,
    target_branch: String,
    head: String,
    base: String,
}
impl DecisionRound {
    fn from_review(r: &Value) -> Result<Self> {
        Ok(Self {
            attempt: text(r, "attempt")?.into(),
            repository: text(r, "repository")?.into(),
            source_repository: text(r, "source_repository")?.into(),
            ticket_key: text(r, "ticket_key")?.into(),
            ticket_uri: text(r, "ticket_uri")?.into(),
            patch_uri: text(&r["patch"], "uri")?.into(),
            patch_cid: text(&r["patch"], "cid")?.into(),
            source_branch: text(r, "source_branch")?.into(),
            target_branch: text(r, "target_branch")?.into(),
            head: text(r, "submitted_head")?.into(),
            base: text(r, "submitted_base")?.into(),
        })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DecisionRecord {
    schema_version: u32,
    sequence: usize,
    previous: Option<String>,
    decision: OwnerDecision,
    round: DecisionRound,
    policy_binding_sha256: String,
    explanation: Option<String>,
}
const DECISION_LIMIT: usize = 16 * 1024;
const HISTORY_LIMIT: usize = 1024;
fn explanation(value: &Option<String>) -> Result<()> {
    ensure!(
        value
            .as_ref()
            .is_none_or(|v| v.len() <= 2048 && !v.contains('\0')),
        "Owner explanation exceeds 2048 bytes or contains NUL"
    );
    Ok(())
}
// One authoritative immutable sequence; no current pointer can lag an archive.
// A published record is the decision, including after an interrupted caller.
fn owner_history(directory: &Path) -> Result<Vec<DecisionRecord>> {
    let dir = directory.join("owner-review-decisions");
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let _directory = files::open_directory(&dir)?;
    let entries = std::fs::read_dir(&dir)?
        .take(2 * HISTORY_LIMIT + 1)
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() <= 2 * HISTORY_LIMIT,
        "Owner decision directory entry limit exceeded"
    );
    let mut names = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        // publish_json uses NamedTempFile's default .tmp + six alphanumeric
        // characters. An interrupted pre-publication file has no authority;
        // never parse or promote it. Its count is still bounded above.
        let unpublished = name.to_str().is_some_and(|n| {
            n.len() == 10
                && n.starts_with(".tmp")
                && n[4..].bytes().all(|b| b.is_ascii_alphanumeric())
        });
        if unpublished {
            ensure!(
                entry.file_type()?.is_file(),
                "Unpublished owner entry is not a regular file"
            );
        } else {
            names.push(name);
        }
    }
    ensure!(
        names.len() <= HISTORY_LIMIT,
        "Owner decision history limit exceeded"
    );
    names.sort();
    let mut records = Vec::new();
    let mut previous = None;
    for (index, name) in names.into_iter().enumerate() {
        ensure!(
            name == std::ffi::OsStr::new(&format!("{:020}.json", index + 1)),
            "Owner decision sequence is incomplete or contains unexpected entries"
        );
        let bytes = files::read_limited(&dir.join(name), DECISION_LIMIT)?;
        let record: DecisionRecord = serde_json::from_value(crate::json::parse(&bytes)?)?;
        ensure!(
            record.schema_version == 1
                && record.sequence == index + 1
                && record.previous == previous,
            "Owner decision history chain is inconsistent"
        );
        explanation(&record.explanation)?;
        crate::publish::oid(&record.round.head)?;
        crate::publish::oid(&record.round.base)?;
        ensure!(
            record.policy_binding_sha256.len() == 64
                && record
                    .policy_binding_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "Owner decision policy binding is malformed"
        );
        previous = Some(files::hash(&serde_json::to_vec(&record)?));
        records.push(record);
    }
    Ok(records)
}
fn owner_policy(digest: &str, authority: Option<&Value>) -> Result<String> {
    Ok(match authority {
        Some(a) => text(a, "policy_digest")?.into(),
        None => digest.into(),
    })
}
fn current_round(r: &Value) -> bool {
    r["phase"] == "submitted"
        && r["source_ahead"] == false
        && r["superseded"] == false
        && r["remote_round_match"] == true
        && r["ticket_observation"] == "open_current_target"
}
fn human_review(
    directory: &Path,
    config: &Config,
    digest: &str,
    authority: Option<&Value>,
    r: &Value,
) -> Result<Value> {
    if !config.require_owner_review {
        return Ok(json!({"status":"unknown","reason":"decision_source_unsupported"}));
    }
    let records = owner_history(directory)?;
    let Some(record) = records.last() else {
        return Ok(
            json!({"source":"host_owner","status":"unknown","reason":"decision_missing","required":true}),
        );
    };
    let applicable = current_round(r)
        && record.round == DecisionRound::from_review(r)?
        && record.policy_binding_sha256 == owner_policy(digest, authority)?;
    Ok(
        json!({"source":"host_owner","status":if applicable {"current"} else {"stale"},
        "required":true,"decision":record.decision,"decision_id":files::hash(&serde_json::to_vec(record)?),
        "round":record.round,"policy_binding_sha256":record.policy_binding_sha256,
        "explanation":record.explanation,"untrusted_content":true}),
    )
}
/// Record a permitted host caller's explicit decision. This grants no upstream
/// authority and must never be exposed as a sandbox/agent approval mechanism.
/// All guards are shared with merge, so withdrawal wins before later dispatch.
pub fn record_owner_decision(
    directory: &Path,
    config_path: &Path,
    input: &DecisionInput,
) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let _sessions = SessionLock::acquire(&lock.directory, true)?;
    let _parents = crate::stacks::guard(&lock.directory)?;
    crate::publish::oid(&input.head)?;
    crate::publish::oid(&input.base)?;
    explanation(&input.explanation)?;
    let (config, publication, digest, authority) = context(&lock.directory, config_path)?;
    ensure!(
        config.require_owner_review,
        "Trusted host policy must select owner review"
    );
    source(&config, &publication)?;
    let r = status_locked(&lock, config_path)?;
    ensure!(
        current_round(&r),
        "Owner decision requires the current exact confirmed open review round"
    );
    ensure!(
        r["submitted_head"] == input.head
            && r["submitted_base"] == input.base
            && r["patch"]["uri"] == input.patch_uri
            && r["patch"]["cid"] == input.patch_cid,
        "Owner decision exact head, base or immutable patch differs"
    );
    let records = owner_history(&lock.directory)?;
    let mut record = DecisionRecord {
        schema_version: 1,
        sequence: records.len() + 1,
        previous: records
            .last()
            .map(|v| serde_json::to_vec(v).map(|b| files::hash(&b)))
            .transpose()?,
        decision: input.decision.clone(),
        round: DecisionRound::from_review(&r)?,
        policy_binding_sha256: owner_policy(&digest, authority.as_ref())?,
        explanation: input.explanation.clone(),
    };
    if let Some(last) = records.last() {
        record.sequence = last.sequence;
        record.previous.clone_from(&last.previous);
        if record == *last {
            return human_review(&lock.directory, &config, &digest, authority.as_ref(), &r);
        }
        record.sequence = records.len() + 1;
        record.previous = Some(files::hash(&serde_json::to_vec(last)?));
    }
    ensure!(
        records.len() < HISTORY_LIMIT,
        "Owner decision history limit reached"
    );
    ensure!(
        serde_json::to_vec_pretty(&record)?.len() < DECISION_LIMIT,
        "Owner decision exceeds storage limit"
    );
    let dir = lock.directory.join("owner-review-decisions");
    crate::state::create_directory(&dir)?;
    files::open_directory(&lock.directory)?.sync_all()?;
    files::publish_json(
        &dir.join(format!("{:020}.json", record.sequence)),
        &record,
        false,
    )?;
    files::open_directory(&dir)?.sync_all()?;
    human_review(&lock.directory, &config, &digest, authority.as_ref(), &r)
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    crate::state::text(value, key)
}
fn read(path: &Path) -> Result<Value> {
    crate::json::parse(&files::read_limited(path, LIMIT)?)
}
fn origin(value: &str) -> Result<url::Url> {
    let u = url::Url::parse(value).map_err(|_| invalid("Invalid service URL".into()))?;
    ensure!(
        u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none(),
        "Service URL contains credentials, query or fragment"
    );
    let loopback = matches!(u.host(),Some(url::Host::Ipv4(ip)) if ip.is_loopback())
        || matches!(u.host(),Some(url::Host::Ipv6(ip)) if ip.is_loopback());
    ensure!(
        u.scheme() == "https" || (u.scheme() == "http" && loopback),
        "HTTPS is required outside numeric loopback fixtures"
    );
    Ok(u)
}
fn outside(path: &Path, project: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute(),
        "Trusted configuration paths must be absolute"
    );
    let path = path.canonicalize()?;
    ensure!(
        !path.starts_with(project),
        "Trusted configuration and helpers must be outside the exported project"
    );
    Ok(path)
}
fn context(directory: &Path, path: &Path) -> Result<(Config, Value, String, Option<Value>)> {
    let publication = read(&directory.join("publication.json"))?;
    let project = Path::new(text(&publication, "project")?).canonicalize()?;
    let path = outside(path, &project)?;
    let bytes = files::read_limited(&path, 64 * 1024)?;
    let mut config: Config = serde_json::from_value(crate::json::parse(&bytes)?)?;
    ensure!(
        matches!(config.schema_version, 1 | 2),
        "Unsupported Tangled configuration schema"
    );
    for did in [&config.repository, &config.source_repository] {
        ensure!(
            did.starts_with("did:")
                && did.len() < 512
                && !did.contains(['/', '?', '#', '\n', '\r']),
            "Invalid repository DID"
        );
    }
    let knot = origin(&config.knot)?;
    ensure!(knot.path() == "/", "Knot URL must be an origin");
    origin(&config.web_url)?;
    for service in [&config.bobbin, &config.spindle].into_iter().flatten() {
        let u = origin(service)?;
        ensure!(u.path() == "/", "Service URL must be an origin");
    }
    let mut binding = bytes.clone();
    let mut authority = None;
    if config.schema_version == 1 {
        ensure!(
            config.connector.is_none(),
            "Legacy authentication and typed connectors cannot be mixed"
        );
        let program = config
            .auth_program
            .as_ref()
            .ok_or_else(|| invalid("Legacy authentication helper is missing".into()))?;
        let program = outside(program, &project)?;
        ensure!(
            program.is_file(),
            "Authentication helper must be a host executable file"
        );
        config.auth_program = Some(program);
    } else {
        ensure!(
            config.auth_program.is_none(),
            "Typed connector cannot fall back to legacy authentication"
        );
        let connector = config
            .connector
            .as_mut()
            .ok_or_else(|| invalid("Typed host connector is missing".into()))?;
        connector.program = outside(&connector.program, &project)?;
        connector.config = outside(&connector.config, &project)?;
        ensure!(
            connector.program.is_file() && connector.connection > 0 && connector.generation > 0,
            "Invalid typed host connector"
        );
        let host_bytes = files::read_limited(&connector.config, 64 * 1024)?;
        let host = crate::json::parse(&host_bytes)?;
        ensure!(
            ((host["schema_version"] == 1 && host.get("session_policy").is_none())
                || (host["schema_version"] == 2 && host["session_policy"] == "refreshable"))
                && host["mode"] == "trusted_owner"
                && host["account"] == connector.account
                && host["connection"] == connector.connection
                && host["generation"] == connector.generation
                && host["knot"] == config.knot
                && host["repository"] == config.repository
                && host["source_repository"] == config.source_repository,
            "Host connector account, generation or target differs from review policy"
        );
        binding = serde_json::to_vec(&(bytes, host_bytes))?;
        let mut host_policy = host;
        host_policy
            .as_object_mut()
            .ok_or_else(|| invalid("Invalid host policy".into()))?
            .remove("generation");
        let mut review_policy = serde_json::to_value(&config)?;
        review_policy["connector"]
            .as_object_mut()
            .ok_or_else(|| invalid("Missing connector policy".into()))?
            .remove("generation");
        let connector = config
            .connector
            .as_ref()
            .ok_or_else(|| invalid("Missing connector".into()))?;
        authority = Some(
            json!({"mode":"trusted_owner","account":connector.account,"connection":connector.connection,"generation":connector.generation,"knot":config.knot,"repository":config.repository,"source_repository":config.source_repository,"program":connector.program,"host_config":connector.config,"review_config":path,"policy_digest":files::hash(&serde_json::to_vec(&(review_policy, host_policy))?)}),
        );
    }
    Ok((config, publication, files::hash(&binding), authority))
}
fn endpoint(service: &str, nsid: &str, params: &[(&str, &str)]) -> Result<String> {
    let mut url = origin(service)?;
    url.set_path(&format!("/xrpc/{nsid}"));
    url.query_pairs_mut().extend_pairs(params.iter().copied());
    Ok(url.to_string())
}
fn config_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn auth(config: &Config, nsid: &str) -> Result<String> {
    let mut cmd = Command::new(
        config
            .auth_program
            .as_ref()
            .ok_or_else(|| invalid("Legacy authentication is not selected".into()))?,
    );
    cmd.args([&config.repository, nsid])
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = crate::process::capture(cmd, Duration::from_secs(10), 16 * 1024)
        .map_err(|_| invalid("Service authentication helper failed (output suppressed)".into()))?;
    let token = String::from_utf8(output)
        .map_err(|_| invalid("Invalid service authentication output".into()))?;
    let token = token.trim();
    ensure!(
        !token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "Invalid service authentication token"
    );
    let segments: Vec<_> = token.split('.').collect();
    ensure!(segments.len() == 3, "Invalid service authentication JWT");
    let payload = URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|_| invalid("Invalid service authentication JWT payload".into()))?;
    let claims = crate::json::parse(&payload)
        .map_err(|_| invalid("Invalid service authentication claims".into()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("Host clock is before epoch".into()))?
        .as_secs();
    ensure!(
        claims["aud"] == config.repository && claims["lxm"] == nsid,
        "Service authentication audience or method mismatch"
    );
    ensure!(
        claims["exp"]
            .as_u64()
            .is_some_and(|exp| exp > now + 15 && exp <= now + 600),
        "Service authentication expired or exceeds the short-lived window"
    );
    ensure!(
        claims.get("nbf").is_none() || claims["nbf"].as_u64().is_some_and(|nbf| nbf <= now),
        "Service authentication is not yet valid"
    );
    Ok(token.to_owned())
}
fn request(url: &str, write: Option<(&str, &Value)>) -> Result<Value> {
    let mut cfg = format!(
        "url = {}\nheader = {}\n",
        config_string(url),
        config_string("Accept: application/json")
    );
    if let Some((token, body)) = write {
        cfg.push_str(&format!(
            "request = \"POST\"\nheader = {}\nheader = {}\ndata-binary = {}\n",
            config_string(&format!("Authorization: Bearer {token}")),
            config_string("Content-Type: application/json"),
            config_string(&serde_json::to_string(body)?)
        ));
    }
    let mut cmd = Command::new("/usr/bin/curl");
    cmd.args([
        "-q",
        "--config",
        "-",
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--max-time",
        "20",
        "--connect-timeout",
        "5",
        "--max-redirs",
        "0",
        "--proto",
        "=http,https",
        "--proxy",
        "",
    ])
    .env_clear()
    .current_dir("/");
    let bytes=crate::process::capture_input(cmd,cfg.as_bytes(),Duration::from_secs(25),LIMIT).map_err(|_|invalid("Tangled HTTP request failed or is uncertain; retained intent must be reconciled (response suppressed)".into()))?;
    crate::json::parse(&bytes)
        .map_err(|_| invalid("Tangled returned invalid JSON (response suppressed)".into()))
}
fn get(service: &str, nsid: &str, params: &[(&str, &str)]) -> Result<Value> {
    request(&endpoint(service, nsid, params)?, None)
}
fn post(
    directory: &Path,
    config: &Config,
    nsid: &str,
    body: &Value,
    receipt: &mut Value,
    phase: &str,
) -> Result<Value> {
    let _parents = crate::stacks::guard(directory)?;
    if config.connector.is_some() {
        let operation = match nsid {
            CREATE => "create_ticket",
            SUBMIT => "submit_patch",
            _ => return Err(invalid("Unsupported typed review operation".into())),
        };
        let command = connector_request(config, operation, body)?;
        let ready = receipt["phase"].clone();
        receipt["phase"] = json!(phase);
        save(directory, receipt)?;
        let response = connector_call(config, "execute", &command)?;
        if response["outcome"] == "not_sent" {
            receipt["phase"] = ready;
            save(directory, receipt)?;
        }
        ensure!(
            response["outcome"] == "confirmed",
            "Typed host operation is unconfirmed; reconcile retained intent"
        );
        return Ok(response["result"].clone());
    }
    // Authentication failure is known to precede the remote write. Preserve a
    // retryable ready state until the helper returns a valid scoped token.
    let token = auth(config, nsid)?;
    receipt["phase"] = json!(phase);
    save(directory, receipt)?;
    request(&endpoint(&config.knot, nsid, &[])?, Some((&token, body)))
}
fn connector_request(config: &Config, operation: &str, body: &Value) -> Result<Value> {
    let connector = config
        .connector
        .as_ref()
        .ok_or_else(|| invalid("Typed host connector is not selected".into()))?;
    let request_id = files::hash(&serde_json::to_vec(&(operation, body))?);
    Ok(
        json!({"schema_version":1,"operation":operation,"request_id":request_id,"connection":connector.connection,"generation":connector.generation,"body":body}),
    )
}
fn connector_call(config: &Config, action: &str, request: &Value) -> Result<Value> {
    let connector = config
        .connector
        .as_ref()
        .ok_or_else(|| invalid("Typed host connector is missing".into()))?;
    let mut command = Command::new(&connector.program);
    command
        .arg(action)
        .arg("--config")
        .arg(&connector.config)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/");
    let bytes=crate::process::capture_input(command,&serde_json::to_vec(request)?,Duration::from_secs(90),262144)
        .map_err(|_|invalid("Typed host connector failed or is uncertain (output suppressed); reconcile retained intent".into()))?;
    let response = crate::json::parse(&bytes)
        .map_err(|_| invalid("Invalid typed host response (output suppressed)".into()))?;
    ensure!(
        response["schema_version"] == 1
            && response["connection"] == connector.connection
            && response["generation"] == connector.generation
            && response["request_id"] == request["request_id"]
            && matches!(
                response["outcome"].as_str(),
                Some("confirmed" | "unknown" | "not_sent")
            ),
        "Typed host response does not match the retained operation"
    );
    ensure!(
        response["mode"] == "trusted_owner"
            && response["account"] == connector.account
            && response["knot"] == config.knot
            && response["repository"] == config.repository
            && response["source_repository"] == config.source_repository,
        "Typed host response account or target differs from review policy"
    );
    Ok(response)
}
fn ticket_matches(config: &Config, receipt: &Value, ticket: &Value) -> Result<()> {
    ref_valid(config, ticket, TICKET)?;
    let value = &ticket["value"];
    for field in ["$type", "title", "body", "state", "targetBranch"] {
        ensure!(
            value[field] == receipt["ticket_record"][field],
            "Ticket authored fields differ from retained intent"
        );
    }
    if let Some(connector) = &config.connector {
        ensure!(
            value["x-tngl-editor"] == connector.account,
            "Ticket editor differs from pinned actor"
        );
    }
    let (seconds, _) = round_time(&value["createdAt"])
        .ok_or_else(|| invalid("Invalid server ticket timestamp".into()))?;
    creation_date(&format!("{seconds}Z"))?;
    Ok(())
}
fn ticket_get(config: &Config, uri: &str) -> Result<Value> {
    let prefix = format!("at://{}/{TICKET}/", config.repository);
    let key = uri
        .strip_prefix(&prefix)
        .ok_or_else(|| invalid("Unexpected ticket URI".into()))?;
    let ticket = get(
        &config.knot,
        "com.atproto.repo.getRecord",
        &[
            ("repo", &config.repository),
            ("collection", TICKET),
            ("rkey", key),
        ],
    )?;
    ref_valid(config, &ticket, TICKET)?;
    ensure!(ticket["uri"] == uri, "Ticket read-back URI differs");
    Ok(ticket)
}
fn pin_ticket(
    directory: &Path,
    config: &Config,
    receipt: &mut Value,
    mut ticket: Value,
) -> Result<()> {
    ticket_matches(config, receipt, &ticket)?;
    if !receipt["ticket_response"].is_null() {
        ensure!(
            ticket["uri"] == receipt["ticket_response"]["uri"]
                && ticket["cid"] == receipt["ticket_response"]["cid"],
            "Ticket read-back strong reference differs from create acknowledgement"
        );
        if let Some(change) = receipt["ticket_response"].get("x-tngl-change") {
            crate::publish::oid(
                change
                    .as_str()
                    .ok_or_else(|| invalid("Invalid ticket change".into()))?,
            )?;
            ticket["x-tngl-change"] = change.clone();
        }
    }
    let uri = text(&ticket, "uri")?.to_owned();
    let key = uri
        .rsplit('/')
        .next()
        .ok_or_else(|| invalid("Missing ticket key".into()))?;
    receipt["ticket_key"] = json!(key);
    receipt["ticket_uri"] = json!(uri);
    receipt["url"] = json!(format!(
        "{}/pulls/{key}",
        config.web_url.trim_end_matches('/')
    ));
    // Accept server extensions without copying arbitrary provider fields into
    // retained public output. Authored fields were checked against this intent.
    let mut canonical = receipt["ticket_record"].clone();
    canonical["createdAt"] = ticket["value"]["createdAt"].clone();
    if let Some(connector) = &config.connector {
        canonical["x-tngl-editor"] = json!(connector.account);
    }
    let mut public = json!({"uri":ticket["uri"],"cid":ticket["cid"],"value":canonical});
    if let Some(change) = ticket.get("x-tngl-change") {
        crate::publish::oid(
            change
                .as_str()
                .ok_or_else(|| invalid("Invalid ticket change".into()))?,
        )?;
        public["x-tngl-change"] = change.clone();
    }
    receipt["ticket"] = public;
    receipt["phase"] = json!("patch_ready");
    // The allocated identity is durable before any dependent patch effect.
    save(directory, receipt)
}
fn create_ticket(directory: &Path, config: &Config, receipt: &mut Value) -> Result<()> {
    ensure!(
        receipt["ticket_allocation"] == "server",
        "Legacy fixed-key ticket intent cannot be resent; reconcile evidence or abandon explicitly"
    );
    let body =
        json!({"repo":config.repository,"collection":TICKET,"record":receipt["ticket_record"]});
    let saved = post(directory, config, CREATE, &body, receipt, "ticket_pending")?;
    ref_valid(config, &saved, TICKET)?;
    let mut acknowledgement = json!({"uri":saved["uri"],"cid":saved["cid"]});
    if let Some(change) = saved.get("x-tngl-change") {
        crate::publish::oid(
            change
                .as_str()
                .ok_or_else(|| invalid("Invalid ticket change".into()))?,
        )?;
        acknowledgement["x-tngl-change"] = change.clone();
    }
    receipt["ticket_response"] = acknowledgement;
    save(directory, receipt)?;
    let ticket = ticket_get(config, text(&receipt["ticket_response"], "uri")?)?;
    pin_ticket(directory, config, receipt, ticket)
}

fn source(config: &Config, p: &Value) -> Result<(String, String)> {
    ensure!(
        p["schema_version"] == 2 && p["phase"] == "published" && p["confirmed"] == true,
        "Review requires a confirmed exact publication"
    );
    let head = text(p, "commit")?;
    crate::publish::oid(head)?;
    crate::publish::oid(text(p, "base")?)?;
    let reference = text(p, "reference")?;
    let branch = reference
        .strip_prefix("refs/heads/")
        .ok_or_else(|| invalid("Publication must target a source branch".into()))?;
    branch_name(branch)?;
    let destination = text(p, "destination")?.trim_end_matches(".git");
    let knot = origin(&config.knot)?;
    let host = knot
        .host_str()
        .ok_or_else(|| invalid("Missing knot host".into()))?;
    let did_url = format!(
        "{}/{}",
        config.knot.trim_end_matches('/'),
        config.source_repository
    );
    let ssh = format!("git@{host}:{}", config.source_repository);
    let web = origin(&config.web_url)?;
    let human_ssh = format!("git@{host}:{}", web.path().trim_matches('/'));
    let web_ssh = format!(
        "git@{}:{}",
        web.host_str().unwrap_or_default(),
        web.path().trim_matches('/')
    );
    ensure!(
        destination == did_url
            || destination == ssh
            || (config.source_repository == config.repository
                && (destination == config.web_url.trim_end_matches('/')
                    || destination == human_ssh
                    || destination == web_ssh)),
        "Published remote does not match the trusted source repository binding"
    );
    Ok((head.into(), branch.into()))
}
fn branch_name(branch: &str) -> Result<()> {
    ensure!(
        !branch.is_empty()
            && branch.len() <= 244
            && !branch.starts_with('-')
            && !branch.starts_with("refs/")
            && !branch.starts_with('/')
            && !branch.contains("//")
            && branch != "@"
            && !branch.chars().any(char::is_control)
            && branch
                .split('/')
                .all(|component| !component.starts_with('.') && !component.ends_with(".lock"))
            && !branch.contains([' ', '\r', '\n', '~', '^', ':', '?', '*', '[', '\\'])
            && !branch.contains("..")
            && !branch.ends_with(['.', '/'])
            && !branch.contains("@{"),
        "Invalid branch name"
    );
    Ok(())
}
fn validate(input: &SubmitInput) -> Result<()> {
    ensure!(
        input.ticket_key.len() <= 512
            && input
                .ticket_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~:-".contains(&b))
            && !matches!(input.ticket_key.as_str(), "." | ".."),
        "Invalid ticket record key"
    );
    crate::publish::oid(&input.target_base)?;
    branch_name(&input.target_branch)?;
    ensure!(
        !input.title.trim().is_empty()
            && input.title.len() <= 16 * 1024
            && input.body.len() <= 1024 * 1024,
        "Invalid review prose size"
    );
    creation_date(&input.created_at)
}
fn creation_date(date: &str) -> Result<()> {
    ensure!(
        date.len() == 20
            && date.ends_with('Z')
            && date.as_bytes()[4] == b'-'
            && date.as_bytes()[7] == b'-'
            && date.as_bytes()[10] == b'T'
            && date.as_bytes()[13] == b':'
            && date.as_bytes()[16] == b':'
            && date
                .bytes()
                .enumerate()
                .all(|(i, b)| matches!(i, 4 | 7 | 10 | 13 | 16 | 19) || b.is_ascii_digit()),
        "Review creation date must use YYYY-MM-DDTHH:MM:SSZ"
    );
    ensure!(
        (1..=12).contains(&date[5..7].parse::<u8>().unwrap_or(0))
            && (1..=31).contains(&date[8..10].parse::<u8>().unwrap_or(0))
            && date[11..13].parse::<u8>().unwrap_or(99) < 24
            && date[14..16].parse::<u8>().unwrap_or(99) < 60
            && date[17..19].parse::<u8>().unwrap_or(99) < 60,
        "Invalid review creation date"
    );
    let year = date[..4].parse::<u32>().unwrap_or(0);
    let month = date[5..7].parse::<u8>().unwrap_or(0);
    let day = date[8..10].parse::<u8>().unwrap_or(0);
    let max_day = match month {
        4 | 6 | 9 | 11 => 30,
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => 31,
    };
    ensure!(year > 0 && day <= max_day, "Invalid review calendar date");
    Ok(())
}
fn journal(directory: &Path) -> Result<Option<Value>> {
    let path = directory.join("review.json");
    if !path.exists() {
        return Ok(None);
    }
    let value = read(&path)?;
    ensure!(
        matches!(value["schema_version"].as_u64(), Some(1 | 2)),
        "Unsupported review journal schema"
    );
    Ok(Some(value))
}
fn save(directory: &Path, journal: &Value) -> Result<()> {
    crate::environment_lock::atomic_json(&directory.join("review.json"), journal)
}
fn archive(directory: &Path, receipt: &Value, kind: &str) -> Result<()> {
    let attempt = text(receipt, "attempt")?;
    ensure!(
        attempt.len() == 64 && attempt.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid review attempt digest"
    );
    let dir = directory.join("review-attempts").join(attempt);
    crate::state::create_directory(&dir)?;
    // Persist the new directory chain before acknowledging an immutable record.
    files::open_directory(&dir)?.sync_all()?;
    files::open_directory(&directory.join("review-attempts"))?.sync_all()?;
    files::open_directory(directory)?.sync_all()?;
    let path = dir.join(format!("{kind}.json"));
    if path.exists() {
        ensure!(read(&path)? == *receipt, "Immutable review attempt differs");
    } else {
        files::publish_json(&path, receipt, false)?;
    }
    Ok(())
}
fn bound(config: &Config, digest: &str, receipt: &Value) -> Result<()> {
    let active_digest = if receipt["schema_version"] == 2 {
        active_credentials(receipt)?.1
    } else {
        text(receipt, "config_digest")?
    };
    ensure!(
        active_digest == digest
            && receipt["repository"] == config.repository
            && receipt["source_repository"] == config.source_repository,
        "Review configuration changed; inspect retained intent before continuing"
    );
    Ok(())
}
fn generation(authority: &Value) -> Result<u64> {
    authority["generation"]
        .as_u64()
        .filter(|g| *g > 0)
        .ok_or_else(|| invalid("Missing retained credential generation".into()))
}
fn same_authority(left: &Value, right: &Value) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left["generation"] = Value::Null;
    right["generation"] = Value::Null;
    left == right
}
fn active_credentials(receipt: &Value) -> Result<(&Value, &str)> {
    ensure!(
        receipt["schema_version"] == 2 && receipt["connector_authority"].is_object(),
        "Review lacks retained credential authority; automatic migration is refused"
    );
    let mut authority = &receipt["connector_authority"];
    ensure!(
        authority["mode"] == "trusted_owner",
        "Unsupported retained authority mode"
    );
    let mut digest = text(receipt, "config_digest")?;
    let history = receipt["credential_history"]
        .as_array()
        .ok_or_else(|| invalid("Missing retained credential history".into()))?;
    for transition in history {
        let next = &transition["authority"];
        ensure!(
            next.is_object()
                && same_authority(authority, next)
                && generation(next)? > generation(authority)?
                && transition["from_generation"] == generation(authority)?
                && transition["from_config_digest"] == digest,
            "Credential history does not preserve the original authority"
        );
        authority = next;
        digest = text(transition, "to_config_digest")?;
    }
    Ok((authority, digest))
}
fn observe_connector_account(config: &Config) -> Result<()> {
    let connector = config
        .connector
        .as_ref()
        .ok_or_else(|| invalid("Typed connector is required".into()))?;
    let host = crate::json::parse(&files::read_limited(&connector.config, 64 * 1024)?)?;
    let mut command = Command::new(&connector.program);
    command
        .args(["account", "--config"])
        .arg(&connector.config)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/");
    let bytes = crate::process::capture(command, Duration::from_secs(90), 262144)
        .map_err(|_| invalid("Credential account observation failed (output suppressed)".into()))?;
    let account = crate::json::parse(&bytes).map_err(|_| {
        invalid("Invalid credential account observation (output suppressed)".into())
    })?;
    let lifecycle_available = if host["schema_version"] == 1 {
        account["schema_version"] == 1
            && account["lease_expired"] == false
            && account.get("session_policy").is_none()
            && account.get("lifecycle").is_none()
    } else {
        host["schema_version"] == 2
            && host["session_policy"] == "refreshable"
            && account["schema_version"] == 2
            && account["session_policy"] == "refreshable"
            && account["lifecycle"] == "active"
            && account.get("lease_expired").is_none()
            && account.get("lease_expires_at").is_none()
            && account["access_expires_at"].as_u64().is_some_and(|n| n > 0)
            && account["access_expired"].is_boolean()
    };
    ensure!(
        lifecycle_available
            && account["mode"] == "trusted_owner"
            && account["account"] == connector.account
            && account["connection"] == connector.connection
            && account["generation"] == connector.generation
            && account["knot"] == config.knot
            && account["repository"] == config.repository
            && account["source_repository"] == config.source_repository
            && account["profile"] == "TangledReview"
            && account["available"] == true
            && account["uncertain_refresh"] == false,
        "New credential authority or session lifecycle does not match the retained review"
    );
    Ok(())
}
/// Explicit same-owner credential renewal. This operation only observes the
/// connector account and records authority continuity; it never sends a write.
pub fn rebind_credentials(directory: &Path, config_path: &Path) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    handoff::ensure_incoming_committed(&lock.directory)?;
    let directory = lock.directory.as_path();
    let _session = SessionLock::acquire(directory, true)?;
    let (config, _, digest, authority) = context(directory, config_path)?;
    let authority = authority
        .ok_or_else(|| invalid("Credential rebind requires a typed owner connector".into()))?;
    let mut receipt =
        journal(directory)?.ok_or_else(|| invalid("No retained review to rebind".into()))?;
    let (old, old_digest) = active_credentials(&receipt)?;
    ensure!(
        same_authority(old, &authority),
        "Credential rebind changed account, target, paths or policy"
    );
    if old == &authority
        && old_digest == digest
        && receipt["credential_history"]
            .as_array()
            .is_some_and(|h| !h.is_empty())
    {
        return Ok(receipt);
    }
    ensure!(
        generation(&authority)? > generation(old)?,
        "Credential rebind requires a newer generation after explicit login"
    );
    observe_connector_account(&config)?;
    let next_generation = generation(&authority)?;
    let transition = json!({"schema_version":1,"attempt":receipt["attempt"],
        "from_generation":generation(old)?,"from_config_digest":old_digest,
        "to_config_digest":digest,"authority":authority,
        "prior_receipt_digest":files::hash(&serde_json::to_vec(&receipt)?)});
    // Both immutable records precede the active journal switch. Repeating after
    // interruption accepts only the exact same prior receipt and transition.
    archive(
        directory,
        &receipt,
        &format!("credential-before-{next_generation}"),
    )?;
    archive(
        directory,
        &transition,
        &format!("credential-rebind-{next_generation}"),
    )?;
    receipt["credential_history"]
        .as_array_mut()
        .ok_or_else(|| invalid("Missing credential history".into()))?
        .push(transition);
    save(directory, &receipt)?;
    Ok(receipt)
}
// AT record links use CIDv1, dag-cbor, sha256/32 bytes and canonical base32.
// https://atproto.com/specs/data-model#link-and-cid-formats
// This checks syntax/profile only; it does not hash or authenticate record content.
fn ticket_record_cid(encoded: &str) -> Result<()> {
    ensure!(
        encoded.len() == 59 && encoded.starts_with('b'),
        "Invalid AT record CID"
    );
    let mut decoded = [0u8; 36];
    let mut output = 0usize;
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for byte in encoded.bytes().skip(1) {
        let digit = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(invalid("Invalid AT record CID".into())),
        };
        accumulator = (accumulator << 5) | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let slot = decoded
                .get_mut(output)
                .ok_or_else(|| invalid("Invalid AT record CID".into()))?;
            *slot = (accumulator >> bits) as u8;
            output += 1;
            accumulator &= (1u16 << bits) - 1;
        }
    }
    // All four header varints are canonical one-byte values. There must be
    // exactly 32 digest bytes and two zero bits completing the final symbol.
    ensure!(
        output == decoded.len()
            && bits == 2
            && accumulator == 0
            && decoded.starts_with(&[0x01, 0x71, 0x12, 0x20]),
        "Invalid AT record CID"
    );
    Ok(())
}
fn ref_valid(config: &Config, value: &Value, collection: &str) -> Result<()> {
    let prefix = format!("at://{}/{collection}/", config.repository);
    let uri = text(value, "uri")?;
    ensure!(
        uri.starts_with(&prefix)
            && !uri[prefix.len()..].is_empty()
            && uri[prefix.len()..].len() <= 512
            && !matches!(&uri[prefix.len()..], "." | "..")
            && uri[prefix.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~:-".contains(&b)),
        "Unexpected Tangled record URI"
    );
    let cid = text(value, "cid")?;
    ensure!(!cid.is_empty(), "Missing Tangled record CID");
    if collection == TICKET {
        ticket_record_cid(cid)?;
    }
    Ok(())
}
fn matches_patch(receipt: &Value, record: &Value) -> bool {
    let v = &record["value"];
    v["ticket"] == receipt["ticket_key"]
        && v["base"]["oid"] == receipt["submitted_base"]
        && v["head"]["oid"] == receipt["submitted_head"]
        && v["source"]["repo"] == receipt["source_repository"]
        && v["source"]["branch"] == receipt["source_branch"]
}
fn list_patches(config: &Config) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    let mut cursor = String::new();
    for _ in 0..100 {
        let mut params = vec![
            ("repo", config.repository.as_str()),
            ("collection", PATCH),
            ("limit", "100"),
        ];
        if !cursor.is_empty() {
            params.push(("cursor", &cursor));
        }
        let page = get(&config.knot, "com.atproto.repo.listRecords", &params)?;
        let records = page["records"]
            .as_array()
            .ok_or_else(|| invalid("Malformed patch listing".into()))?;
        out.extend(records.iter().cloned());
        match page["cursor"].as_str() {
            Some(next) if !next.is_empty() => {
                ensure!(next != cursor, "Patch listing cursor did not advance");
                cursor = next.into();
            }
            _ => return Ok(out),
        }
    }
    Err(invalid(
        "Patch listing exceeded bounded pagination; reconciliation incomplete".into(),
    ))
}
fn finish(directory: &Path, config: &Config, receipt: &mut Value, patch: &Value) -> Result<Value> {
    ref_valid(config, patch, PATCH)?;
    receipt["patch"] = json!({"uri":patch["uri"],"cid":patch["cid"]});
    if let Some(change) = patch.get("x-tngl-change") {
        crate::publish::oid(
            change
                .as_str()
                .ok_or_else(|| invalid("Invalid patch change".into()))?,
        )?;
        receipt["patch"]["x-tngl-change"] = change.clone();
    }
    receipt["knot_confirmed"] = json!(true);
    if config.connector.is_some() {
        let mut subjects = Vec::new();
        if receipt["previous"].is_null() {
            subjects.push(receipt["ticket"].clone());
        }
        subjects.push(receipt["patch"].clone());
        let mut attestations = Vec::new();
        for subject in subjects {
            let mut record = json!({"$type":"org.tangled.graph.attestation","subject":{"uri":subject["uri"],"cid":subject["cid"]},"createdAt":receipt["ticket_record"]["createdAt"]});
            if let Some(change) = subject.get("x-tngl-change") {
                record["change"] = change.clone();
            }
            let body = json!({"rkey":attestation_key(&record)?,"record":record});
            attestations.push(
                json!({"phase":"ready","request":connector_request(config,"attest_record",&body)?,"change_binding":if record.get("change").is_some(){"known"}else{"incomplete"}}),
            );
        }
        receipt["attestations"] = json!(attestations);
        receipt["phase"] = json!("attestation_pending");
        receipt["authentication_mode"] = json!("trusted_owner");
        save(directory, receipt)?;
        return attest(directory, config, receipt);
    }
    receipt["phase"] = json!("submitted");
    archive(directory, receipt, "confirmed")?;
    save(directory, receipt)?;
    Ok(receipt.clone())
}
fn attestation_key(record: &Value) -> Result<String> {
    let micros: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("Host clock is before epoch".into()))?
        .as_micros()
        .try_into()
        .map_err(|_| invalid("Host timestamp overflow".into()))?;
    let hash = files::hash(&serde_json::to_vec(record)?);
    let clock = u64::from_str_radix(&hash[..4], 16)
        .map_err(|_| invalid("Invalid attestation digest".into()))?
        & 1023;
    let mut value = micros
        .checked_mul(1024)
        .and_then(|v| v.checked_add(clock))
        .ok_or_else(|| invalid("Attestation timestamp overflow".into()))?;
    let alphabet = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut key = [b'2'; 13];
    for byte in key.iter_mut().rev() {
        *byte = alphabet[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(key.to_vec()).map_err(Into::into)
}
fn attest(directory: &Path, config: &Config, receipt: &mut Value) -> Result<Value> {
    let connector = config
        .connector
        .as_ref()
        .ok_or_else(|| invalid("Actor attestation needs a typed host connector".into()))?;
    if !directory
        .join("review-attempts")
        .join(text(receipt, "attempt")?)
        .join("knot-confirmed.json")
        .exists()
    {
        archive(directory, receipt, "knot-confirmed")?;
    }
    let count = receipt["attestations"]
        .as_array()
        .ok_or_else(|| invalid("Attestation intents are missing".into()))?
        .len();
    ensure!((1..=2).contains(&count), "Invalid attestation intent count");
    for index in 0..count {
        let stage = receipt["attestations"][index]["phase"].clone();
        if stage == "confirmed" {
            continue;
        }
        ensure!(
            stage == "ready" || stage == "pending",
            "Unknown attestation stage"
        );
        let original = &receipt["attestations"][index]["request"];
        let request = connector_request(config, "attest_record", &original["body"])?;
        ensure!(
            original["operation"] == "attest_record"
                && original["request_id"] == request["request_id"]
                && original["connection"] == request["connection"],
            "Retained attestation intent differs from its dispatch envelope"
        );
        let _parents = if stage == "ready" {
            crate::stacks::guard(directory)?
        } else {
            Vec::new()
        };
        if stage == "ready" {
            receipt["attestations"][index]["phase"] = json!("pending");
            save(directory, receipt)?;
        }
        let response = connector_call(
            config,
            if stage == "ready" {
                "execute"
            } else {
                "reconcile"
            },
            &request,
        )?;
        if response["outcome"] == "not_sent" && stage == "ready" {
            receipt["attestations"][index]["phase"] = json!("ready");
            save(directory, receipt)?;
        }
        ensure!(response["outcome"]=="confirmed","Actor attestation is unconfirmed; reconcile the exact retained key without resubmitting the patch");
        let result = &response["result"];
        ensure!(
            result["uri"]
                == format!(
                    "at://{}/org.tangled.graph.attestation/{}",
                    connector.account,
                    text(&request["body"], "rkey")?
                )
                && !text(result, "cid")?.is_empty(),
            "Actor attestation response differs from the retained account and key"
        );
        receipt["attestations"][index]["response"] = result.clone();
        receipt["attestations"][index]["phase"] = json!("confirmed");
        save(directory, receipt)?;
    }
    receipt["actor_attribution"] = json!({"pds_records":"accepted","appview":"unverified","change_binding":if receipt["attestations"].as_array().is_some_and(|items| items.iter().all(|item| item["change_binding"] == "known")){"known"}else{"incomplete"}});
    receipt["phase"] = json!("submitted");
    archive(directory, receipt, "confirmed")?;
    save(directory, receipt)?;
    Ok(receipt.clone())
}
fn submit_patch(directory: &Path, config: &Config, receipt: &mut Value) -> Result<Value> {
    let body = json!({"repo":config.repository,"patch":{"ticket":receipt["ticket_key"],"base":{"oid":receipt["submitted_base"]},"head":{"oid":receipt["submitted_head"]},"sourceRepo":receipt["source_repository"],"sourceBranch":receipt["source_branch"]}});
    let patch = post(directory, config, SUBMIT, &body, receipt, "patch_pending")?;
    finish(directory, config, receipt, &patch)
}
/// Create a stable ticket, then submit an immutable patch. Repeating the same
/// confirmed request is idempotent. Uncertain writes require public read-back.
pub fn submit(directory: &Path, config_path: &Path, input: &SubmitInput) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let directory = lock.directory.as_path();
    let _session = SessionLock::acquire(directory, true)?;
    validate(input)?;
    let (config, p, digest, authority) = context(directory, config_path)?;
    let (head, branch) = source(&config, &p)?;
    let required_checks = if !p["checks"].is_null() {
        let export = Path::new(text(&p, "export")?);
        crate::publication_checks::revalidate(export, &p["checks"])?;
        json!({"publication_head":head,"receipt":read(&export.join("checks.json"))?})
    } else {
        Value::Null
    };
    let prior = journal(directory)?;
    if let Some(old) = &prior {
        handoff::validate_first_submit(directory, old, &p, input)?;
        bound(&config, &digest, old)?;
        ensure!(
            old["phase"] == "submitted",
            "Pending review writes must be reconciled before submission"
        );
        ensure!(
            (input.ticket_key.is_empty() || old["ticket_key"] == input.ticket_key)
                && old["target_branch"] == input.target_branch,
            "Existing review belongs to a different ticket or target"
        );
        if old["submitted_head"] == head && old["submitted_base"] == input.target_base {
            return Ok(old.clone());
        }
        ensure!(
            input.resubmit && !input.ticket_key.is_empty(),
            "Use explicit resubmit and the allocated ticket key for a new immutable round"
        );
    } else {
        ensure!(!input.resubmit && input.ticket_key.is_empty(), "New tickets require server allocation; an explicit ticket key requires an existing resubmit round");
    }
    if prior.is_some() {
        let ticket = get(
            &config.knot,
            "com.atproto.repo.getRecord",
            &[
                ("repo", &config.repository),
                ("collection", TICKET),
                ("rkey", &input.ticket_key),
            ],
        )?;
        ref_valid(&config, &ticket, TICKET)?;
        ensure!(
            ticket["uri"]
                == json!(format!(
                    "at://{}/{TICKET}/{}",
                    config.repository, input.ticket_key
                ))
                && ticket["value"]["targetBranch"] == input.target_branch
                && ticket["value"]["state"] == "open",
            "Resubmission ticket target or state changed"
        );
    }
    let mut ticket_record = json!({"$type":TICKET,"title":{"$type":"org.tangled.markup.markdown#inline","text":input.title},"state":"open","targetBranch":input.target_branch,"createdAt":input.created_at});
    if !input.body.trim().is_empty() {
        ticket_record["body"] = json!({"$type":"org.tangled.markup.markdown","text":input.body});
    }
    let ticket_uri = format!("at://{}/{TICKET}/{}", config.repository, input.ticket_key);
    let mut receipt = json!({"schema_version":1,"phase":if prior.is_some(){"patch_ready"}else{"ticket_ready"},"config_digest":digest,"repository":config.repository,"source_repository":config.source_repository,"ticket_key":input.ticket_key,"ticket_uri":ticket_uri,"ticket_record":ticket_record,"submitted_head":head,"submitted_base":input.target_base,"publication_base":p["base"],"required_checks":required_checks,"change_summary":{"title":input.title,"body":input.body},"source_branch":branch,"target_branch":input.target_branch,"url":format!("{}/pulls/{}",config.web_url.trim_end_matches('/'),input.ticket_key),"previous":prior.as_ref().map(|v|json!({"attempt":v["attempt"],"patch":v["patch"],"submitted_head":v["submitted_head"],"submitted_base":v["submitted_base"]}))});
    if prior.is_none() {
        receipt["ticket_allocation"] = json!("server");
        receipt["ticket_key"] = Value::Null;
        receipt["ticket_uri"] = Value::Null;
        receipt["url"] = Value::Null;
    }
    if let Some(authority) = authority {
        receipt["schema_version"] = json!(2);
        receipt["connector_authority"] = authority;
        receipt["credential_history"] = json!([]);
    }
    if let Some(predecessor) = handoff::predecessor(directory)? {
        receipt["review_predecessor"] = predecessor;
    }
    receipt["attempt"] = json!(files::hash(&serde_json::to_vec(&receipt)?));
    ensure!(!directory.join("review-attempts").join(text(&receipt,"attempt")?).join("abandoned.json").exists(), "An abandoned immutable attempt cannot be reused; provide a new creation timestamp for a new ticket attempt");
    archive(directory, &receipt, "intent")?;
    save(directory, &receipt)?;
    if prior.is_none() {
        create_ticket(directory, &config, &mut receipt)?;
    }
    submit_patch(directory, &config, &mut receipt)
}
/// Reconcile accepted-but-unacknowledged writes. An absent uncertain patch is
/// retained as uncertain: absence in an eventually consistent list permits no retry.
pub fn reconcile(directory: &Path, config_path: &Path) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let directory = lock.directory.as_path();
    let _session = SessionLock::acquire(directory, true)?;
    handoff::ensure_incoming_committed(directory)?;
    let (config, publication, digest, _) = context(directory, config_path)?;
    let mut r = journal(directory)?.ok_or_else(|| invalid("No review intent exists".into()))?;
    bound(&config, &digest, &r)?;
    if r["phase"] == "submitted" {
        return Ok(r);
    }
    ensure_review_writable(directory)?;
    if r["phase"] == "attestation_pending" {
        return attest(directory, &config, &mut r);
    }
    if r["phase"] == "ticket_ready" || r["phase"] == "patch_ready" {
        let (head, branch) = source(&config, &publication)?;
        ensure!(
            r["submitted_head"] == head && r["source_branch"] == branch,
            "Source changed before a ready review write"
        );
    }
    if r["phase"] == "ticket_ready" {
        create_ticket(directory, &config, &mut r)?;
    }
    if r["phase"] == "ticket_pending" {
        ensure!(r["ticket_allocation"] == "server", "Legacy fixed-key ticket intent remains uncertain; archive evidence and abandon explicitly");
        if !r["ticket_response"].is_null() {
            let ticket = ticket_get(&config, text(&r["ticket_response"], "uri")?)?;
            pin_ticket(directory, &config, &mut r, ticket)?;
        } else {
            let candidates = ticket_candidates(&config, &r)?;
            // Matching prose and actor do not correlate an unknown create acknowledgement.
            // Every candidate needs an explicit host selection of its strong reference.
            r["ticket_candidates"] = json!(candidates);
            r["ticket_recovery"] = json!("explicit_selection_required");
            return Ok(r);
        }
    }
    if r["phase"] == "patch_ready" {
        let (head, branch) = source(&config, &publication)?;
        ensure!(
            r["submitted_head"] == head && r["source_branch"] == branch,
            "Source changed before patch submission"
        );
        let ticket = get(
            &config.knot,
            "com.atproto.repo.getRecord",
            &[
                ("repo", &config.repository),
                ("collection", TICKET),
                ("rkey", text(&r, "ticket_key")?),
            ],
        )?;
        ref_valid(&config, &ticket, TICKET)?;
        ensure!(
            ticket["uri"] == r["ticket_uri"]
                && ticket["value"]["targetBranch"] == r["target_branch"]
                && ticket["value"]["state"] == "open",
            "Recovered ticket target or state changed"
        );
        if r["ticket_allocation"] == "server" && r["previous"].is_null() {
            ticket_matches(&config, &r, &ticket)?;
            ensure!(
                ticket["cid"] == r["ticket"]["cid"],
                "Pinned ticket changed before recovered patch submission"
            );
        }
        return submit_patch(directory, &config, &mut r);
    }
    ensure!(r["phase"] == "patch_pending", "Unknown review phase");
    let matching: Vec<_> = list_patches(&config)?
        .into_iter()
        .filter(|p| matches_patch(&r, p))
        .collect();
    ensure!(
        matching.len() == 1,
        "Uncertain patch lacks exactly one matching remote record; no duplicate round was sent"
    );
    finish(directory, &config, &mut r, &matching[0])
}
fn ticket_candidates(config: &Config, receipt: &Value) -> Result<Vec<Value>> {
    let mut candidates = Vec::new();
    let mut cursors = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut cursor = String::new();
    for _ in 0..100 {
        let mut params = vec![
            ("repo", config.repository.as_str()),
            ("collection", TICKET),
            ("limit", "100"),
        ];
        if !cursor.is_empty() {
            params.push(("cursor", &cursor));
        }
        let page = get(&config.knot, "com.atproto.repo.listRecords", &params)?;
        let records = page["records"]
            .as_array()
            .ok_or_else(|| invalid("Malformed ticket listing".into()))?;
        ensure!(records.len() <= 100, "Ticket listing page exceeds limit");
        for listed in records {
            ref_valid(config, listed, TICKET)?;
            ensure!(
                ids.insert(text(listed, "uri")?.to_owned()),
                "Ticket listing repeats a record; recovery incomplete"
            );
            if ticket_matches(config, receipt, listed).is_ok() {
                let strong = ticket_get(config, text(listed, "uri")?)?;
                ticket_matches(config, receipt, &strong)?;
                ensure!(
                    strong["cid"] == listed["cid"],
                    "Ticket changed during candidate discovery"
                );
                candidates.push(json!({"uri":strong["uri"],"cid":strong["cid"]}));
            }
        }
        match page.get("cursor") {
            None | Some(Value::Null) => return Ok(candidates),
            Some(Value::String(next)) if next.is_empty() => return Ok(candidates),
            Some(Value::String(next)) if !next.is_empty() && cursors.insert(next.clone()) => {
                cursor = next.clone()
            }
            _ => {
                return Err(invalid(
                    "Ticket pagination is malformed or cyclic; recovery incomplete".into(),
                ))
            }
        }
    }
    Err(invalid(
        "Ticket listing exceeded bounded pagination; recovery incomplete".into(),
    ))
}
/// Select a remote ticket only by explicit host-reviewed strong reference.
/// Listing completeness does not establish absence or provider idempotency.
pub fn select_ticket(directory: &Path, config_path: &Path, uri: &str, cid: &str) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let directory = lock.directory.as_path();
    let _session = SessionLock::acquire(directory, true)?;
    let (config, _, digest, _) = context(directory, config_path)?;
    let mut receipt =
        journal(directory)?.ok_or_else(|| invalid("No review intent exists".into()))?;
    bound(&config, &digest, &receipt)?;
    ensure!(
        receipt["phase"] == "ticket_pending"
            && receipt["ticket_allocation"] == "server"
            && receipt["ticket_response"].is_null(),
        "Only an uncertain server-allocated ticket can be selected"
    );
    let candidates = ticket_candidates(&config, &receipt)?;
    ensure!(
        candidates
            .iter()
            .any(|v| v["uri"] == uri && v["cid"] == cid),
        "Selected ticket does not match complete retained-intent candidate discovery"
    );
    let ticket = ticket_get(&config, uri)?;
    ensure!(
        ticket["cid"] == cid,
        "Selected ticket strong reference changed"
    );
    receipt["ticket_selection"] = json!({"source":"host_owner","uri":uri,"cid":cid});
    // No change OID is inferred from record content or the attestation key.
    pin_ticket(directory, &config, &mut receipt, ticket)?;
    Ok(receipt)
}
/// Archive an uncertain new-ticket attempt before releasing the current pointer.
/// This neither deletes remote records nor establishes that no remote ticket exists.
pub fn abandon_ticket(directory: &Path, config_path: &Path, explanation: &str) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let directory = lock.directory.as_path();
    let _session = SessionLock::acquire(directory, true)?;
    let (config, _, digest, _) = context(directory, config_path)?;
    let receipt = journal(directory)?.ok_or_else(|| invalid("No review intent exists".into()))?;
    bound(&config, &digest, &receipt)?;
    ensure!(
        receipt["phase"] == "ticket_pending" && receipt["previous"].is_null(),
        "Only an uncertain new-ticket attempt can be abandoned"
    );
    ensure!(
        !explanation.trim().is_empty() && explanation.len() <= 2048 && !explanation.contains('\0'),
        "Abandonment needs a bounded host explanation"
    );
    let mut abandoned = receipt.clone();
    abandoned["abandonment"] = json!({"source":"host_owner","explanation":explanation,"remote_effect":"unknown","remaining_work":"Inspect remote candidates and close any unwanted ticket explicitly; no remote rollback was performed"});
    archive(directory, &abandoned, "abandoned")?;
    std::fs::remove_file(directory.join("review.json"))?;
    files::open_directory(directory)?.sync_all()?;
    Ok(abandoned)
}
fn ci(config: &Config, r: &Value) -> Result<Value> {
    let unknown = |reason: &str| {
        json!({"status":"unknown","reason":reason,
        "commit":r["submitted_head"],"pipelines":[],"complete":false,"acceptance_authority":false})
    };
    let Some(spindle) = &config.spindle else {
        return Ok(unknown("spindle_not_configured"));
    };
    let page = match get(
        spindle,
        "org.tangled.ci.queryPipelines",
        &[
            ("repo", &config.repository),
            ("commits", text(r, "submitted_head")?),
            ("limit", "250"),
        ],
    ) {
        Ok(page) => page,
        Err(_) => return Ok(unknown("spindle_unavailable")),
    };
    let Some(pipelines) = page["pipelines"].as_array() else {
        return Ok(unknown("invalid_pipeline_page"));
    };
    let Some(total) = page["total"].as_u64() else {
        return Ok(unknown("invalid_pipeline_total"));
    };
    if !page["cursor"].is_null()
        || total != pipelines.len() as u64
        || pipelines.is_empty()
        || pipelines.len() > 250
    {
        return Ok(unknown("incomplete_pipeline_page"));
    }
    let mut failed = false;
    let mut pending = false;
    for pipeline in pipelines {
        if pipeline["repo"] != config.repository
            || pipeline["commit"] != r["submitted_head"]
            || !(pipeline["sourceRepo"].is_null() && config.source_repository == config.repository
                || pipeline["sourceRepo"] == config.source_repository)
        {
            return Ok(unknown("pipeline_binding_mismatch"));
        }
        let Some(workflows) = pipeline["workflows"].as_array().filter(|w| !w.is_empty()) else {
            return Ok(unknown("missing_workflow_results"));
        };
        for workflow in workflows {
            match workflow["status"].as_str() {
                Some("success") => (),
                Some("failed" | "timeout" | "cancelled") => failed = true,
                Some("pending" | "blocked" | "running") => pending = true,
                _ => return Ok(unknown("invalid_workflow_status")),
            }
        }
    }
    Ok(
        json!({"status":if failed {"failed"} else if pending {"pending"} else {"success"},
        "commit":r["submitted_head"],"pipelines":pipelines,"total":total,"complete":true,"acceptance_authority":false}),
    )
}
fn required_check_summary(review: &Value) -> Value {
    let unknown = || json!({"status":"unknown","commit":review["submitted_head"],"acceptance_authority":false});
    let binding = &review["required_checks"];
    let receipt = &binding["receipt"];
    let digest = |value: &Value| {
        value
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    if binding["publication_head"] != review["submitted_head"]
        || receipt["schema_version"] != 1
        || !digest(&receipt["snapshot_sha256"])
        || !digest(&receipt["policy_sha256"])
    {
        return unknown();
    }
    let Some(commands) = receipt["commands"].as_array().filter(|v| !v.is_empty()) else {
        return unknown();
    };
    let Some(results) = receipt["results"].as_array() else {
        return unknown();
    };
    let complete = results.len() == commands.len()
        && results.iter().all(|result| {
            result["exit_code"].as_i64().is_some() && digest(&result["output_sha256"])
        });
    let status = if !complete
        || !receipt["passed"].is_boolean()
        || !receipt["cleanup_confirmed"].is_boolean()
    {
        "unknown"
    } else if receipt["passed"] == true
        && receipt["cleanup_confirmed"] == true
        && results.iter().all(|r| r["exit_code"] == 0)
    {
        "success"
    } else {
        "failed"
    };
    // Only this public projection is delivered: commands, paths, errors and
    // verifier identities stay in the host-owned required-check receipt.
    json!({"status":status,"commit":review["submitted_head"],"snapshot_sha256":receipt["snapshot_sha256"],
        "policy_sha256":receipt["policy_sha256"],"completed_checks":results.len(),"required_checks":commands.len(),
        "complete":complete,"acceptance_authority":false})
}
// Server timestamps may include fractional seconds. Raw RFC3339 string order
// puts `.5Z` before `Z`; compare normalized UTC seconds and nanoseconds instead.
// Unknown time zones or malformed dates deliberately leave admission unknown.
fn round_time(value: &Value) -> Option<(String, u32)> {
    let utc = value.as_str()?.strip_suffix('Z')?;
    let (seconds, fraction) = utc.split_once('.').unwrap_or((utc, ""));
    if seconds.len() != 19
        || !seconds.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            _ => b.is_ascii_digit(),
        })
        || (utc.contains('.') && fraction.is_empty())
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let nanos = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u32>()
            .ok()?
            .checked_mul(10u32.pow((9 - fraction.len()) as u32))?
    };
    Some((seconds.to_owned(), nanos))
}
/// Read local exact source binding and public CI. CI is informational; successful
/// agent-editable workflows never replace the independent required-check receipt.
pub fn status(directory: &Path, config_path: &Path) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    status_locked(&lock, config_path)
}
fn status_locked(lock: &StateLock, config_path: &Path) -> Result<Value> {
    let directory = lock.directory.as_path();
    let (config, p, digest, authority) = context(directory, config_path)?;
    let handoff = handoff::summary(directory)?;
    let Some(mut r) = journal(directory)? else {
        return Ok(json!({"schema_version":1,"phase":"draft","publication":p,
            "display_state":"draft","handoff":handoff,"human_review":if config.require_owner_review {json!({"source":"host_owner","status":"unknown","reason":"no_confirmed_round","required":true})} else {json!({"status":"unknown","reason":"decision_source_unsupported"})}}));
    };
    r["handoff"] = handoff;
    bound(&config, &digest, &r)?;
    let continuous_current = current_publication(directory).is_ok();
    r["continuous_publication_current"] = json!(continuous_current);
    r["source_ahead"] = json!(!continuous_current || p["commit"] != r["submitted_head"]);
    r["current_source_head"] = p["commit"].clone();
    if r["phase"] == "submitted" {
        r["ci"] = ci(&config, &r)?;
        let rounds = list_patches(&config)?;
        let exact = rounds.iter().find(|p| {
            p["uri"] == r["patch"]["uri"] && p["cid"] == r["patch"]["cid"] && matches_patch(&r, p)
        });
        r["remote_round_match"] = json!(exact.is_some());
        let created = exact.and_then(|p| round_time(&p["value"]["createdAt"]));
        let mut ambiguous = created.is_none();
        let mut newer = false;
        for patch in rounds
            .iter()
            .filter(|p| p["value"]["ticket"] == r["ticket_key"] && p["uri"] != r["patch"]["uri"])
        {
            match round_time(&patch["value"]["createdAt"])
                .as_ref()
                .zip(created.as_ref())
            {
                Some((a, b)) if a > b => newer = true,
                Some((a, b)) if a < b => (),
                _ => ambiguous = true,
            }
        }
        r["superseded"] = if ambiguous && !newer {
            Value::Null
        } else {
            json!(newer)
        };
    }
    r["ticket_observation"] = json!("unknown");
    if r["phase"] == "submitted" {
        // Read current provider evidence; never infer a human decision from
        // comments or treat cached CI as ticket/merge authority.
        if let Some(key) = r["ticket_key"].as_str() {
            if let Ok(ticket) = get(
                &config.knot,
                "com.atproto.repo.getRecord",
                &[
                    ("repo", &config.repository),
                    ("collection", TICKET),
                    ("rkey", key),
                ],
            ) {
                if ref_valid(&config, &ticket, TICKET).is_ok() && ticket["uri"] == r["ticket_uri"] {
                    r["ticket_observation"] = json!(if ticket["value"]["state"] == "open"
                        && ticket["value"]["targetBranch"] == r["target_branch"]
                    {
                        "open_current_target"
                    } else {
                        "closed_or_retargeted"
                    });
                }
            }
        }
    }
    r["human_review"] = human_review(directory, &config, &digest, authority.as_ref(), &r)?;
    r["display_state"] = json!(if r["phase"] != "submitted" {
        "recovery_needed"
    } else if !continuous_current {
        "stale_continuous_epoch"
    } else if r["superseded"] == true {
        "superseded_round"
    } else if r["remote_round_match"] != true
        || r["superseded"] != false
        || r["ticket_observation"] != "open_current_target"
    {
        "unknown"
    } else if r["human_review"]["status"] == "current"
        && r["human_review"]["decision"] == "changes_requested"
    {
        "changes_requested"
    } else if r["ci"]["status"] == "failed" {
        "checks_failed"
    } else if r["ci"]["status"] == "unknown" {
        "unknown"
    } else {
        "requested_review"
    });
    r["display_scope"] = json!("submitted_round");
    Ok(r)
}
// Host-only context, never part of the delivered/public feedback envelope.
// Binding the exact feedback hash makes an interrupted two-file fetch fail
// closed until another supported fetch reconstructs the pair.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FeedbackOwnerContext {
    schema_version: u32,
    config: PathBuf,
    feedback_sha256: String,
}
/// Fetch comments for the ticket and exact immutable patch, preserving subject
/// references and pagination cursors. Persist only within the owning task state.
pub fn feedback(directory: &Path, config_path: &Path) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let directory = lock.directory.as_path();
    let (config, _, digest, _) = context(directory, config_path)?;
    let r = journal(directory)?.ok_or_else(|| invalid("No review exists".into()))?;
    bound(&config, &digest, &r)?;
    ensure!(
        r["phase"] == "submitted",
        "Feedback requires a confirmed review round"
    );
    let service = config
        .bobbin
        .as_deref()
        .ok_or_else(|| invalid("Feedback requires an explicit public bobbin endpoint".into()))?;
    let mut pages = Vec::new();
    for subject in [text(&r, "ticket_uri")?, text(&r["patch"], "uri")?] {
        let page = get(
            service,
            "org.tangled.feed.listComments",
            &[("subject", subject), ("limit", "1000")],
        )?;
        ensure!(page["items"].is_array(), "Malformed feedback response");
        pages.push(json!({"subject":subject,"response":page}));
    }
    let result = json!({"schema_version":1,"attempt":r["attempt"],"repository":config.repository,"submitted_head":r["submitted_head"],"submitted_base":r["submitted_base"],"patch":r["patch"],"pages":pages,"ci":ci(&config, &r)?,"required_checks":required_check_summary(&r),"human_review":status_locked(&lock, config_path)?["human_review"],"untrusted_content":true});
    crate::environment_lock::atomic_json(&directory.join("review-feedback.json"), &result)?;
    if config.require_owner_review {
        let owner_context = FeedbackOwnerContext {
            schema_version: 1,
            config: config_path.canonicalize()?,
            feedback_sha256: files::hash(&serde_json::to_vec(&result)?),
        };
        crate::environment_lock::atomic_json(
            &directory.join("review-feedback-owner-context.json"),
            &owner_context,
        )?;
    }
    Ok(result)
}
/// Copies feedback as a JSON document; comments never become host commands.
pub trait FeedbackDriver {
    fn deliver(&mut self, current: &Value, bytes: &[u8]) -> Result<()>;
}
struct NativeFeedback;
impl FeedbackDriver for NativeFeedback {
    fn deliver(&mut self, current: &Value, bytes: &[u8]) -> Result<()> {
        crate::continuous::native::admit(current)?;
        let backend = crate::openshell::Backend::new(&current["context"])?;
        backend.verify_execution(current)?;
        // This fixed installer executes inside the sandbox. Refuse a substituted
        // workspace link; replace the JSON atomically by dirfd.
        let script = r#"import os,sys
data=sys.stdin.buffer.read(2621441)
if len(data)>2621440: raise ValueError('Feedback exceeds delivery limit')
directory=os.open('/sandbox/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
name='.review-feedback-'+os.urandom(12).hex()
try:
 fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
 with os.fdopen(fd,'wb') as output:
  output.write(data);output.flush();os.fsync(output.fileno())
 os.replace(name,'review-feedback.json',src_dir_fd=directory,dst_dir_fd=directory)
finally:
 try: os.unlink(name,dir_fd=directory)
 except FileNotFoundError: pass
 os.close(directory)
"#;
        let mut command = backend.command();
        command.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--timeout",
            "30",
            text(current, "sandbox_name")?,
            "--",
            "python3",
            "-c",
            script,
        ]);
        crate::process::capture_input(command, bytes, std::time::Duration::from_secs(35), 65536)?;
        backend.verify_execution(current)?;
        Ok(())
    }
}
pub fn deliver_feedback(directory: &Path) -> Result<Value> {
    deliver_feedback_with(directory, &mut NativeFeedback)
}
pub fn deliver_feedback_with(directory: &Path, driver: &mut impl FeedbackDriver) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    ensure_review_writable(&lock.directory)?;
    let _sessions = SessionLock::acquire(&lock.directory, true)?;
    let current =
        crate::state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let review = journal(&lock.directory)?.ok_or_else(|| invalid("No review exists".into()))?;
    let feedback = crate::state::read(&lock.directory.join("review-feedback.json"))?
        .ok_or_else(|| invalid("Fetch review feedback before delivery".into()))?;
    ensure!(
        review["phase"] == "submitted"
            && feedback["schema_version"] == 1
            && feedback["untrusted_content"] == true,
        "Feedback requires a confirmed review and an untrusted-content envelope"
    );
    for key in ["attempt", "submitted_head", "submitted_base", "patch"] {
        ensure!(
            !review[key].is_null() && feedback[key] == review[key],
            "Feedback belongs to a different review round"
        );
    }
    if feedback["human_review"]["source"] == "host_owner" {
        let owner_context: FeedbackOwnerContext =
            serde_json::from_value(crate::json::parse(&files::read_limited(
                &lock.directory.join("review-feedback-owner-context.json"),
                64 * 1024,
            )?)?)?;
        ensure!(
            owner_context.schema_version == 1
                && owner_context.feedback_sha256 == files::hash(&serde_json::to_vec(&feedback)?),
            "Feedback owner context is missing or inconsistent; refetch before delivery"
        );
        // Reuse trusted configuration validation, the retained policy binding,
        // publication and current provider observations. Decision identity alone
        // cannot prove that an unchanged approval remains applicable.
        let observed = status_locked(&lock, &owner_context.config)?;
        ensure!(
            feedback["human_review"] == observed["human_review"],
            "Owner decision or applicability changed since feedback fetch; refetch before delivery"
        );
    }
    let bytes = serde_json::to_vec(&feedback)?;
    ensure!(bytes.len() <= 2621440, "Feedback exceeds delivery limit");
    driver.deliver(&current, &bytes)?;
    let receipt = json!({"schema_version":1,"attempt":review["attempt"],"sandbox_id":current["sandbox_id"],"path":"/sandbox/workspace/review-feedback.json","sha256":crate::files::hash(&bytes),"untrusted_content":true,"delivered":true});
    crate::environment_lock::atomic_json(
        &lock.directory.join("review-feedback-delivery.json"),
        &receipt,
    )?;
    Ok(receipt)
}
/// Exact review admission only. The caller must additionally verify independent
/// required checks, signing policy and a fast-forward target lease before merging.
pub fn merge_admission(
    directory: &Path,
    config_path: &Path,
    expected_head: &str,
    expected_base: &str,
) -> Result<Value> {
    let lock = StateLock::acquire(directory)?;
    let _sessions = SessionLock::acquire(&lock.directory, true)?;
    let _parents = crate::stacks::guard(&lock.directory)?;
    merge_admission_locked(&lock, config_path, expected_head, expected_base)
}
/// Use with a retained state lock and an exclusive SessionLock across the host
/// merge operation. The lock must remain alive until the target effect completes.
pub fn merge_admission_locked(
    lock: &StateLock,
    config_path: &Path,
    expected_head: &str,
    expected_base: &str,
) -> Result<Value> {
    ensure_review_writable(&lock.directory)?;
    crate::publish::oid(expected_head)?;
    crate::publish::oid(expected_base)?;
    let (config, publication, _, _) = context(&lock.directory, config_path)?;
    ensure!(config.repository == config.source_repository,
        "Merge supports only the same repository for source and target; fork merge needs a separate target transport binding");
    source(&config, &publication)?;
    let r = status_locked(lock, config_path)?;
    ensure!(
        r["ticket_observation"] == "open_current_target",
        "Review ticket is closed or its target changed or current evidence is unavailable"
    );
    ensure!(
        r["phase"] == "submitted"
            && r["submitted_head"] == expected_head
            && r["submitted_base"] == expected_base
            && r["source_ahead"] == false
            && r["superseded"] == false
            && r["remote_round_match"] == true,
        "Merge requires the current exact confirmed round and source"
    );
    ensure!(
        !config.require_owner_review
            || (r["human_review"]["source"] == "host_owner"
                && r["human_review"]["status"] == "current"
                && r["human_review"]["decision"] == "approved"),
        "Merge requires a current explicit approved host-owner decision"
    );
    Ok(
        json!({"review":r,"merge_performed":false,"required_host_checks":["independent_required_check_receipt","trusted_signature_verification","fast_forward_ancestry","expected_target_lease"]}),
    )
}

#[cfg(test)]
mod ticket_cid_tests {
    use super::ticket_record_cid;
    use sha2::{Digest, Sha256};

    // Independent encoder extracts each symbol by absolute bit position, unlike
    // the production decoder's incremental accumulator and byte emission.
    fn encode(raw: &[u8]) -> String {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut encoded = String::from("b");
        for offset in (0..raw.len() * 8).step_by(5) {
            let mut digit = 0u8;
            for bit in 0..5 {
                let index = offset + bit;
                let value = raw
                    .get(index / 8)
                    .map_or(0, |byte| (byte >> (7 - index % 8)) & 1);
                digit = (digit << 1) | value;
            }
            encoded.push(char::from(alphabet[usize::from(digit)]));
        }
        encoded
    }

    #[test]
    fn seeded_ticket_cid_profile_matches_independent_binary_vectors(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz234567";
        for seed in 1u64..=300 {
            let mut raw = vec![1, 0x71, 0x12, 0x20];
            raw.extend_from_slice(&Sha256::digest(seed.to_be_bytes()));
            let encoded = encode(&raw);
            assert!(ticket_record_cid(&encoded).is_ok(), "seed {seed}");
            for header in 0..4 {
                let mut changed = raw.clone();
                changed[header] ^= 1;
                assert!(
                    ticket_record_cid(&encode(&changed)).is_err(),
                    "seed {seed}, header {header}"
                );
            }
            assert!(
                ticket_record_cid(&encode(&raw[..35])).is_err(),
                "seed {seed}, short digest"
            );
            let mut extended = raw;
            extended.push(0);
            assert!(
                ticket_record_cid(&encode(&extended)).is_err(),
                "seed {seed}, long digest"
            );
            let mut padding = encoded.into_bytes();
            let last = padding[58];
            let value = alphabet
                .iter()
                .position(|byte| *byte == last)
                .ok_or("Independent encoder emitted invalid alphabet")?;
            padding[58] = alphabet[value | 1];
            let padding = String::from_utf8(padding)?;
            assert!(
                ticket_record_cid(&padding).is_err(),
                "seed {seed}, nonzero padding"
            );
        }
        Ok(())
    }
}
