//! Provider bridge: only an opaque reference and a non-secret routing UUID cross the boundary.
use crate::{
    error::{Error, Result},
    files, state,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::json;
use std::{
    ffi::CString,
    io::Write,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn is_reference(value: &str) -> bool {
    let Some(name) = value.strip_prefix("openshell:resolve:env:") else {
        return false;
    };
    let name = if let Some(versioned) = name.strip_prefix('v') {
        let Some((version, name)) = versioned.split_once('_') else {
            return false;
        };
        if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        name
    } else {
        name
    };
    name == "CODEX_AUTH_ACCESS_TOKEN"
}
fn invalid() -> Error {
    Error::Authentication { message: "Invalid authentication: verify the OpenShell provider and host Codex routing identifier".into() }
}
pub fn account_id(value: &str) -> Result<String> {
    let compact = value.strip_prefix("urn:uuid:").unwrap_or(value);
    let compact = compact
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(compact);
    let hex: String = compact.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
        || !(compact.len() == 32
            || (compact.len() == 36
                && [8, 13, 18, 23]
                    .into_iter()
                    .all(|i| compact.as_bytes()[i] == b'-')))
    {
        return Err(invalid());
    }
    let hex = hex.to_ascii_lowercase();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
/// Deserialize only the routing field; never return, forward or diagnose host credentials.
pub fn host_account(path: &Path) -> Result<String> {
    #[derive(Deserialize)]
    struct Host {
        tokens: Tokens,
    }
    #[derive(Deserialize)]
    struct Tokens {
        account_id: String,
    }
    let bytes = files::read_limited(path, 1024 * 1024).map_err(|_| invalid())?;
    let host: Host = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    account_id(&host.tokens.account_id)
}
pub fn remote_prepare() -> Result<()> {
    let reference = std::env::var("CODEX_AUTH_ACCESS_TOKEN").map_err(|_| invalid())?;
    let account = std::env::var("CODEX_ACCOUNT_ID").map_err(|_| invalid())?;
    let home = std::env::var_os("CODEX_HOME").ok_or_else(invalid)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs();
    prepare(Path::new(&home), &reference, &account, now)
}
pub fn prepare(home: &Path, reference: &str, account: &str, now: u64) -> Result<()> {
    if !is_reference(reference) {
        return Err(invalid());
    }
    let account = account_id(account)?;
    let expiration = now.checked_add(3600).ok_or_else(invalid)?;
    let timestamp: libc::time_t = now.try_into().map_err(|_| invalid())?;
    let mut calendar = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers refer to live, correctly aligned storage.
    if unsafe { libc::gmtime_r(&timestamp, calendar.as_mut_ptr()) }.is_null() {
        return Err(invalid());
    }
    // SAFETY: gmtime_r succeeded and initialized the entire tm value.
    let calendar = unsafe { calendar.assume_init() };
    let refreshed = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        calendar.tm_year + 1900,
        calendar.tm_mon + 1,
        calendar.tm_mday,
        calendar.tm_hour,
        calendar.tm_min,
        calendar.tm_sec
    );
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg":"none","typ":"JWT"}))?);
    let payload=URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"iss":"https://auth.openai.com","aud":"codex","sub":"openshell-lab","email":"lab@openshell.invalid","iat":now,"exp":expiration}))?);
    let data = json!({"auth_mode":"chatgptAuthTokens","OPENAI_API_KEY":null,"tokens":{"id_token":format!("{header}.{payload}.placeholder"),"access_token":reference,"refresh_token":"","account_id":account},"last_refresh":refreshed});
    state::create_directory(home)?;
    let directory = files::open_directory(home)?;
    let anchored = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    match std::fs::symlink_metadata(anchored.join("auth.json")) {
        Ok(meta) if !meta.is_file() => return Err(invalid()),
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".auth-")
        .tempfile_in(&anchored)?;
    temp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temp.write_all(&serde_json::to_vec(&data)?)?;
    temp.as_file().sync_all()?;
    let name = temp.path().file_name().ok_or_else(invalid)?;
    use std::os::unix::ffi::OsStrExt;
    let source = CString::new(name.as_bytes())?;
    let destination = c"auth.json";
    // SAFETY: names are NUL terminated; directory owns the fd for both relative paths.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            destination.as_ptr(),
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.sync_all()?;
    Ok(())
}
