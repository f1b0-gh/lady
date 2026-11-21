use crate::{
    config::Permissions,
    error::{ensure, Error, Result},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
const READ_ONLY: &[&str] = &[
    "/nix/store",
    "/usr",
    "/bin",
    "/etc",
    "/proc",
    "/dev/urandom",
];
const READ_WRITE: &[&str] = &["/tmp", "/dev/null", "/sandbox/.codex", "/sandbox/workspace"];
const HOSTS: &[&str] = &["api.openai.com", "chatgpt.com", "auth.openai.com"];
pub fn native_policy(binary: &str) -> Result<Value> {
    let suffix = binary
        .strip_prefix("/nix/store/")
        .and_then(|s| s.strip_suffix("/bin/codex"))
        .ok_or_else(|| invalid("Chemin Codex Nix requis".into()))?;
    let (hash, name) = suffix
        .split_once('-')
        .ok_or_else(|| invalid("Identité Nix invalide".into()))?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && ["ladyshell-codex", "lab-codex"].contains(&name),
        "Chemin Codex Nix exact requis"
    );
    Ok(
        json!({"version":1,"landlock":{"compatibility":"hard_requirement"},"process":{"run_as_user":"sandbox","run_as_group":"sandbox"},"filesystem_policy":{"include_workdir":false,"read_only":READ_ONLY,"read_write":READ_WRITE},"network_policies":{"openai_codex":{"endpoints":HOSTS.iter().map(|host|json!({"host":host,"port":443,"protocol":"rest","enforcement":"enforce","access":"full"})).collect::<Vec<_>>(),"binaries":[{"path":binary}]}}}),
    )
}
fn strings(value: &Value) -> Result<BTreeSet<&str>> {
    value
        .as_array()
        .ok_or_else(|| invalid("Liste de chemins requise".into()))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| invalid("Chemin texte requis".into()))
        })
        .collect()
}
pub fn validate_effective(actual: &Value, binary: &str) -> Result<()> {
    let expected = native_policy(binary)?;
    for field in ["version", "landlock", "process"] {
        ensure!(
            actual.get(field) == expected.get(field),
            "Politique divergente : {field}"
        );
    }
    let filesystem = &actual["filesystem_policy"];
    ensure!(
        filesystem["include_workdir"] == false,
        "include_workdir doit rester false"
    );
    ensure!(
        strings(&filesystem["read_write"])?
            == strings(&expected["filesystem_policy"]["read_write"])?,
        "Accès écriture divergent"
    );
    let read = strings(&filesystem["read_only"])?;
    let required: BTreeSet<_> = READ_ONLY.iter().copied().collect();
    let allowed: BTreeSet<_> = READ_ONLY
        .iter()
        .copied()
        .chain(["/lib", "/var/log"])
        .collect();
    ensure!(
        required.is_subset(&read) && read.is_subset(&allowed),
        "Accès lecture divergent"
    );
    ensure!(
        actual.get("network_middlewares").is_none_or(|v| v.is_null()
            || v.as_object().is_some_and(|m| m.is_empty())
            || v.as_array().is_some_and(|a| a.is_empty())),
        "Middleware réseau non autorisé"
    );
    let rules = actual["network_policies"]
        .as_object()
        .ok_or_else(|| invalid("Règles réseau absentes".into()))?;
    ensure!(rules.contains_key("openai_codex"), "Règle Codex absente");
    for rule in rules.values() {
        let binaries = rule["binaries"]
            .as_array()
            .ok_or_else(|| invalid("Identité réseau absente".into()))?;
        ensure!(!binaries.is_empty(), "Identité réseau absente");
        for value in binaries {
            ensure!(
                *value == json!({"path":binary})
                    || *value == json!({"path":"/usr/local/bin/codex"}),
                "Binaire réseau non autorisé"
            );
        }
        let endpoints = rule["endpoints"]
            .as_array()
            .ok_or_else(|| invalid("Endpoints absents".into()))?;
        ensure!(!endpoints.is_empty(), "Endpoints absents");
        for endpoint in endpoints {
            ensure!(
                endpoint["host"]
                    .as_str()
                    .is_some_and(|s| HOSTS.contains(&s))
                    && endpoint["port"] == 443
                    && endpoint["protocol"] == "rest"
                    && endpoint["enforcement"] == "enforce",
                "Endpoint non autorisé"
            );
        }
    }
    Ok(())
}
pub fn review(requests: &Permissions) -> Vec<Value> {
    let mut results = Vec::new();
    for request in &requests.network {
        let authorized = request.tool == "codex"
            && HOSTS.contains(&request.host.as_str())
            && request.port == 443;
        results.push(json!({"kind":"network","request":request,"authorized":authorized}));
    }
    for request in &requests.filesystem {
        let allowed = if request.access == "read" {
            READ_ONLY
        } else {
            READ_WRITE
        };
        results.push(json!({"kind":"filesystem","request":request,"authorized":allowed.contains(&request.path.as_str())}));
    }
    results
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
