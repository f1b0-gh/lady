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
        .ok_or_else(|| invalid("A Codex Nix path is required".into()))?;
    let (hash, name) = suffix
        .split_once('-')
        .ok_or_else(|| invalid("Invalid Nix identity".into()))?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && ["ladyshell-codex", "lab-codex"].contains(&name),
        "An exact Codex Nix path is required"
    );
    Ok(
        json!({"version":1,"landlock":{"compatibility":"hard_requirement"},"process":{"run_as_user":"sandbox","run_as_group":"sandbox"},"filesystem_policy":{"include_workdir":false,"read_only":READ_ONLY,"read_write":READ_WRITE},"network_policies":{"openai_codex":{"endpoints":HOSTS.iter().map(|host|json!({"host":host,"port":443,"protocol":"rest","enforcement":"enforce","access":"full"})).collect::<Vec<_>>(),"binaries":[{"path":binary}]}}}),
    )
}
fn strings(value: &Value) -> Result<BTreeSet<&str>> {
    value
        .as_array()
        .ok_or_else(|| invalid("A list of paths is required".into()))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| invalid("Path must be a string".into()))
        })
        .collect()
}
pub fn validate_effective(actual: &Value, binary: &str) -> Result<()> {
    let expected = native_policy(binary)?;
    for field in ["version", "landlock", "process"] {
        ensure!(
            actual.get(field) == expected.get(field),
            "Policy mismatch: {field}"
        );
    }
    let filesystem = &actual["filesystem_policy"];
    ensure!(
        filesystem["include_workdir"] == false,
        "include_workdir must remain false"
    );
    ensure!(
        strings(&filesystem["read_write"])?
            == strings(&expected["filesystem_policy"]["read_write"])?,
        "Write access mismatch"
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
        "Read access mismatch"
    );
    ensure!(
        actual.get("network_middlewares").is_none_or(|v| v.is_null()
            || v.as_object().is_some_and(|m| m.is_empty())
            || v.as_array().is_some_and(|a| a.is_empty())),
        "Unauthorized network middleware"
    );
    let rules = actual["network_policies"]
        .as_object()
        .ok_or_else(|| invalid("Missing network rules".into()))?;
    ensure!(rules.contains_key("openai_codex"), "Missing Codex rule");
    for rule in rules.values() {
        let binaries = rule["binaries"]
            .as_array()
            .ok_or_else(|| invalid("Missing network identity".into()))?;
        ensure!(!binaries.is_empty(), "Missing network identity");
        for value in binaries {
            ensure!(
                *value == json!({"path":binary})
                    || *value == json!({"path":"/usr/local/bin/codex"}),
                "Unauthorized network binary"
            );
        }
        let endpoints = rule["endpoints"]
            .as_array()
            .ok_or_else(|| invalid("Missing endpoints".into()))?;
        ensure!(!endpoints.is_empty(), "Missing endpoints");
        for endpoint in endpoints {
            ensure!(
                endpoint["host"]
                    .as_str()
                    .is_some_and(|s| HOSTS.contains(&s))
                    && endpoint["port"] == 443
                    && endpoint["protocol"] == "rest"
                    && endpoint["enforcement"] == "enforce",
                "Unauthorized endpoint"
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

/// Closed network policy for the fixed WASI broker. Only the three separately
/// capped storage roots and /dev/null are writable; components get no ambient I/O.
pub fn broker_policy() -> Value {
    json!({"version":1,"landlock":{"compatibility":"hard_requirement"},
        "process":{"run_as_user":"sandbox","run_as_group":"sandbox"},
        "filesystem_policy":{"include_workdir":false,"read_only":READ_ONLY,
            "read_write":["/dev/null", "/var/lib/ladyshell/broker/control",
                "/var/lib/ladyshell/broker/artifacts", "/var/lib/ladyshell/broker/incoming"]},
        "network_policies":{}})
}

pub fn validate_broker_effective(actual: &Value) -> Result<()> {
    let expected = broker_policy();
    for field in ["version", "landlock", "process"] {
        ensure!(
            actual.get(field) == expected.get(field),
            "Broker policy mismatch: {field}"
        );
    }
    // OpenShell 0.1.4 omits empty BTreeMap fields in effective-policy JSON.
    // An omitted map and an explicitly empty map both contain no allow rules.
    ensure!(
        actual
            .get("network_policies")
            .is_none_or(|v| v.as_object().is_some_and(|m| m.is_empty())),
        "Broker network rules must be empty"
    );
    let filesystem = &actual["filesystem_policy"];
    ensure!(
        filesystem["include_workdir"] == false
            && strings(&filesystem["read_write"])?
                == strings(&expected["filesystem_policy"]["read_write"])?,
        "Broker writable scope mismatch"
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
        "Broker readable scope mismatch"
    );
    ensure!(
        actual.get("network_middlewares").is_none_or(|v| v.is_null()
            || v.as_object().is_some_and(|m| m.is_empty())
            || v.as_array().is_some_and(|a| a.is_empty())),
        "Unauthorized broker network middleware"
    );
    Ok(())
}
