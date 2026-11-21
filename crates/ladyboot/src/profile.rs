//! Bounded public needs validation; package versions and dependency resolution belong to Nix.
use nickel_util::error::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Needs {
    schema_version: u32,
    architecture: String,
    os_id: String,
    revision: String,
    needs: Vec<String>,
    podman: Option<Podman>,
    network: Option<Network>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Podman {
    user: String,
    uid: u32,
    gid: u32,
    subuid_start: u32,
    subgid_start: u32,
    range_size: u32,
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct Flow {
    address: String,
    protocol: String,
    port: u16,
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct NtsSource {
    server: String,
    address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    interface: String,
    dns: Vec<String>,
    nts: Vec<NtsSource>,
    egress: Vec<Flow>,
    ingress: Vec<Flow>,
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.len() <= 64 && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn unicast(address: &str) -> bool {
    address.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
        let first = ip.octets()[0];
        first != 0 && first != 127 && first < 224
    })
}

fn server_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').count() >= 2
        && name
            .rsplit('.')
            .next()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_lowercase()))
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.starts_with(|c: char| c.is_ascii_alphanumeric())
                && label.ends_with(|c: char| c.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

impl Podman {
    fn valid(&self) -> bool {
        let range = |start: u32| {
            start >= 65536
                && self.range_size > 0
                && self.range_size <= 65536
                && start.checked_add(self.range_size).is_some()
        };
        !self.user.is_empty()
            && self.user.len() <= 32
            && self.user != "root"
            && self.user.starts_with(|c: char| c.is_ascii_lowercase())
            && self
                .user
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
            && (1000..=60000).contains(&self.uid)
            && (1000..=60000).contains(&self.gid)
            && range(self.subuid_start)
            && range(self.subgid_start)
    }
}

impl Network {
    fn valid(&self) -> bool {
        let addresses = |values: &[String]| {
            !values.is_empty() && unique(values) && values.iter().all(|v| unicast(v))
        };
        let flows = |values: &[Flow], minimum: u16| {
            unique(values)
                && values.iter().all(|v| {
                    unicast(&v.address)
                        && matches!(v.protocol.as_str(), "tcp" | "udp")
                        && v.port >= minimum
                })
        };
        !self.interface.is_empty()
            && self.interface.len() <= 15
            && self.interface != "lo"
            && self
                .interface
                .starts_with(|c: char| c.is_ascii_alphabetic())
            && self
                .interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            && addresses(&self.dns)
            && !self.nts.is_empty()
            && unique(&self.nts)
            && self
                .nts
                .iter()
                .all(|s| server_name(&s.server) && unicast(&s.address))
            && self
                .nts
                .iter()
                .map(|s| &s.server)
                .collect::<BTreeSet<_>>()
                .len()
                == self.nts.len()
            && self
                .nts
                .iter()
                .map(|s| &s.address)
                .collect::<BTreeSet<_>>()
                .len()
                == self.nts.len()
            && flows(&self.egress, 1)
            && self.egress.iter().all(|flow| {
                !matches!(
                    (flow.protocol.as_str(), flow.port),
                    ("udp", 123) | ("tcp", 4460)
                ) || self.nts.iter().any(|source| source.address == flow.address)
            })
            && flows(&self.ingress, 1024)
    }
}

pub fn validate(value: &Value) -> Result<()> {
    let request: Needs = serde_json::from_value(value.clone())?;
    let known = [
        "bootc-base",
        "virtio-vm",
        "qemu-agent",
        "network-dhcp",
        "diagnostics",
        "offline",
        "podman-rootless",
        "podman-debug",
        "network-runtime",
    ];
    let needs: BTreeSet<_> = request.needs.iter().map(String::as_str).collect();
    let has_podman = needs.contains("podman-rootless");
    let has_network = needs.contains("network-runtime");
    let valid = (!needs.contains("podman-debug") || has_podman)
        && has_podman == value.get("podman").is_some()
        && has_podman == request.podman.is_some()
        && has_network == value.get("network").is_some()
        && has_network == request.network.is_some()
        && request.podman.as_ref().is_none_or(Podman::valid)
        && request.network.as_ref().is_none_or(Network::valid)
        && (!has_network || request.podman.as_ref().is_none_or(|p| p.user != "ntpd-rs"))
        && !(has_network && (needs.contains("offline") || needs.contains("network-dhcp")))
        && request.schema_version == 1
        && request.architecture == "x86_64-linux"
        && !request.os_id.is_empty()
        && request.os_id.len() <= 32
        && request.os_id.starts_with(|c: char| c.is_ascii_lowercase())
        && request
            .os_id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && !request.revision.is_empty()
        && request.revision.len() <= 12
        && request.revision.bytes().all(|c| c.is_ascii_digit())
        && request.needs.len() <= 16
        && needs.len() == request.needs.len()
        && needs.iter().all(|need| known.contains(need))
        && needs.contains("bootc-base")
        && !(needs.contains("offline") && needs.contains("network-dhcp"))
        && (!needs.contains("qemu-agent") || needs.contains("virtio-vm"));
    if !valid {
        return Err(Error::InvalidInput {
            message: "Invalid bootc needs, rootless identity or explicit network policy".into(),
        });
    }
    Ok(())
}

/// Deterministic field-level comparison retains reasons and package versions.
pub fn differences(left: &Value, right: &Value) -> Value {
    fn visit(path: &str, a: Option<&Value>, b: Option<&Value>, changes: &mut Vec<Value>) {
        if a == b {
            return;
        }
        if let (Some(Value::Object(a)), Some(Value::Object(b))) = (a, b) {
            let keys: BTreeSet<_> = a.keys().chain(b.keys()).collect();
            for key in keys {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                visit(
                    &format!("{path}/{escaped}"),
                    a.get(key),
                    b.get(key),
                    changes,
                );
            }
        } else {
            changes.push(serde_json::json!({"path":path,"before":a,"after":b}));
        }
    }
    let mut changes = Vec::new();
    visit("", Some(left), Some(right), &mut changes);
    serde_json::json!({"schema_version":1,"changes":changes,"equal":changes.is_empty()})
}
