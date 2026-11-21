use ladyboot::profile::validate;
use serde_json::{json, Value};

fn profile() -> Value {
    json!({
        "schema_version": 1, "architecture": "x86_64-linux",
        "os_id": "bootc-podman", "revision": "1",
        "needs": ["bootc-base", "virtio-vm", "podman-rootless", "network-runtime"],
        "podman": {"user": "containers", "uid": 1000, "gid": 1000,
            "subuid_start": 65536, "subgid_start": 65536, "range_size": 65536},
        "network": {"interface": "enp0s2", "dns": ["192.0.2.1"], "nts": [{"server": "nts.test", "address": "192.0.2.1"}],
            "egress": [{"address": "192.0.2.2", "protocol": "tcp", "port": 443}],
            "ingress": [{"address": "192.0.2.3", "protocol": "tcp", "port": 8080}]}
    })
}

#[test]
fn podman_profile_accepts_explicit_rootless_and_network() -> Result<(), Box<dyn std::error::Error>>
{
    assert!(validate(&profile()).is_ok());
    let mut offline = profile();
    offline["needs"] = json!(["bootc-base", "podman-rootless", "offline"]);
    offline
        .as_object_mut()
        .ok_or("test fixture shape")?
        .remove("network");
    assert!(validate(&offline).is_ok());
    Ok(())
}

#[test]
fn legacy_profiles_keep_their_contract() {
    for needs in [json!(["bootc-base"]), json!(["bootc-base", "network-dhcp"])] {
        assert!(
            validate(&json!({"schema_version": 1, "architecture": "x86_64-linux",
            "os_id": "test", "revision": "1", "needs": needs}))
            .is_ok()
        );
    }
}

#[test]
fn refuses_unknown_fields_and_conflicts() -> Result<(), Box<dyn std::error::Error>> {
    for pointer in ["/unknown", "/podman/password", "/network/fallback_dns"] {
        let mut p = profile();
        let (parent, key) = pointer.rsplit_once('/').ok_or("test fixture shape")?;
        p.pointer_mut(parent)
            .ok_or("test fixture shape")?
            .as_object_mut()
            .ok_or("test fixture shape")?
            .insert(key.into(), json!(true));
        assert!(validate(&p).is_err(), "accepted {pointer}");
    }
    for needs in [
        json!([
            "bootc-base",
            "podman-rootless",
            "network-runtime",
            "offline"
        ]),
        json!([
            "bootc-base",
            "podman-rootless",
            "network-runtime",
            "network-dhcp"
        ]),
        json!(["bootc-base", "network-runtime"]),
        json!(["bootc-base", "podman-rootless"]),
    ] {
        let mut p = profile();
        p["needs"] = needs;
        assert!(validate(&p).is_err());
    }
    for field in ["podman", "network"] {
        let mut p = profile();
        p.as_object_mut().ok_or("test fixture shape")?.remove(field);
        assert!(validate(&p).is_err());
        p[field] = Value::Null;
        assert!(validate(&p).is_err());
    }
    Ok(())
}

#[test]
fn refuses_overlapping_or_overflowing_ids() {
    for (key, value) in [
        ("uid", 0_u64),
        ("gid", 999),
        ("uid", 60001),
        ("subuid_start", 1000),
        ("subgid_start", 1000),
        ("subuid_start", u64::from(u32::MAX)),
        ("subgid_start", u64::from(u32::MAX) + 1),
        ("range_size", 0),
        ("range_size", 65537),
    ] {
        let mut p = profile();
        p["podman"][key] = json!(value);
        assert!(validate(&p).is_err(), "accepted {key}={value}");
    }
    for name in ["root", "../owner", "user\nroot", "-operator", "", "a:b"] {
        let mut p = profile();
        p["podman"]["user"] = json!(name);
        assert!(validate(&p).is_err(), "accepted username {name:?}");
    }
}

#[test]
fn refuses_unbounded_and_injected_network() {
    for name in [
        "en*",
        "lo",
        "../../device",
        "eth0\n[Network]",
        "abcdefghijklmnop",
        "",
    ] {
        let mut p = profile();
        p["network"]["interface"] = json!(name);
        assert!(validate(&p).is_err(), "accepted interface {name:?}");
    }
    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "192.0.2.1/0",
        "192.0.2.1; accept",
        "example.com",
        "192.000.2.1",
    ] {
        let mut p = profile();
        p["network"]["dns"] = json!([address]);
        assert!(validate(&p).is_err(), "accepted DNS address: {address}");
        let mut p = profile();
        p["network"]["egress"][0]["address"] = json!(address);
        assert!(validate(&p).is_err());
    }
    for field in ["dns", "nts", "egress", "ingress"] {
        let mut p = profile();
        p["network"][field] = json!(vec![p["network"][field][0].clone(); 65]);
        assert!(validate(&p).is_err(), "accepted oversized {field}");
    }
    for port in [0, 65536] {
        let mut p = profile();
        p["network"]["egress"][0]["port"] = json!(port);
        assert!(validate(&p).is_err());
    }
    let mut p = profile();
    p["network"]["egress"][0]["protocol"] = json!("tcp; accept");
    assert!(validate(&p).is_err());
}

#[test]
fn debug_profile_requires_rootless_runtime() {
    let mut p = profile();
    p["needs"] = json!([
        "bootc-base",
        "podman-rootless",
        "network-runtime",
        "podman-debug"
    ]);
    assert!(validate(&p).is_ok());
    p["needs"] = json!(["bootc-base", "network-runtime", "podman-debug"]);
    if let Some(object) = p.as_object_mut() {
        object.remove("podman");
    }
    assert!(validate(&p).is_err());
}
