use ladyboot::profile::validate;
use serde_json::{json, Value};

fn profile() -> Value {
    json!({
        "schema_version": 1, "architecture": "x86_64-linux",
        "os_id": "bootc-podman", "revision": "1",
        "needs": ["bootc-base", "network-runtime"],
        "network": {
            "interface": "enp0s2", "dns": ["192.0.2.1"],
            "nts": [{"server": "nts.test", "address": "192.0.2.1"}],
            "egress": [], "ingress": []
        }
    })
}

#[test]
fn accepts_explicit_nts_sources_and_dns_boundaries() {
    for server in [
        "nts.test".to_owned(),
        "1-time.example.test".to_owned(),
        "a.b".to_owned(),
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        ),
    ] {
        let mut p = profile();
        p["network"]["nts"][0]["server"] = json!(server);
        assert!(validate(&p).is_ok(), "rejected valid source {server:?}");
    }
    let mut p = profile();
    p["network"]["nts"] = json!((1..=64)
        .map(|n| json!({"server": format!("time-{n}.test"), "address": format!("192.0.2.{n}")}))
        .collect::<Vec<_>>());
    assert!(
        validate(&p).is_ok(),
        "rejected exactly 64 distinct NTS sources"
    );
}

#[test]
fn rejects_legacy_ntp_and_unknown_nts_options() -> Result<(), Box<dyn std::error::Error>> {
    let mut legacy = profile();
    legacy["network"]
        .as_object_mut()
        .ok_or("test fixture shape")?
        .remove("nts");
    legacy["network"]["ntp"] = json!(["192.0.2.1"]);
    assert!(
        validate(&legacy).is_err(),
        "accepted unauthenticated legacy source"
    );
    for key in ["port", "fallback", "certificate", "nocerttimecheck"] {
        let mut p = profile();
        p["network"]["nts"][0][key] = json!(true);
        assert!(validate(&p).is_err(), "accepted extra NTS option {key}");
    }
    Ok(())
}

#[test]
fn rejects_nts_names_that_could_escape_identity_or_configuration() {
    for server in [
        "",
        "nts",
        "NTS.test",
        ".nts.test",
        "nts.test.",
        "nts..test",
        "-nts.test",
        "nts-.test",
        "nts_test.example",
        "*.test",
        "https://nts.test",
        "nts.test:4460",
        "nts.test\n[[source]]",
        "nts.test\"",
        "ntś.test",
        "192.0.2.1",
        "1.2",
        "1.0x0201",
        "::1",
        "nts.test/path",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        format!("{}.test", "a".repeat(64)),
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        ),
    ]) {
        let mut p = profile();
        p["network"]["nts"][0]["server"] = json!(server);
        assert!(
            validate(&p).is_err(),
            "accepted hostile NTS identity {server:?}"
        );
    }
}

#[test]
fn rejects_ambiguous_empty_and_unbounded_nts_endpoints() {
    for sources in [
        json!([]),
        json!([{"server": "nts.test", "address": "192.0.2.1"},
               {"server": "nts.test", "address": "192.0.2.2"}]),
        json!([{"server": "nts.test", "address": "192.0.2.1"},
               {"server": "other.test", "address": "192.0.2.1"}]),
        json!((1..=65)
            .map(|n| json!({"server": format!("time-{n}.test"),
                                    "address": format!("192.0.2.{n}")}))
            .collect::<Vec<_>>()),
    ] {
        let mut p = profile();
        p["network"]["nts"] = sources;
        assert!(validate(&p).is_err());
    }
    for address in [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.000.2.1",
        "192.0.2.1/24",
        "192.0.2.1; accept",
        "nts.test",
        "::1",
    ] {
        let mut p = profile();
        p["network"]["nts"][0]["address"] = json!(address);
        assert!(
            validate(&p).is_err(),
            "accepted invalid NTS endpoint {address:?}"
        );
    }
}

#[test]
fn reserves_nts_service_identity_only_when_composed() -> Result<(), Box<dyn std::error::Error>> {
    let mut p: Value = serde_json::from_str(include_str!("../profiles/podman-vm.json"))?;
    p["podman"]["user"] = json!("ntpd-rs");
    assert!(
        validate(&p).is_err(),
        "workload shares the time daemon identity"
    );
    p["needs"]
        .as_array_mut()
        .ok_or("test fixture needs shape")?
        .retain(|n| n != "network-runtime");
    p.as_object_mut()
        .ok_or("test fixture shape")?
        .remove("network");
    assert!(validate(&p).is_ok(), "reserved name without the service");
    Ok(())
}

#[test]
fn time_ports_cannot_escape_declared_nts_addresses() {
    for (protocol, port) in [("udp", 123), ("tcp", 4460)] {
        let mut p = profile();
        p["network"]["egress"] =
            json!([{"address":"192.0.2.42", "protocol":protocol, "port":port}]);
        assert!(
            validate(&p).is_err(),
            "time destination escaped through generic egress"
        );
        p["network"]["egress"][0]["address"] = json!("192.0.2.1");
        assert!(validate(&p).is_ok(), "declared endpoint rejected");
    }
    for (protocol, port) in [("tcp", 123), ("udp", 4460)] {
        let mut p = profile();
        p["network"]["egress"] =
            json!([{"address":"192.0.2.42", "protocol":protocol, "port":port}]);
        assert!(
            validate(&p).is_ok(),
            "unrelated application transport rejected"
        );
    }
}
