use ladybom::deps::vuln::{
    osv::{index_keys, match_record, normalize_package, validate_record, validate_snapshot},
    MatchStatus, Snapshot,
};
use serde_json::{json, Value};

fn advisory(ecosystem: &str, name: &str, ranges: Value) -> Value {
    json!({
        "id": "OSV-TEST-1", "modified": "2026-10-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": ecosystem, "name": name}, "ranges": ranges}]
    })
}

fn range(kind: &str, events: Value) -> Value {
    json!([{"type": kind, "events": events}])
}

#[test]
fn semver_bounds_include_prereleases_and_ignore_build_metadata() -> ladybom::error::Result<()> {
    let record = advisory(
        "crates.io",
        "demo",
        range(
            "SEMVER",
            json!([
                {"introduced": "1.0.0-alpha.1"}, {"fixed": "1.0.0"}
            ]),
        ),
    );
    for (version, expected) in [
        ("0.9.9", None),
        ("1.0.0-alpha.1", Some(MatchStatus::Matched)),
        ("1.0.0-rc.1+local", Some(MatchStatus::Matched)),
        ("1.0.0+build", None),
    ] {
        let result = match_record(&record, "crates.io", "demo", version)?;
        assert_eq!(result.status, expected, "{version}");
        assert_eq!(result.fixed_versions, ["1.0.0"]);
    }
    Ok(())
}

#[test]
fn unordered_events_multiple_intervals_and_limits_follow_osv_timeline() -> ladybom::error::Result<()>
{
    let record = advisory(
        "npm",
        "demo",
        range(
            "ECOSYSTEM",
            json!([
                {"fixed": "4.0.0"}, {"introduced": "3.0.0"},
                {"limit": "3.5.0"}, {"introduced": "0"}, {"fixed": "2.0.0"},
                {"limit": "3.8.0"}
            ]),
        ),
    );
    validate_record(&record)?;
    for (version, expected) in [
        ("0.0.0-alpha", Some(MatchStatus::Matched)),
        ("2.0.0", None),
        ("2.5.0", None),
        ("3.5.0", Some(MatchStatus::Matched)),
        ("3.8.0", None),
        ("4.0.0", None),
    ] {
        assert_eq!(
            match_record(&record, "npm", "demo", version)?.status,
            expected,
            "{version}"
        );
    }
    Ok(())
}

#[test]
fn last_affected_is_inclusive_open_ranges_and_infinite_limits_are_supported(
) -> ladybom::error::Result<()> {
    let record = advisory(
        "crates.io",
        "demo",
        range(
            "SEMVER",
            json!([
                {"introduced": "0"}, {"last_affected": "1.0.0"}, {"limit": "*"}
            ]),
        ),
    );
    assert_eq!(
        match_record(&record, "crates.io", "demo", "1.0.0")?.status,
        Some(MatchStatus::Matched)
    );
    assert_eq!(
        match_record(&record, "crates.io", "demo", "1.0.1")?.status,
        None
    );
    let open = advisory(
        "npm",
        "demo",
        range("SEMVER", json!([{"introduced": "2.0.0"}])),
    );
    assert_eq!(
        match_record(&open, "npm", "demo", "99.0.0")?.status,
        Some(MatchStatus::Matched)
    );
    Ok(())
}

#[test]
fn pypi_normalizes_names_and_compares_pep440_epochs_pre_dev_post_releases(
) -> ladybom::error::Result<()> {
    let record = advisory(
        "PyPI",
        "Demo_Package..Name",
        range(
            "ECOSYSTEM",
            json!([
                {"introduced": "1!2.0.dev1"}, {"fixed": "1!2.0.post1"}
            ]),
        ),
    );
    assert_eq!(
        normalize_package("PyPI", "Demo_Package..Name"),
        "demo-package-name"
    );
    assert_eq!(
        index_keys(&record),
        [("PyPI".into(), "demo-package-name".into())]
    );
    for (version, expected) in [
        ("2.0", None),
        ("1!2.0.dev0", None),
        ("1!2.0rc1", Some(MatchStatus::Matched)),
        ("1!2.0.0", Some(MatchStatus::Matched)),
        ("1!2.0.post1", None),
    ] {
        assert_eq!(
            match_record(&record, "PyPI", "demo-package-name", version)?.status,
            expected,
            "{version}"
        );
    }
    Ok(())
}

#[test]
fn explicit_versions_union_with_ranges_and_use_ecosystem_equality() -> ladybom::error::Result<()> {
    let mut record = advisory(
        "PyPI",
        "demo",
        range(
            "ECOSYSTEM",
            json!([
                {"introduced": "2.0"}, {"fixed": "3.0"}
            ]),
        ),
    );
    record["affected"][0]["versions"] = json!(["1.0"]);
    assert_eq!(
        match_record(&record, "PyPI", "demo", "1.0.0")?.status,
        Some(MatchStatus::Matched)
    );
    assert_eq!(match_record(&record, "PyPI", "demo", "1.5")?.status, None);
    assert_eq!(
        match_record(&record, "PyPI", "demo", "2.5")?.status,
        Some(MatchStatus::Matched)
    );
    Ok(())
}

#[test]
fn unsupported_ranges_remain_unknown_even_when_explicit_versions_do_not_match(
) -> ladybom::error::Result<()> {
    let mut record = advisory(
        "npm",
        "demo",
        json!([{
            "type": "GIT", "repo": "https://example.invalid/demo", "events": [{"introduced": "0"}]
        }]),
    );
    record["affected"][0]["versions"] = json!(["1.0.0"]);
    let missing = match_record(&record, "npm", "demo", "2.0.0")?;
    assert_eq!(missing.status, Some(MatchStatus::Unknown));
    assert!(!missing.limitations.is_empty());
    let matched = match_record(&record, "npm", "demo", "1.0.0")?;
    assert_eq!(matched.status, Some(MatchStatus::Matched));
    assert!(!matched.limitations.is_empty());
    Ok(())
}

#[test]
fn unsupported_versions_and_missing_affected_information_are_unknown() -> ladybom::error::Result<()>
{
    let record = advisory("npm", "demo", range("SEMVER", json!([{"introduced": "0"}])));
    assert_eq!(
        match_record(&record, "npm", "demo", "banana")?.status,
        Some(MatchStatus::Unknown)
    );
    let empty = advisory("npm", "demo", json!([]));
    assert_eq!(
        match_record(&empty, "npm", "demo", "1.0.0")?.status,
        Some(MatchStatus::Unknown)
    );
    let unparseable = advisory(
        "npm",
        "demo",
        range("ECOSYSTEM", json!([{"introduced": "release-old"}])),
    );
    assert_eq!(
        match_record(&unparseable, "npm", "demo", "1.0.0")?.status,
        Some(MatchStatus::Unknown)
    );
    Ok(())
}

#[test]
fn withdrawn_and_other_names_do_not_match_and_only_fixed_events_are_candidates(
) -> ladybom::error::Result<()> {
    let mut record = advisory(
        "crates.io",
        "Demo",
        json!([
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "3.0.0"}]}
        ]),
    );
    assert_eq!(
        match_record(&record, "crates.io", "demo", "0.5.0")?.status,
        None
    );
    let result = match_record(&record, "crates.io", "Demo", "0.5.0")?;
    assert_eq!(result.fixed_versions, ["1.0.0"]);
    record["withdrawn"] = json!("2026-09-30T00:00:00Z");
    assert_eq!(
        match_record(&record, "crates.io", "Demo", "0.5.0")?.status,
        None
    );
    Ok(())
}

#[test]
fn purl_conflicts_and_private_registry_qualifiers_do_not_create_false_certainty(
) -> ladybom::error::Result<()> {
    let mut record = advisory("npm", "demo", range("SEMVER", json!([{"introduced": "0"}])));
    record["affected"][0]["package"]["purl"] = json!("pkg:npm/other");
    assert_eq!(
        match_record(&record, "npm", "demo", "1.0.0")?.status,
        Some(MatchStatus::Unknown)
    );
    assert_eq!(
        match_record(&record, "npm", "other", "1.0.0")?.status,
        Some(MatchStatus::Unknown)
    );
    assert!(index_keys(&record).contains(&("npm".into(), "other".into())));
    record["affected"][0]["package"]["purl"] =
        json!("pkg:npm/demo?repository_url=https%3A%2F%2Fprivate.invalid");
    assert_eq!(
        match_record(&record, "npm", "demo", "1.0.0")?.status,
        Some(MatchStatus::Unknown)
    );
    record["affected"][0]["package"]["purl"] = json!("pkg:npm/demo");
    assert_eq!(
        match_record(&record, "npm", "demo", "1.0.0")?.status,
        Some(MatchStatus::Matched)
    );
    Ok(())
}

#[test]
fn wildcard_packages_apply_to_every_name_in_the_declared_ecosystem() -> ladybom::error::Result<()> {
    let record = advisory(
        "npm",
        "*",
        range("SEMVER", json!([{"introduced": "0"}, {"fixed": "2.0.0"}])),
    );
    assert_eq!(index_keys(&record), [("npm".into(), "*".into())]);
    assert_eq!(
        match_record(&record, "npm", "@scope/anything", "1.0.0")?.status,
        Some(MatchStatus::Matched)
    );
    assert_eq!(
        match_record(&record, "npm", "@scope/anything", "2.0.0")?.status,
        None
    );
    assert_eq!(
        match_record(&record, "crates.io", "anything", "1.0.0")?.status,
        None
    );
    Ok(())
}

#[test]
fn fixed_candidates_are_unique_and_do_not_include_unrelated_packages_or_limits(
) -> ladybom::error::Result<()> {
    let mut record = advisory(
        "npm",
        "demo",
        json!([
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]},
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "9.0.0"}]}
        ]),
    );
    record["affected"]
        .as_array_mut()
        .ok_or_else(|| std::io::Error::other("fixture"))?
        .push(json!({
            "package": {"ecosystem": "npm", "name": "other"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.0.0"}]}]
        }));
    assert_eq!(
        match_record(&record, "npm", "demo", "0.5.0")?.fixed_versions,
        ["1.0.0", "2.0.0"]
    );
    Ok(())
}

#[test]
fn malformed_event_shapes_and_conflicting_range_bound_types_are_rejected(
) -> ladybom::error::Result<()> {
    for events in [
        json!([]),
        json!([{"fixed": "1.0.0"}]),
        json!([{"introduced": "0", "fixed": "1.0.0"}]),
        json!([{"introduced": 0}]),
        json!([{"introduced": ""}]),
        json!([{"introduced": "0"}, {"fixed": "1.0.0"}, {"last_affected": "2.0.0"}]),
    ] {
        assert!(
            validate_record(&advisory("npm", "demo", range("SEMVER", events.clone()))).is_err(),
            "{events}"
        );
    }
    Ok(())
}

#[test]
fn required_typed_fields_safe_identifiers_and_timestamp_formats_are_checked(
) -> ladybom::error::Result<()> {
    for patch in [
        json!({"id": "../unsafe"}),
        json!({"id": ""}),
        json!({"modified": "yesterday"}),
        json!({"aliases": ["safe", "bad/alias"]}),
        json!({"affected": {}}),
        json!({"summary": false}),
        json!({"severity": [{"type": "CVSS_V3", "score": 3}]}),
        json!({"references": [{"type": "WEB", "url": false}]}),
        json!({"published": "tomorrow"}),
        json!({"published": false}),
        json!({"withdrawn": "yesterday"}),
        json!({"schema_version": "2.0.0"}),
    ] {
        let mut record = advisory("npm", "demo", json!([]));
        let entries: serde_json::Map<String, Value> = serde_json::from_value(patch.clone())?;
        for (key, value) in entries {
            record[&key] = value;
        }
        assert!(validate_record(&record).is_err(), "{patch}");
    }
    let mut future_minor = advisory("npm", "demo", json!([]));
    future_minor["schema_version"] = json!("1.99.0");
    future_minor["future_field"] = json!({"kept": true});
    validate_record(&future_minor)?;
    Ok(())
}

#[test]
fn nested_collections_are_bounded() -> ladybom::error::Result<()> {
    let mut record = advisory("npm", "demo", json!([]));
    record["database_specific"] = json!({"future": vec![0; 10_001]});
    assert!(validate_record(&record).is_err());
    Ok(())
}

#[test]
fn input_byte_and_record_count_limits_are_enforced() -> ladybom::error::Result<()> {
    let mut record = advisory("npm", "demo", json!([]));
    record["details"] = Value::String("x".repeat(ladybom::deps::vuln::MAX_INPUT_BYTES));
    assert!(validate_record(&record).is_err());
    drop(record);
    let mut value = snapshot();
    value.advisories = vec![Value::Null; ladybom::deps::vuln::MAX_RECORDS + 1];
    assert!(validate_snapshot(&value).is_err());
    Ok(())
}

fn snapshot() -> Snapshot {
    Snapshot {
        schema_version: 1,
        source: "synthetic fixtures".into(),
        fetched_at: "2026-10-01T00:00:00Z".into(),
        complete: false,
        ecosystems: vec!["npm".into()],
        advisories: vec![],
    }
}

#[test]
fn snapshots_allow_incomplete_empty_evidence_but_reject_invalid_provenance_and_duplicates(
) -> ladybom::error::Result<()> {
    validate_snapshot(&snapshot())?;
    for ecosystems in [vec![], vec!["unknown"], vec!["npm", "npm"]] {
        let mut value = snapshot();
        value.ecosystems = ecosystems.iter().map(|v| (*v).into()).collect();
        assert!(validate_snapshot(&value).is_err());
    }
    let mut value = snapshot();
    value.source = " ".into();
    assert!(validate_snapshot(&value).is_err());
    value = snapshot();
    value.fetched_at = "bad".into();
    assert!(validate_snapshot(&value).is_err());
    value = snapshot();
    let record = advisory("npm", "demo", json!([]));
    value.advisories = vec![record.clone(), record];
    assert!(validate_snapshot(&value).is_err());
    Ok(())
}

#[test]
fn snapshot_cannot_claim_to_have_fetched_records_before_their_last_modification(
) -> ladybom::error::Result<()> {
    let mut value = snapshot();
    let mut record = advisory("npm", "demo", json!([]));
    record["modified"] = json!("2026-10-01T00:00:00.001Z");
    value.advisories = vec![record];
    assert!(validate_snapshot(&value).is_err());
    value.fetched_at = "2026-10-01T00:00:00.001Z".into();
    validate_snapshot(&value)?;
    Ok(())
}
