use ladyshell::config::Config;
use serde_json::json;
#[test]
fn optional_storage_survives_resolution_with_exact_validated_caps(
) -> Result<(), Box<dyn std::error::Error>> {
    let base = json!({"schema_version":1,"name":"fixture", "sources":{"include":[],"exclude":[]},
        "tools":{},"missions":{"dev":{"tools":[],"include":[],"depends_on":[],"checks":[]}},
        "sandbox":{"gateway":"g","workspace":"w","provider":"p"}});
    let old = serde_json::to_value(Config::from_value(base.clone())?.resolve("dev")?)?;
    assert!(old.get("storage").is_none());
    let profile = json!({"control":{"bytes":65536,"inodes":32},
        "artifacts":{"bytes":262144,"inodes":64},"incoming":{"bytes":262144,"inodes":64}});
    let mut selected = base;
    selected["storage"] = profile.clone();
    let resolved = serde_json::to_value(Config::from_value(selected.clone())?.resolve("dev")?)?;
    assert_eq!(resolved["storage"], profile);
    selected["storage"]["control"]["bytes"] = json!(65537);
    assert!(Config::from_value(selected.clone()).is_err());
    selected["storage"]["control"]["bytes"] = json!(65536);
    selected["storage"]["fallback"] = json!(true);
    assert!(Config::from_value(selected).is_err());
    Ok(())
}
