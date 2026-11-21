use ladyboot::{
    artifact::{explain, ArtifactRequest},
    profile::differences,
};
use std::path::Path;

#[test]
fn resolved_plan_explains_versions_services_and_optional_needs(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = explain(
        &ArtifactRequest {
            config: root.join("profiles/base.ncl"),
            resources: root.to_owned(),
        },
        None,
    )?;
    let vm = explain(
        &ArtifactRequest {
            config: root.join("profiles/network-vm.ncl"),
            resources: root.to_owned(),
        },
        None,
    )?;
    let packages = base["planned"]["runtime_packages"]
        .as_array()
        .ok_or("missing packages")?;
    assert!(packages
        .iter()
        .all(|p| !p["version"].as_str().unwrap_or("").is_empty()
            && !p["origins"].as_array().is_none_or(|a| a.is_empty())));
    assert!(!packages
        .iter()
        .any(|p| p["selection"] == "qemu-agent" || p["selection"] == "python3-minimal"));
    let services = base["planned"]["enabled_services"]
        .as_array()
        .ok_or("services")?;
    assert!(services
        .iter()
        .any(|s| s["name"] == "systemd-journald.service" && s["origin"] == "bootc-base"));
    assert!(!services
        .iter()
        .any(|s| s["name"] == "systemd-networkd.service"));
    assert!(base["planned"]["vendor_unit_links"]
        .as_array()
        .is_some_and(|a| !a.is_empty()));
    assert!(!base["planned"]["build_tools"]
        .as_array()
        .ok_or("tools")?
        .iter()
        .any(|t| t["nix_name"] == "nix"));
    assert!(base["observed"].is_null());
    assert!(base["planned"]["measurements"]["image_bytes"].is_null());
    let delta = differences(&base["planned"], &vm["planned"]);
    assert_eq!(delta["equal"], false);
    assert!(delta["changes"]
        .as_array()
        .ok_or("changes")?
        .iter()
        .any(|r| r["path"] == "/enabled_services"));
    assert_eq!(differences(&base, &base)["equal"], true);
    Ok(())
}
