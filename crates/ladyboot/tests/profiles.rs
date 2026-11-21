use ladyboot::artifact::{check, ArtifactRequest};
use std::{fs, path::Path};

fn request(profile: &str) -> ArtifactRequest {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    ArtifactRequest {
        config: root.join("profiles").join(profile),
        resources: root.to_owned(),
    }
}

#[test]
fn baseline_is_a_fresh_bootc_needs_contract() -> Result<(), Box<dyn std::error::Error>> {
    let value = check(&request("base.ncl"))?.configuration;
    assert_eq!(value["needs"], serde_json::json!(["bootc-base"]));
    assert!(value.get("runtime").is_none());
    Ok(())
}

#[test]
fn unknown_conflicting_duplicate_and_implicit_needs_are_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("profile.ncl");
    let mut input = request("base.ncl");
    input.config = config.clone();
    for needs in [
        "[\"unknown\"]",
        "[\"bootc-base\", \"offline\", \"network-dhcp\"]",
        "[\"bootc-base\", \"bootc-base\"]",
        "[\"bootc-base\", \"qemu-agent\"]",
    ] {
        fs::write(
            &config,
            format!(
                r#"{{schema_version=1, architecture="x86_64-linux", os_id="test", revision="1", needs={needs}}}"#
            ),
        )?;
        assert!(check(&input).is_err(), "accepted {needs}");
    }
    Ok(())
}
