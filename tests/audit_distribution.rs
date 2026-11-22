use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

#[test]
fn distribution_matches_its_locked_resource_hashes() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest: Value = serde_json::from_slice(&fs::read(
        root.join("crates/ladyshell/resources/audit/provenance.json"),
    )?)?;
    for (path, expected) in manifest["distribution_files"]
        .as_object()
        .ok_or("resource map")?
    {
        let bytes = fs::read(root.join(path))?;
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            expected.as_str().ok_or("hash")?,
            "{path}"
        );
    }
    for entry in manifest["files"].as_array().ok_or("provenance files")? {
        let path = entry["path"].as_str().ok_or("path")?;
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(root.join(path))?)),
            entry["sha256"].as_str().ok_or("hash")?,
            "{path}"
        );
    }
    Ok(())
}
