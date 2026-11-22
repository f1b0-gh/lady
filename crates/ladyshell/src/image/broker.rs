//! Fixed broker image construction from original source, recipe and ELF digests.
use super::{archive_image_id, invalid, load_archive, run};
use crate::{
    config::ResolvedConfig,
    environment_lock::{self, atomic_json},
    error::{ensure, Result},
    files, policy,
    process::capture,
    sources,
    state::text,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
    time::Duration,
};

pub(super) fn build(desired: &Value, directory: &Path, migration: Option<&Value>) -> Result<Value> {
    let config: ResolvedConfig = serde_json::from_value(desired["evaluated"]["config"].clone())?;
    config.validate_broker()?;
    ensure!(
        migration.is_none(),
        "Broker replacement requires a separate deployment; native source migration is unsupported"
    );
    crate::state::create_directory(directory)?;
    use std::os::unix::fs::PermissionsExt;
    let out = tempfile::Builder::new()
        .prefix("broker-build-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(directory)?
        .keep();
    let mut receipt = json!({"format":1,"desired_hash":crate::plan::digest(desired)?,
        "build_dir":out,"loaded":false,"validated":false});
    atomic_json(&out.join("broker-build.json"), &receipt)?;
    // Authenticate every named artifact before invoking Nix or the container daemon.
    for name in ["lo-executor-worker", "ladyshell"] {
        let record = desired["artifacts"]
            .get(name)
            .filter(|v| v.is_object())
            .ok_or_else(|| invalid(format!("Missing broker artifact: {name}")))?;
        let expected = text(record, "sha256")?;
        ensure!(
            desired["environment_lock"]["artifacts_sha256"][name] == expected,
            "Broker artifact does not match original environment lock: {name}"
        );
        let mut input =
            files::open_regular(Path::new(text(record, "path")?))?.take(1024 * 1024 * 1024 + 1);
        let target = out.join(name);
        let mut output = File::create(&target)?;
        let size = std::io::copy(&mut input, &mut output)?;
        ensure!(size <= 1024 * 1024 * 1024, "Artifact is too large");
        output.sync_all()?;
        drop(output);
        ensure!(
            environment_lock::artifact_hash(&target)? == expected,
            "Artifact changed since plan: {name}"
        );
    }
    let source = out.join("project");
    fs::create_dir(&source)?;
    let actual = sources::snapshot(
        Path::new(text(desired, "project")?),
        &config.sources,
        Some(&source),
    )?;
    ensure!(
        serde_json::to_value(&actual)? == desired["sources"],
        "Sources changed since plan"
    );
    // Nix reads only copied bytes authenticated by the original environment lock.
    let frozen = crate::continuous::native::freeze_resources(desired, &out.join("resources"))?;
    let nix = Path::new(text(&frozen, "resources")?).join("nix");
    atomic_json(&out.join("config.json"), &config)?;
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--impure",
            "--no-link",
            "--print-out-paths",
            "--file",
        ])
        .arg(nix.join("broker-build.nix"));
    for (name, value) in [
        ("flakePath", nix),
        ("configPath", out.join("config.json")),
        ("sourcePath", source.clone()),
        ("brokerPath", out.join("lo-executor-worker")),
        ("runtimePath", out.join("ladyshell")),
    ] {
        command.arg("--argstr").arg(name).arg(value);
    }
    let archive = String::from_utf8(capture(command, Duration::from_secs(900), 8 * 1024 * 1024)?)?;
    let archive = archive.trim();
    ensure!(
        archive.starts_with("/nix/store/") && !archive.contains('\n'),
        "Unexpected Nix output"
    );
    let image_id = archive_image_id(Path::new(archive))?;
    // Preserve the exact image identity before the external load can take effect.
    receipt["archive"] = json!(archive);
    receipt["image_id"] = json!(image_id);
    atomic_json(&out.join("broker-build.json"), &receipt)?;
    load_archive(archive, &image_id)?;
    receipt["loaded"] = json!(true);
    atomic_json(&out.join("broker-build.json"), &receipt)?;
    // Inspect immutable image metadata only. Runtime probes belong to the owned,
    // journalled OpenShell sandbox, so interrupted builds leave no probe process.
    let metadata: Value = crate::json::parse(
        run(
            &[
                "docker",
                "image",
                "inspect",
                &image_id,
                "--format",
                "{{json .}}",
            ],
            30,
        )?
        .as_bytes(),
    )?;
    ensure!(
        metadata["Id"] == image_id,
        "Image metadata identity changed"
    );
    let binary = metadata_binary(&metadata)?;
    let policy_path = out.join("policy.json");
    atomic_json(&policy_path, &policy::broker_policy())?;
    receipt["metadata_validated"] = json!(true);
    atomic_json(&out.join("broker-build.json"), &receipt)?;
    Ok(
        json!({"image_profile":"openshell-wasi","image_id":image_id,"archive":archive,
        "policy_path":policy_path,"build_dir":out,"project_snapshot":source,
        "host_sources":actual,"broker_binary":binary,"dependencies":null}),
    )
}
fn metadata_binary(metadata: &Value) -> Result<&str> {
    ensure!(
        metadata["Config"]["User"] == "10001:10001",
        "Incorrect broker image identity"
    );
    let labels = &metadata["Config"]["Labels"];
    ensure!(
        labels["ladyshell.image.profile"] == "openshell-wasi",
        "Incorrect image profile"
    );
    let binary = text(labels, "ladyshell.broker.binary")?;
    let suffix = binary
        .strip_prefix("/nix/store/")
        .and_then(|v| v.strip_suffix("-ladyshell-lo-executor/bin/lo-executor-worker"))
        .ok_or_else(|| invalid("Broker must resolve to its fixed Nix artifact".into()))?;
    ensure!(
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "Invalid broker Nix identity"
    );
    Ok(binary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_metadata_requires_closed_identity_and_fixed_broker_path() -> Result<()> {
        let binary = format!(
            "/nix/store/{}-ladyshell-lo-executor/bin/lo-executor-worker",
            "0".repeat(32)
        );
        let original = json!({"Config":{"User":"10001:10001", "Labels":{
            "ladyshell.image.profile":"openshell-wasi", "ladyshell.broker.binary":binary}}});
        assert_eq!(metadata_binary(&original)?, binary);
        for (key, value) in [("User", json!("0")), ("Labels", json!({}))] {
            let mut changed = original.clone();
            changed["Config"][key] = value;
            assert!(metadata_binary(&changed).is_err());
        }
        for path in [
            "/tmp/worker",
            "/nix/store/../lo-executor-worker",
            "/nix/store/000-ladyshell-lo-executor/bin/lo-executor-worker",
        ] {
            let mut changed = original.clone();
            changed["Config"]["Labels"]["ladyshell.broker.binary"] = json!(path);
            assert!(metadata_binary(&changed).is_err());
        }
        Ok(())
    }
}
