use ladyshell::image::archive_image_id;
#[test]
fn image_digest_comes_from_config_and_rejects_external_manifest_paths(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fn archive(
        path: &std::path::Path,
        config_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut archive = tar::Builder::new(std::fs::File::create(path)?);
        for (name, data) in [
            ("config.json", b"{}".to_vec()),
            (
                "manifest.json",
                serde_json::to_vec(&serde_json::json!([{"Config":config_name}]))?,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, name, &data[..])?;
        }
        archive.finish()?;
        Ok(())
    }
    let path = dir.path().join("image.tar");
    archive(&path, "config.json")?;
    assert_eq!(
        archive_image_id(&path)?,
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    archive(&path, "../escape")?;
    assert!(archive_image_id(&path).is_err());
    Ok(())
}
#[test]
fn rust_and_cargo_versions_require_exact_release() {
    use ladyshell::image::tool_version_matches;
    assert!(tool_version_matches(
        "rustc",
        "rustc 1.98.1 (abcdef 2026-10-01)",
        "1.98.1"
    ));
    assert!(tool_version_matches(
        "cargo",
        "cargo 1.98.1 (abcdef 2026-10-01)",
        "1.98.1"
    ));
    assert!(!tool_version_matches(
        "rustc",
        "rustc 1.98.10 (abcdef)",
        "1.98.1"
    ));
    assert!(!tool_version_matches(
        "rustc",
        "rustc 1.98.1-nightly (abcdef)",
        "1.98.1"
    ));
    assert!(!tool_version_matches(
        "cargo",
        "rustc 1.98.1 (abcdef)",
        "1.98.1"
    ));
    assert!(tool_version_matches("node", "v24.21.0\n", "24.21.0"));
    assert!(tool_version_matches("zig", "0.17.0\n", "0.17.0"));
}

#[test]
fn native_build_tools_require_exact_release_tokens() {
    use ladyshell::image::tool_version_matches;
    for (name, output, version) in [
        ("cmake", "cmake version 4.4.3\n\nCMake suite", "4.4.3"),
        ("make", "GNU Make 4.4.1\nBuilt for x86_64", "4.4.1"),
        (
            "openssl",
            "OpenSSL 3.5.8 1 Oct 2026 (Library: OpenSSL 3.5.8)",
            "3.5.8",
        ),
        ("maturin", "maturin 1.15.0", "1.15.0"),
        ("uv", "uv 0.13.0", "0.13.0"),
    ] {
        assert!(tool_version_matches(name, output, version), "{name}");
        assert!(!tool_version_matches(name, output, &format!("{version}0")));
        assert!(!tool_version_matches(
            name,
            &output.replace(version, &format!("{version}-dev")),
            version
        ));
    }
}
