use ladyshell::{config::Tool, deps, sources};
use std::{collections::BTreeMap, fs, path::Path};

fn fixture(
    config_name: &str,
    content: &str,
) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    fs::create_dir(root.path().join(".cargo"))?;
    fs::write(
        root.path().join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )?;
    fs::write(
        root.path().join("Cargo.lock"),
        "version=4\n[[package]]\nname='fixture'\nversion='0.1.0'\n",
    )?;
    fs::write(
        root.path().join("build.rs"),
        "compile_error!(\"project code must not run during planning\");\n",
    )?;
    fs::write(root.path().join(config_name), content)?;
    Ok(root)
}

fn snapshot(root: &Path) -> ladyshell::error::Result<sources::Snapshot> {
    sources::snapshot(root, &deps::project_sources(root)?, None)
}

fn plan(root: &Path, snapshot: &sources::Snapshot) -> ladyshell::error::Result<deps::Preparation> {
    deps::prepare::plan(
        root,
        snapshot,
        &deps::DependencyConfig {
            projects: vec!["Cargo.toml".into()],
            allowed_hosts: vec![],
        },
        &BTreeMap::from([(
            "rust".into(),
            Tool {
                version: "1.98.1".into(),
                phase: "runtime".into(),
            },
        )]),
    )
}

#[test]
fn alias_only_cargo_configuration_preserves_arguments_without_running_project_code(
) -> Result<(), Box<dyn std::error::Error>> {
    for name in [".cargo/config.toml", ".cargo/config"] {
        let root = fixture(
            name,
            r#"[alias]
proxy = ["build", "--package", "lo-proxy", "--package", "lo-proxy-*"]
gnap = ["build", "--package", "lo-gnap", "--package", "lo-gnap-*"]
check-all = "check --workspace --all-targets"
quoted = ["test", "--", "literal argument with spaces"]
"#,
        )?;
        let before = snapshot(root.path())?;
        let prepared = plan(root.path(), &before)?;
        assert_eq!(prepared.projects.len(), 1);
        assert_eq!(prepared.projects[0].manifest, "Cargo.toml");
        assert_eq!(prepared.inputs, before);
        assert_eq!(snapshot(root.path())?, before);
        assert!(!root.path().join("target").exists());
    }
    Ok(())
}

#[test]
fn cargo_configuration_rejects_every_non_alias_section() -> Result<(), Box<dyn std::error::Error>> {
    for content in [
        "[build]\nrustc='outside-rustc'\n",
        "[build]\nrustc-wrapper='outside-wrapper'\n",
        "[target.x86_64-unknown-linux-gnu]\nrunner='outside-runner'\n",
        "[net]\ngit-fetch-with-cli=true\n",
        "[http]\nproxy='https://unapproved.example'\n",
        "[source.crates-io]\nreplace-with='outside'\n[source.outside]\ndirectory='../outside'\n",
        "[env]\nRUSTC='outside-rustc'\n",
        "[registries.other]\nindex='https://unapproved.example'\n",
        "[future-section]\nunknown=true\n",
        "paths=['../outside']\n",
    ] {
        let root = fixture(
            ".cargo/config.toml",
            &format!("{content}\n[alias]\ncheck-all='check --workspace'\n"),
        )?;
        assert!(
            plan(root.path(), &snapshot(root.path())?).is_err(),
            "{content}"
        );
    }
    Ok(())
}

#[test]
fn cargo_aliases_reject_shell_commands_in_strings_and_array_heads(
) -> Result<(), Box<dyn std::error::Error>> {
    for value in [
        "'!touch SHELL_ALIAS_EXECUTED'",
        "'  !touch SHELL_ALIAS_EXECUTED'",
        "['!touch', 'SHELL_ALIAS_EXECUTED']",
        "['  !touch', 'SHELL_ALIAS_EXECUTED']",
    ] {
        let root = fixture(".cargo/config.toml", &format!("[alias]\nrun={value}\n"))?;
        assert!(
            plan(root.path(), &snapshot(root.path())?).is_err(),
            "{value}"
        );
        assert!(!root.path().join("SHELL_ALIAS_EXECUTED").exists());
    }
    Ok(())
}

#[test]
fn cargo_aliases_reject_malformed_empty_and_control_character_values(
) -> Result<(), Box<dyn std::error::Error>> {
    for content in [
        "",
        "[alias]",
        "alias='check'",
        "[alias]\nrun=1",
        "[alias]\nrun=true",
        "[alias]\nrun={command='check'}",
        "[alias]\nrun=[]",
        "[alias]\nrun=['check', 1]",
        "[alias]\nrun=''",
        "[alias]\nrun='  '",
        "[alias]\nrun=['']",
        "[alias]\nrun=['  ', 'check']",
        "[alias]\nrun=['check --workspace']",
        "[alias]\nrun=['check', '']",
        "[alias]\n''='check'",
        "[alias]\n'bad name'='check'",
        "[alias]\nrun=\"check\\n--workspace\"",
        "[alias]\nrun=['check', \"bad\\u0000argument\"]",
        "[alias]\nrun=['check', \"bad\\u007Fargument\"]",
        "[alias]\n\"bad\\tname\"='check'",
        "[alias\nrun='check'",
    ] {
        let root = fixture(".cargo/config.toml", content)?;
        assert!(
            plan(root.path(), &snapshot(root.path())?).is_err(),
            "{content}"
        );
    }
    Ok(())
}

#[test]
fn cargo_configuration_is_bounded_to_one_mib() -> Result<(), Box<dyn std::error::Error>> {
    let mut content = "[alias]\ncheck-all='check --workspace'\n#".to_string();
    content.push_str(&"x".repeat(1024 * 1024 - content.len()));
    let root = fixture(".cargo/config.toml", &content)?;
    assert!(plan(root.path(), &snapshot(root.path())?).is_ok());
    content.push('x');
    fs::write(root.path().join(".cargo/config.toml"), content)?;
    let error = plan(root.path(), &snapshot(root.path())?)
        .err()
        .ok_or("oversize config accepted")?;
    assert!(error.to_string().contains("File is too large"), "{error}");
    Ok(())
}

#[test]
fn cargo_configuration_must_still_match_the_selected_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = fixture(
        ".cargo/config.toml",
        "[alias]\ncheck-all='check --workspace'\n",
    )?;
    let before = snapshot(root.path())?;
    fs::write(
        root.path().join(".cargo/config.toml"),
        "[alias]\ncheck-all='check'\n",
    )?;
    assert!(plan(root.path(), &before).is_err());
    Ok(())
}

#[test]
fn cargo_configuration_rejects_symlinks_after_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    for directory_link in [false, true] {
        let content = "[alias]\ncheck-all='check --workspace'\n";
        let root = fixture(".cargo/config.toml", content)?;
        let outside = tempfile::tempdir()?;
        fs::write(outside.path().join("config.toml"), content)?;
        let before = snapshot(root.path())?;
        fs::remove_file(root.path().join(".cargo/config.toml"))?;
        if directory_link {
            fs::remove_dir(root.path().join(".cargo"))?;
            std::os::unix::fs::symlink(outside.path(), root.path().join(".cargo"))?;
        } else {
            std::os::unix::fs::symlink(
                outside.path().join("config.toml"),
                root.path().join(".cargo/config.toml"),
            )?;
        }
        assert!(plan(root.path(), &before).is_err());
    }
    Ok(())
}
