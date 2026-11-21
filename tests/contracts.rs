use ladyshell_cli::{cli::validate_args, config::resolve};
use serde_json::{json, Value};
fn config() -> Value {
    json!({"schema_version":1,"name":"example","sources":{"include":["src"],"exclude":[]},
      "tools":{"zig":{"version":"0.17.0"},"node":{"version":"24.21.0"}},
      "missions":{"dev":{"tools":["zig"],"include":[],"depends_on":[],"checks":[["zig","build"]]},
       "audit":{"tools":["node"],"include":["audit directory"],"depends_on":["dev"],"checks":[["node","--test"]]}},
      "sandbox":{"gateway":"openshell","workspace":"default","provider":"codex"}})
}
#[test]
fn cli_accepts_ten_commands_and_paths_with_spaces() -> Result<(), Box<dyn std::error::Error>> {
    for command in ["lock", "plan", "apply"] {
        validate_args(&[
            "ladyshell",
            command,
            "--config",
            "/a b/sandbox.ncl",
            "--project",
            "/a b",
            "--state",
            "/state dir",
            "--resources",
            "/resources",
            "--codex",
            "/bin/codex",
            "--codex-code-mode-host",
            "/bin/host",
        ])?;
    }
    for command in [
        "shell", "chat", "resume", "status", "check", "sync", "destroy",
    ] {
        validate_args(&["ladyshell", command, "--state", "/state dir"])?;
    }
    Ok(())
}
#[test]
fn cli_rejects_unknown_options_missing_inputs_and_unsafe_flag_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    for args in [
        vec!["ladyshell", "plan", "--state", "/s"],
        vec!["ladyshell", "sync", "--state", "/s", "--discard-work"],
        vec!["ladyshell", "shell", "--state", "/s", "--oops"],
        vec!["ladyshell", "destroy"],
    ] {
        assert!(validate_args(&args).is_err(), "{args:?}");
    }
    Ok(())
}
#[test]
fn resolves_parent_checks_and_tool_union_without_duplicate_parents(
) -> Result<(), Box<dyn std::error::Error>> {
    let value = resolve(config(), "audit")?;
    assert_eq!(value["resolved_missions"], json!(["dev", "audit"]));
    assert_eq!(
        value["checks"],
        json!([["zig", "build"], ["node", "--test"]])
    );
    assert_eq!(
        value["sources"]["include"],
        json!(["audit directory", "src"])
    );
    assert_eq!(
        value["tools"]["zig"],
        json!({"version":"0.17.0","phase":"runtime"})
    );
    assert_eq!(value["image"]["profile"], "openshell-native");
    Ok(())
}
#[test]
fn rejects_unknown_fields_versions_cycles_paths_and_references(
) -> Result<(), Box<dyn std::error::Error>> {
    let mutations = [
        ("/tools/zig/version", json!("latest")),
        ("/tools/zig/phase", json!("build")),
        ("/sources/include", json!(["../secret"])),
        ("/sources/include", json!(["a//b"])),
        ("/missions/dev/depends_on", json!(["audit"])),
        ("/missions/dev/tools", json!(["missing"])),
        ("/schema_version", json!(true)),
    ];
    for (pointer, replacement) in mutations {
        let mut v = config();
        if pointer == "/tools/zig/phase" {
            v["tools"]["zig"]["phase"] = replacement;
        } else {
            *v.pointer_mut(pointer)
                .ok_or("Invalid fixture: missing value")? = replacement;
        }
        assert!(resolve(v, "audit").is_err(), "{pointer}");
    }
    let mut v = config();
    v["extra"] = json!(true);
    assert!(resolve(v, "dev").is_err());
    let mut v = config();
    v["missions"]["dev"]["extra"] = json!(true);
    assert!(resolve(v, "dev").is_err());
    assert!(resolve(config(), "missing").is_err());
    Ok(())
}
#[test]
fn executable_rejects_unknown_options_and_missing_state() -> Result<(), Box<dyn std::error::Error>>
{
    use std::process::Command;
    let exe = env!("CARGO_BIN_EXE_ladyshell");
    assert_eq!(
        Command::new(exe)
            .args(["status", "--state", "/absent", "--oops"])
            .output()?
            .status
            .code(),
        Some(2)
    );
    assert!(!Command::new(exe)
        .args(["status", "--state", "/absent"])
        .output()?
        .status
        .success());
    assert!(Command::new(exe).arg("--help").output()?.status.success());
    Ok(())
}
#[test]
fn rejects_excessive_mission_graph_before_recursion() -> Result<(), Box<dyn std::error::Error>> {
    let mut value = config();
    let missions = value["missions"]
        .as_object_mut()
        .ok_or("Invalid fixture: missing value")?;
    for i in 0..1100 {
        missions.insert(format!("m{i}"),json!({"tools":[],"include":[],"checks":[],"depends_on":if i==0 {vec![]}else{vec![format!("m{}",i-1)]}}));
    }
    assert!(resolve(value, "m1099").is_err());
    Ok(())
}
