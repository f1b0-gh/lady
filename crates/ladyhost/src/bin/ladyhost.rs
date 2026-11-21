//! Standalone owner-facing setup for the Ladyhost GitHub coordinator.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use anyhow::{Context, Result, ensure};
use ladyhost::{
    Config, app,
    setup::{self, Spec, Store},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
};
const HELP: &str = r#"ladyhost — configure a GitHub project without a coding agent

  ladyhost init --repo OWNER/REPO --app-name SLUG --workspace PATH
      --target BRANCH --check '["program","arg"]' --state PRIVATE_PATH [--apply]
  ladyhost init --spec FILE --state PRIVATE_PATH [--apply]
  ladyhost init --state PRIVATE_PATH --apply             Resume
  ladyhost doctor --state PRIVATE_PATH
  ladyhost doctor --config FILE --integration FILE [--workflow FILE]
  ladyhost uninstall --state PRIVATE_PATH [--apply]
  ladyhost review-conflict --config FILE --candidate FULL_OID [--render]
  ladyhost help <command>                       Command usage and examples

Init shows a plan unless --apply is present. Owner authorization and App creation
open GitHub browser steps. Install the App on only the selected repository, then
rerun init with the same state to continue. No agent or personal publishing login
is needed. State and keys must stay outside the source checkout.

Options: --gh PATH --jj PATH --signing-key PATH --ci-check NAME
         --workflow-path .github/workflows/NAME.yml --adopt-workflow --json
Repeat --check for sequential argv commands. With --adopt-workflow, select an
existing exact-push workflow and its job name instead of generating one.
Missing --gh/--jj paths are found on PATH. All recorded paths become absolute.
Uninstall revokes the installation, then removes unchanged owned rules. It keeps
history, source, signing keys and workflows. Global App deletion remains an owner
browser step and is reported separately.
Exit codes: 0 healthy/plan/uninstalled, 2 pending/incomplete/unknown, 1 failure.
"#;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "credential") {
        if let Err(error) = credential(&args) {
            if args.get(2).is_some_and(|s| s == "get") {
                let _ = std::io::stdout().write_all(b"quit=true\n\n");
            }
            eprintln!("Ladyhost credential helper refused: {error}");
            std::process::exit(1);
        }
        return;
    }
    let json_mode = args.iter().any(|s| s == "--json");
    match run(&args) {
        Ok(Some(value)) => {
            if json_mode {
                println!("{value}");
            } else {
                display(&value);
            }
            let status = value["status"].as_str().unwrap_or("plan");
            if matches!(status, "pending" | "unknown" | "incomplete") {
                std::process::exit(2);
            }
            if status == "failed" {
                std::process::exit(1);
            }
        }
        Ok(None) => {}
        Err(error) => {
            if json_mode {
                println!(
                    "{}",
                    json!({"status":"failed","reason":error.to_string(),"recovery":"Keep the state directory; inspect doctor and resume the same operation. Do not delete intent files to force a retry."})
                );
            } else {
                eprintln!(
                    "Ladyhost: {error}\nKeep the state directory for inspection and recovery."
                );
            }
            std::process::exit(1);
        }
    }
}
fn display(v: &Value) {
    println!("Ladyhost: {}", v["status"].as_str().unwrap_or("plan"));
    for field in [
        "repository",
        "target",
        "step",
        "next_action",
        "url",
        "resume",
        "config",
        "host_checkout",
        "integration_defaults",
    ] {
        if let Some(s) = v[field].as_str() {
            println!("{field}: {s}");
        }
    }
    if let Some(checks) = v["checks"].as_array() {
        for check in checks {
            println!(
                "  {}: {}",
                check["check"].as_str().unwrap_or("project command"),
                check["status"].as_str().unwrap_or("selected")
            );
            if check["status"] != "healthy" {
                println!("    {}", check["detail"]);
            }
        }
    }
    if let Some(body) = v["body"].as_str() {
        println!("{body}");
    }
    // Plans expose the exact selected commands, resource scope and preserved data.
    if v["status"] == "plan" || v.get("status").is_none() {
        println!(
            "{}",
            serde_json::to_string_pretty(v).unwrap_or_else(|_| "Plan rendering failed".into())
        );
    }
    if let Some(limits) = v["limits"].as_array() {
        for limit in limits {
            if let Some(s) = limit.as_str() {
                println!("Limit: {s}");
            }
        }
    }
}
fn absolute(path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(path);
    let p = if p.is_absolute() {
        p
    } else {
        std::env::current_dir()?.join(p)
    };
    if p.exists() {
        return Ok(p.canonicalize()?);
    }
    let parent = p
        .parent()
        .context("Path has no parent")?
        .canonicalize()
        .context("Create the parent directory first")?;
    Ok(parent.join(p.file_name().context("Path has no file name")?))
}
fn executable(name: &str) -> Result<PathBuf> {
    for dir in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate.canonicalize()?);
        }
    }
    anyhow::bail!("Install {name}, or select its absolute path with --{name}")
}
fn read_json(path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "Input exceeds 64 KiB");
    Ok(serde_json::from_slice(&bytes)?)
}
fn run(args: &[String]) -> Result<Option<Value>> {
    if args.is_empty() || args == ["--help"] || args == ["-h"] || args == ["help"] {
        println!("{HELP}");
        return Ok(None);
    }
    if args.len() == 2 && (args[0] == "help" || args[1] == "--help" || args[1] == "-h") {
        let topic = if args[0] == "help" {
            &args[1]
        } else {
            &args[0]
        };
        println!("{}", setup::help::command(topic)?);
        return Ok(None);
    }
    let action = &args[0];
    ensure!(
        matches!(
            action.as_str(),
            "init" | "doctor" | "uninstall" | "review-conflict"
        ),
        "Unknown command; run ladyhost --help"
    );
    let mut options = BTreeMap::new();
    let mut checks = vec![];
    let mut i = 1;
    while i < args.len() {
        let key = &args[i];
        if matches!(
            key.as_str(),
            "--apply" | "--json" | "--adopt-workflow" | "--render"
        ) {
            ensure!(
                options.insert(key.clone(), "true".into()).is_none(),
                "Repeated option"
            );
            i += 1;
            continue;
        }
        ensure!(
            matches!(
                key.as_str(),
                "--state"
                    | "--candidate"
                    | "--spec"
                    | "--repo"
                    | "--app-name"
                    | "--workspace"
                    | "--target"
                    | "--check"
                    | "--gh"
                    | "--jj"
                    | "--signing-key"
                    | "--ci-check"
                    | "--workflow-path"
                    | "--config"
                    | "--integration"
                    | "--workflow"
            ),
            "Unknown option; run ladyhost --help"
        );
        let value = args.get(i + 1).context("Option requires a value")?.clone();
        if key == "--check" {
            checks.push(
                serde_json::from_str::<Vec<String>>(&value)
                    .context("--check must be a JSON argv array")?,
            );
        } else {
            ensure!(
                options.insert(key.clone(), value).is_none(),
                "Repeated option"
            );
        }
        i += 2;
    }
    let get = |key: &str| options.get(key).map(String::as_str);
    if action == "review-conflict" {
        ensure!(
            checks.is_empty()
                && options.keys().all(|k| matches!(
                    k.as_str(),
                    "--config" | "--candidate" | "--render" | "--json"
                )),
            "Unsupported conflict review options"
        );
        let config = Config::load_host(&absolute(
            get("--config").context("Select --config with a host-bound conflict_review package")?,
        )?)?;
        let value = ladyhost::conflict_review::inspect(
            &config,
            get("--candidate").context("Select --candidate FULL_OID")?,
            get("--render").is_some(),
        )?;
        if get("--render").is_some() && get("--json").is_none() {
            print!("{}", value["body"].as_str().context("Review text missing")?);
            return Ok(None);
        }
        return Ok(Some(value));
    }
    if action == "doctor" && get("--config").is_some() {
        ensure!(
            options.keys().all(|k| matches!(
                k.as_str(),
                "--config" | "--integration" | "--workflow" | "--json"
            )) && checks.is_empty(),
            "Unsupported doctor options"
        );
        let config = absolute(get("--config").context("Config missing")?)?;
        let defaults = read_json(&absolute(
            get("--integration").context("Select --integration with retained rules/CI IDs")?,
        )?)?;
        let workflow = get("--workflow")
            .map(|p| absolute(p).and_then(|p| read_json(&p)))
            .transpose()?;
        return Ok(Some(setup::doctor::inspect(
            &config,
            &defaults,
            workflow.as_ref(),
        )?));
    }
    ensure!(
        get("--render").is_none() && get("--candidate").is_none(),
        "Conflict options require review-conflict"
    );
    let root = absolute(get("--state").context("Select --state outside your source checkout")?)?;
    if action != "init" {
        ensure!(
            options
                .keys()
                .all(|k| matches!(k.as_str(), "--state" | "--json")
                    || action == "uninstall" && k == "--apply")
                && checks.is_empty(),
            "Unsupported command options"
        );
        let store = Store::resume(&root)?;
        return Ok(Some(if action == "doctor" {
            setup::doctor::run(&store)?
        } else if get("--apply").is_some() {
            setup::engine::uninstall(&store)?
        } else {
            setup::engine::uninstall_plan(&store)?
        }));
    }
    ensure!(
        !options.contains_key("--config")
            && !options.contains_key("--integration")
            && !options.contains_key("--workflow"),
        "Unsupported init options"
    );
    let spec: Spec = if root.join("request.json").exists()
        && options
            .keys()
            .all(|k| matches!(k.as_str(), "--state" | "--apply" | "--json"))
        && checks.is_empty()
    {
        serde_json::from_value(read_json(&root.join("request.json"))?)?
    } else if let Some(file) = get("--spec") {
        ensure!(
            options
                .keys()
                .all(|k| matches!(k.as_str(), "--spec" | "--state" | "--apply" | "--json"))
                && checks.is_empty(),
            "Do not combine --spec with project selection flags"
        );
        serde_json::from_value(read_json(&absolute(file)?)?)?
    } else {
        serde_json::from_value(
            json!({"schema_version":1,"repository":get("--repo").context("Select --repo OWNER/REPO")?,"app_name":get("--app-name").context("Select a globally unique --app-name slug")?,
            "workspace":absolute(get("--workspace").unwrap_or("."))?,"target":get("--target").unwrap_or("main"),"checks":checks,
            "gh":get("--gh").map(absolute).unwrap_or_else(||executable("gh"))?,"jj":get("--jj").map(absolute).unwrap_or_else(||executable("jj"))?,
            "signing_key":get("--signing-key").map(absolute).transpose()?,"ci_check":get("--ci-check").unwrap_or("ci/ladyhost"),
            "workflow_path":get("--workflow-path").unwrap_or(".github/workflows/ladyhost.yml"),"adopt_workflow":get("--adopt-workflow").is_some()}),
        )?
    };
    let mut plan = setup::engine::plan(&spec)?;
    plan["state"] = json!(root);
    if get("--apply").is_none() {
        return Ok(Some(plan));
    }
    eprintln!(
        "Configuring {} on {}. Owner consent is required for App creation and repository administration.",
        spec.repository, spec.target
    );
    let store = Store::open(&root, &spec)?;
    Ok(Some(setup::engine::init(&store)?))
}
fn credential(args: &[String]) -> Result<()> {
    ensure!(args.len() == 3, "Invalid credential helper invocation");
    let config = Config::load_host(Path::new(&args[1]))?;
    let mut bytes = vec![];
    std::io::stdin().take(32769).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 32768, "Credential request exceeds bound");
    let input = std::str::from_utf8(&bytes).context("Invalid credential input")?;
    let response = app::credential_response(
        &config,
        &args[2],
        input,
        || app::mint(&config),
        &app::SystemClock,
    )?;
    std::io::stdout().write_all(response.as_bytes())?;
    Ok(())
}
