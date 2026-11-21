//! Host adapter over the pinned jjpr public library.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() >= 3,
        "usage: ladyhost-jjpr <preflight|git-helper> CONFIG | <plan|submit> CONFIG BOOKMARK | <inspect-integration|integrate> CONFIG REQUEST | credential CONFIG <get|store|erase>"
    );
    anyhow::ensure!(
        (matches!(args[1].as_str(), "preflight" | "git-helper") && args.len() == 3)
            || (matches!(
                args[1].as_str(),
                "plan"
                    | "submit"
                    | "credential"
                    | "inspect-integration"
                    | "integrate"
                    | "render-conflict"
                    | "inspect-conflict"
            ) && args.len() == 4),
        "unsupported operation or argument count"
    );
    let result = run(&args);
    if result.is_err() && args[1] == "credential" && args[3] == "get" {
        // Git's quit response stops other helpers and interactive user fallback.
        std::io::stdout().write_all(b"quit=true\n\n")?;
    }
    result
}

fn run(args: &[String]) -> anyhow::Result<()> {
    use ladyhost::{Config, app};
    let path = std::path::Path::new(&args[2]);
    if matches!(args[1].as_str(), "inspect-integration" | "integrate") {
        let result = Config::load_host(path).and_then(|config| {
            ladyhost::integration::run(
                &config,
                path,
                std::path::Path::new(&args[3]),
                args[1] == "integrate",
            )
        });
        match result {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
            Err(error) => {
                println!(
                    "{}",
                    serde_json::json!({"outcome":ladyhost::integration::failure_outcome(&error),"reason":error.to_string(),"retry":"never automatically replay; inspect existing receipt intent before another attempt"})
                );
                anyhow::bail!("integration refused or outcome unknown");
            }
        }
        return Ok(());
    }
    let config = Config::load_host(path)?;
    match args[1].as_str() {
        "render-conflict" | "inspect-conflict" => {
            let value = ladyhost::conflict_review::inspect(
                &config,
                &args[3],
                args[1] == "render-conflict",
            )?;
            if args[1] == "render-conflict" {
                print!(
                    "{}",
                    value["body"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Review body missing"))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            Ok(())
        }
        "preflight" => {
            println!("{}", serde_json::to_string_pretty(&config.preflight()?)?);
            Ok(())
        }
        "git-helper" => app::install_git_helper(&config, path),
        "credential" => {
            let mut bytes = Vec::new();
            std::io::stdin().take(32769).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 32768, "credential request exceeds limit");
            let input = std::str::from_utf8(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid credential encoding"))?;
            let response = app::credential_response(
                &config,
                &args[3],
                input,
                || app::mint(&config),
                &app::SystemClock,
            )?;
            std::io::stdout().write_all(response.as_bytes())?;
            Ok(())
        }
        _ => config.submit(&args[3], args[1] == "plan"),
    }
}
