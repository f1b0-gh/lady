use clap::{Args, Subcommand};
use ladyshell::{deps::prune_validation, error::Result, files};
use std::{io::Write, path::PathBuf};

#[derive(Debug, Args)]
pub struct DepsArgs {
    #[command(subcommand)]
    pub command: DepsCommand,
}
#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Validate a dependency removal analyzed and planned by Ladybom.
    Prune {
        #[command(subcommand)]
        command: PruneCommand,
    },
}
#[derive(Debug, Subcommand)]
pub enum PruneCommand {
    /// Run declared checks in a verified sandbox bound to the plan.
    #[command(
        after_help = "Examples:\n  ladyshell deps prune validate --state /path/to/state --plan /path/to/plan.json --output /path/to/receipt.json"
    )]
    Validate {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
pub fn run(args: DepsArgs) -> Result<i32> {
    match args.command {
        DepsCommand::Prune {
            command:
                PruneCommand::Validate {
                    state,
                    plan,
                    output,
                },
        } => {
            let plan = serde_json::from_value(ladyshell::json::parse(&files::read_limited(
                &plan,
                32 * 1024 * 1024,
            )?)?)?;
            let receipt = prune_validation::run(&state, &plan)?;
            if let Some(output) = output {
                files::publish_json(&output, &receipt, false)?;
            } else {
                writeln!(
                    std::io::stdout().lock(),
                    "{}",
                    serde_json::to_string(&receipt)?
                )?;
            }
            Ok(if receipt.passed { 0 } else { 2 })
        }
    }
}
