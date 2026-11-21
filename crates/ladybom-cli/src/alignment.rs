use ladybom::{deps::graph, error::Result};
use std::{path::PathBuf, time::Duration};

#[derive(Debug, clap::Args)]
pub struct AlignmentArgs {
    #[arg(long)]
    snapshot: PathBuf,
    /// Require alignment, exact pins and complete coverage (otherwise exit 2).
    #[arg(long)]
    check: bool,
    /// Absolute path to the LadybugDB 0.17.1 CLI for explaining occurrences.
    #[arg(long)]
    engine: Option<PathBuf>,
    /// Canonical unversioned PURL to explain; otherwise, explain duplicates only.
    #[arg(long, requires = "engine")]
    package: Option<String>,
    #[arg(long, default_value_t = 8)]
    max_queries: usize,
    #[arg(long, default_value_t = 4096)]
    max_results: usize,
    #[arg(long, default_value_t = 16)]
    depth: u32,
    /// Total native traversal budget (1 to 300 seconds).
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
}

pub(crate) fn run(args: AlignmentArgs) -> Result<(serde_json::Value, bool)> {
    let snapshot = graph::read_snapshot(&args.snapshot)?;
    let report = if let Some(engine) = args.engine {
        graph::Ladybug::new(engine)?.explain_alignment(
            &snapshot,
            &graph::AlignmentExplanationOptions {
                package: args.package,
                max_queries: args.max_queries,
                max_results: args.max_results,
                max_depth: args.depth,
                timeout: Duration::from_secs(args.timeout_secs),
            },
        )?
    } else {
        graph::analyze_alignment(&snapshot)?
    };
    let success = if args.check {
        report.policy_pass()
    } else {
        report.complete()
    };
    Ok((serde_json::to_value(report)?, success))
}
