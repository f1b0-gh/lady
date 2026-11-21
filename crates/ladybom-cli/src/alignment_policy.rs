use ladybom::{deps::graph, error::Result, files};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct AlignmentPolicyArgs {
    #[arg(long)]
    snapshot: PathBuf,
    /// Verified baseline snapshot; records debt without approving it.
    #[arg(long)]
    baseline: PathBuf,
    /// Versioned JSON policy binding the baseline digest (maximum 4 MiB).
    #[arg(long)]
    policy: PathBuf,
    /// Explicit RFC3339 date for evaluating exceptions.
    #[arg(long)]
    as_of: String,
    /// Also require an active exception for each remaining difference.
    #[arg(long)]
    require_reviewed: bool,
}

pub(crate) fn run(args: AlignmentPolicyArgs) -> Result<(serde_json::Value, bool)> {
    let policy = graph::AlignmentPolicy::from_json(&files::read_limited(
        &args.policy,
        graph::MAX_ALIGNMENT_POLICY_BYTES,
    )?)?;
    let baseline = graph::read_snapshot(&args.baseline)?;
    let current = graph::read_snapshot(&args.snapshot)?;
    let report = graph::check_alignment_policy(&current, &baseline, &policy, &args.as_of)?;
    let success = if args.require_reviewed {
        report.reviewed_alignment_pass
    } else {
        report.non_regression_pass
    };
    Ok((serde_json::to_value(report)?, success))
}
