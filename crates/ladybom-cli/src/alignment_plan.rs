use ladybom::{deps::graph, error::Result};
use std::{io::Write, path::PathBuf};

#[derive(Debug, clap::Args)]
pub struct AlignmentPlanArgs {
    #[arg(long)]
    snapshot: PathBuf,
    /// Rendre un plan Markdown ; JSON versionné par défaut.
    #[arg(long)]
    markdown: bool,
}

pub(crate) fn run(args: AlignmentPlanArgs) -> Result<i32> {
    let plan = graph::plan_alignment(&graph::read_snapshot(&args.snapshot)?)?;
    let mut stdout = std::io::stdout().lock();
    if args.markdown {
        // Finish bounded rendering before writing anything to stdout.
        write!(stdout, "{}", plan.to_markdown()?)?;
    } else {
        serde_json::to_writer(&mut stdout, &plan)?;
        writeln!(stdout)?;
    }
    Ok(if plan.analysis_complete { 0 } else { 2 })
}
