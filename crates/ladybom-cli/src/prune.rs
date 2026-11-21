use clap::Subcommand;
use ladybom::{
    deps::{graph, prune_validation, usage},
    error::Result,
    files,
};
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Subcommand)]
pub enum PruneCommand {
    /// Record usage and removal candidates without executing the project or external tools.
    Analyze {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, required = true)]
        manifest: Vec<String>,
        /// Existing cargo-machete JSON report produced in a controlled environment.
        #[arg(long)]
        machete_report: Option<PathBuf>,
        #[arg(long)]
        knip_report: Option<PathBuf>,
        #[arg(long)]
        deptry_report: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Display exact declarations and their removal identifiers.
    Roots {
        #[arg(long)]
        snapshot: PathBuf,
    },
    /// Build a request bound to the snapshot; does not modify any manifest.
    Request {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long, required = true)]
        remove_root: Vec<String>,
        #[arg(long)]
        retain_manifest: Vec<String>,
        #[arg(long, default_value_t = 32)]
        depth: u32,
        #[arg(long)]
        kind: Vec<String>,
        #[arg(long)]
        context: Vec<String>,
        #[arg(long)]
        unconditional_only: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Compare native traversals before and after removing selected declarations.
    Simulate {
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        engine: PathBuf,
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Hash an explicitly edited copy and verify that the declarations were removed.
    ValidationPlan {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        exclude: Vec<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
fn read(path: &Path) -> Result<Value> {
    ladybom::json::parse(&files::read_limited(path, 32 * 1024 * 1024)?)
}
fn emit(value: Value, output: Option<PathBuf>, complete: bool) -> Result<i32> {
    if let Some(path) = output {
        files::publish_json(&path, &value, false)?;
    } else {
        writeln!(
            std::io::stdout().lock(),
            "{}",
            serde_json::to_string(&value)?
        )?;
    }
    Ok(if complete { 0 } else { 2 })
}
pub fn run(command: PruneCommand) -> Result<i32> {
    match command {
        PruneCommand::Analyze {
            project,
            snapshot,
            manifest,
            machete_report,
            knip_report,
            deptry_report,
            output,
        } => {
            let graph = graph::read_snapshot(&snapshot)?;
            let mut report = usage::analyze(&project, &graph, &manifest)?;
            for (tool, path) in [
                ("cargo-machete", machete_report),
                ("knip", knip_report),
                ("deptry", deptry_report),
            ] {
                if let Some(path) = path {
                    usage::enrich(&mut report, tool, &read(&path)?)?;
                }
            }
            emit(serde_json::to_value(&report)?, output, report.complete)
        }
        PruneCommand::Roots { snapshot } => {
            let graph = graph::read_snapshot(&snapshot)?;
            emit(
                serde_json::json!({"graph_sha256":graph::graph_digest(&graph)?,"roots":graph::root_catalog(&graph)?}),
                None,
                true,
            )
        }
        PruneCommand::Request {
            snapshot,
            remove_root,
            retain_manifest,
            depth,
            kind,
            context,
            unconditional_only,
            output,
        } => {
            let graph = graph::read_snapshot(&snapshot)?;
            let mut request = graph::RemovalRequest::new(&graph, remove_root)?;
            request.retained_manifests = retain_manifest.into_iter().collect();
            request.max_depth = depth;
            request.filter = graph::Filter {
                kinds: kind.into_iter().collect(),
                graphs: context.into_iter().collect(),
                include_conditional: !unconditional_only,
            };
            request.validate(&graph)?;
            emit(serde_json::to_value(&request)?, output, true)
        }
        PruneCommand::Simulate {
            snapshot,
            request,
            engine,
            timeout_secs,
            output,
        } => {
            let graph = graph::read_snapshot(&snapshot)?;
            let request = serde_json::from_value(read(&request)?)?;
            let result = graph::Ladybug::new(engine)?
                .with_timeout(Duration::from_secs(timeout_secs))?
                .simulate_removal(&graph, &request)?;
            emit(serde_json::to_value(&result)?, output, result.complete)
        }
        PruneCommand::ValidationPlan {
            before,
            after,
            request,
            project,
            exclude,
            output,
        } => {
            let before = graph::read_snapshot(&before)?;
            let after = graph::read_snapshot(&after)?;
            let request = serde_json::from_value(read(&request)?)?;
            let plan = prune_validation::plan(&before, &after, &request, &project, &exclude)?;
            emit(serde_json::to_value(&plan)?, output, true)
        }
    }
}
