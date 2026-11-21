mod alignment;
mod alignment_plan;
mod alignment_policy;
mod artifact;
mod interop;
mod prune;
mod vuln;
mod vxdf;
use clap::{Parser, Subcommand};
use ladybom::{deps, error::Result, files, sources};
use std::{io::Write, path::PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "ladybom",
    version,
    about = "Static dependency analysis and removal simulations"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: DepsCommand,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Collect and export an artifact SBOM with explicit provenance.
    Artifact {
        #[command(subcommand)]
        command: artifact::ArtifactCommand,
    },
    /// Prepare public artifacts separated by lockfile, without network publication.
    Interop {
        #[command(subcommand)]
        command: interop::InteropCommand,
    },
    /// Import, correlate and export VXDF with explicit technical review.
    Vxdf {
        #[command(subcommand)]
        command: vxdf::VxdfCommand,
    },
    /// Assess vulnerabilities using local OSV advisories, without network access.
    Vuln {
        #[command(subcommand)]
        command: vuln::VulnCommand,
    },
    /// Detect, simulate and validate dependency removals.
    Prune {
        #[command(subcommand)]
        command: prune::PruneCommand,
    },
    /// Export and analyze conservative dependency graphs.
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },
    /// Inventory manifests and lockfiles without executing the project or accessing the network.
    Scan {
        #[arg(long)]
        project: PathBuf,
        /// JSON scope {include, exclude}, limited to 1 MiB, identical to Ladyshell's.
        #[arg(long)]
        sources: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Export a CycloneDX 1.5 JSON SBOM from the static inventory.
        #[arg(long, conflicts_with = "json")]
        cyclonedx: bool,
        /// public omits opaque data; private-detailed may contain secrets.
        #[arg(long, requires = "cyclonedx", value_parser = ["public", "private-detailed"])]
        export_profile: Option<String>,
    },
}

pub fn run(args: Cli) -> Result<i32> {
    match args.command {
        DepsCommand::Artifact { command } => artifact::run(command),
        DepsCommand::Interop { command } => interop::run(command),
        DepsCommand::Vxdf { command } => vxdf::run(command),
        DepsCommand::Vuln { command } => vuln::run(command),
        DepsCommand::Prune { command } => prune::run(command),
        DepsCommand::Graph { command } => run_graph(command),
        DepsCommand::Scan {
            project,
            sources,
            json,
            cyclonedx,
            export_profile,
        } => {
            let report = scan_input(&project, sources)?;
            let mut stdout = std::io::stdout().lock();
            if cyclonedx {
                let profile = if export_profile.as_deref() == Some("private-detailed") {
                    deps::cyclonedx::ExportProfile::PrivateDetailed
                } else {
                    deps::cyclonedx::ExportProfile::Public
                };
                deps::cyclonedx::write_json_with_profile(&report, profile, &mut stdout)?;
            } else if json {
                writeln!(stdout, "{}", serde_json::to_string(&report)?)?;
            } else {
                for project in &report.projects {
                    writeln!(
                        stdout,
                        "{}: {} ({}, {} requirements, {} locked components)",
                        project.root,
                        project.ecosystem,
                        project.manager,
                        project.requirements.len(),
                        report.components_for(project)?.len()
                    )?;
                }
                for diagnostic in &report.diagnostics {
                    writeln!(
                        stdout,
                        "{}: {} — {}",
                        diagnostic.file, diagnostic.code, diagnostic.message
                    )?;
                }
                writeln!(
                    stdout,
                    "Scan {}; no installation performed.",
                    if report.complete {
                        "complete"
                    } else {
                        "partial"
                    }
                )?;
            }
            Ok(if report.complete { 0 } else { 2 })
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum GraphCommand {
    /// Publish a new immutable Parquet snapshot, without execution or network access.
    Export {
        #[arg(long)]
        project: PathBuf,
        /// Same JSON scope as scan --sources and Ladyshell.
        #[arg(long)]
        sources: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read and verify a snapshot and its contexts.
    Inspect {
        #[arg(long)]
        snapshot: PathBuf,
    },
    /// Traverse dependencies, or a path to a target.
    Query(QueryArgs),
    /// Traverse dependents potentially affected by a PURL.
    Impact(QueryArgs),
    /// Check versions by lockfile and declared pins; explain with Ladybug.
    Alignment(alignment::AlignmentArgs),
    /// Prepare a static duplicate reduction plan without selecting a version.
    AlignmentPlan(alignment_plan::AlignmentPlanArgs),
    /// Check differences against a baseline and temporary exceptions.
    AlignmentPolicy(alignment_policy::AlignmentPolicyArgs),
    /// Compare two verified snapshots.
    Diff {
        #[arg(long)]
        before: PathBuf,
        #[arg(long)]
        after: PathBuf,
    },
}
#[derive(Debug, clap::Args)]
pub struct QueryArgs {
    #[arg(long)]
    snapshot: PathBuf,
    /// Absolute path to the trusted LadybugDB 0.17.1 CLI.
    #[arg(long)]
    engine: PathBuf,
    #[arg(long)]
    purl: String,
    /// Required if the PURL appears in multiple contexts.
    #[arg(long)]
    graph: Option<String>,
    #[arg(long)]
    target_purl: Option<String>,
    #[arg(long, requires = "target_purl")]
    target_graph: Option<String>,
    #[arg(long)]
    reverse: bool,
    #[arg(long, default_value_t = 32)]
    depth: u32,
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
    /// Edge types allowed before traversal; repeatable.
    #[arg(long)]
    kind: Vec<String>,
    /// Contexts allowed at both ends; repeatable.
    #[arg(long)]
    context: Vec<String>,
    #[arg(long)]
    unconditional_only: bool,
}
fn run_graph(command: GraphCommand) -> Result<i32> {
    use deps::graph::{self, Direction, Filter, Ladybug, NodeRef, Query};
    let command = match command {
        GraphCommand::Impact(mut args) => {
            args.reverse = true;
            GraphCommand::Query(args)
        }
        other => other,
    };
    let (value, complete) = match command {
        GraphCommand::Export {
            project,
            sources,
            output,
        } => {
            let graph = graph::project(scan_input(&project, sources)?)?;
            graph::write_snapshot(&graph, &output)?;
            (
                serde_json::json!({"snapshot":output,"complete":graph.complete(),"contexts":graph.contexts,"components":graph.components.len(),"dependencies":graph.dependencies.len(),"limitations":graph.limitations}),
                graph.complete(),
            )
        }
        GraphCommand::Inspect { snapshot } => {
            let graph = graph::read_snapshot(&snapshot)?;
            (serde_json::to_value(&graph)?, graph.complete())
        }
        GraphCommand::Alignment(args) => alignment::run(args)?,
        GraphCommand::AlignmentPlan(args) => return alignment_plan::run(args),
        GraphCommand::AlignmentPolicy(args) => alignment_policy::run(args)?,
        GraphCommand::Diff { before, after } => {
            let diff = graph::diff(
                &graph::read_snapshot(&before)?,
                &graph::read_snapshot(&after)?,
            )?;
            (serde_json::to_value(&diff)?, diff.complete)
        }
        GraphCommand::Query(args) | GraphCommand::Impact(args) => {
            let graph = graph::read_snapshot(&args.snapshot)?;
            let select = |purl: &str, context: Option<&str>| -> Result<NodeRef> {
                let candidates: Vec<_> = graph
                    .components
                    .iter()
                    .filter(|n| n.key.purl == purl && context.is_none_or(|g| n.key.graph == g))
                    .collect();
                if candidates.len() != 1 {
                    return Err(ladybom::error::Error::InvalidInput { message: format!("Missing or ambiguous PURL ({purl}): specify --graph or --target-graph; see graph inspect") });
                }
                Ok(candidates[0].key.clone())
            };
            let query = Query {
                start: select(&args.purl, args.graph.as_deref())?,
                target: args
                    .target_purl
                    .as_deref()
                    .map(|purl| select(purl, args.target_graph.as_deref()))
                    .transpose()?,
                direction: if args.reverse {
                    Direction::Dependants
                } else {
                    Direction::Dependencies
                },
                max_depth: args.depth,
                filter: Filter {
                    kinds: args.kind.into_iter().collect(),
                    graphs: args.context.into_iter().collect(),
                    include_conditional: !args.unconditional_only,
                },
            };
            let result = Ladybug::new(args.engine)?
                .with_timeout(std::time::Duration::from_secs(args.timeout_secs))?
                .query(&graph, &query)?;
            (serde_json::to_value(&result)?, result.complete)
        }
    };
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string(&value)?
    )?;
    Ok(if complete { 0 } else { 2 })
}

fn scan_input(project: &std::path::Path, sources: Option<PathBuf>) -> Result<deps::Report> {
    if let Some(path) = sources {
        let spec: sources::Sources =
            serde_json::from_slice(&files::read_limited(&path, 1024 * 1024)?)?;
        let snapshot = sources::snapshot(project, &spec, None)?;
        deps::scan_snapshot(project, &snapshot)
    } else {
        deps::scan_project(project)
    }
}
