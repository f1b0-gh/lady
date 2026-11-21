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
    about = "Analyse statique des dépendances et simulations de retrait"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: DepsCommand,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Collecter et exporter le SBOM d’un artefact avec provenance explicite.
    Artifact {
        #[command(subcommand)]
        command: artifact::ArtifactCommand,
    },
    /// Préparer des artefacts publics séparés par verrou, sans publication réseau.
    Interop {
        #[command(subcommand)]
        command: interop::InteropCommand,
    },
    /// Importer, corréler et exporter VXDF avec revue technique explicite.
    Vxdf {
        #[command(subcommand)]
        command: vxdf::VxdfCommand,
    },
    /// Évaluer les vulnérabilités depuis des avis OSV locaux, sans réseau.
    Vuln {
        #[command(subcommand)]
        command: vuln::VulnCommand,
    },
    /// Détecter, simuler et valider les retraits de dépendances.
    Prune {
        #[command(subcommand)]
        command: prune::PruneCommand,
    },
    /// Exporter et analyser des graphes de dépendances conservateurs.
    Graph {
        #[command(subcommand)]
        command: GraphCommand,
    },
    /// Inventorier les manifests et verrous sans exécuter le projet ni accéder au réseau.
    Scan {
        #[arg(long)]
        project: PathBuf,
        /// Périmètre JSON {include, exclude}, limité à 1 Mio, identique à Ladyshell.
        #[arg(long)]
        sources: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Exporter un SBOM JSON CycloneDX 1.5 à partir de l’inventaire statique.
        #[arg(long, conflicts_with = "json")]
        cyclonedx: bool,
        /// public omet les données opaques ; private-detailed peut contenir des secrets.
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
                        "{} : {} ({}, {} exigences, {} composants verrouillés)",
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
                    "Scan {} ; aucune installation effectuée.",
                    if report.complete {
                        "complet"
                    } else {
                        "partiel"
                    }
                )?;
            }
            Ok(if report.complete { 0 } else { 2 })
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum GraphCommand {
    /// Publier un nouveau snapshot Parquet immuable, sans exécution ni réseau.
    Export {
        #[arg(long)]
        project: PathBuf,
        /// Même périmètre JSON que scan --sources et Ladyshell.
        #[arg(long)]
        sources: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Lire et vérifier un snapshot et ses contextes.
    Inspect {
        #[arg(long)]
        snapshot: PathBuf,
    },
    /// Parcourir les dépendances, ou un chemin vers une cible.
    Query(QueryArgs),
    /// Parcourir les dépendants potentiellement affectés par une PURL.
    Impact(QueryArgs),
    /// Vérifier les versions par verrou et les pins déclarés ; expliquer avec Ladybug.
    Alignment(alignment::AlignmentArgs),
    /// Préparer un plan statique de réduction des doublons, sans choisir de version.
    AlignmentPlan(alignment_plan::AlignmentPlanArgs),
    /// Contrôler les divergences contre une référence et des exceptions temporaires.
    AlignmentPolicy(alignment_policy::AlignmentPolicyArgs),
    /// Comparer deux snapshots vérifiés.
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
    /// Chemin absolu du CLI LadybugDB 0.17.1 de confiance.
    #[arg(long)]
    engine: PathBuf,
    #[arg(long)]
    purl: String,
    /// Obligatoire si la PURL apparaît dans plusieurs contextes.
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
    /// Types d'arêtes autorisés avant parcours, répétable.
    #[arg(long)]
    kind: Vec<String>,
    /// Contextes autorisés aux deux extrémités, répétable.
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
                    return Err(ladybom::error::Error::InvalidInput { message: format!("PURL absente ou ambiguë ({purl}) : préciser --graph ou --target-graph ; voir graph inspect") });
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
