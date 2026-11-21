//! CLI adapter for the local management API; no provider calls.
use clap::{Args, Subcommand, ValueEnum};
use ladyshell::{
    associations,
    error::{Error, Result},
    management::{Annotation, Filter, RecordedStatus, Registry},
};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};
#[derive(Debug, Args)]
pub struct ManagementArgs {
    /// Local database in a private directory; defaults to XDG_STATE_HOME/ladyshell/management.
    #[arg(long, global = true)]
    database: Option<PathBuf>,
    #[command(subcommand)]
    action: Action,
}
#[derive(Debug, Subcommand)]
enum Action {
    /// Explicitly import or refresh verified local associations.
    Refresh,
    /// Read retained catalog observations without OpenShell calls.
    List {
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        status: Option<Status>,
        #[arg(long, value_parser=parse_label)]
        label: Option<(String, String)>,
        #[arg(long)]
        include_archived: bool,
        #[arg(long)]
        include_deleted: bool,
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Inspect a catalog identity, including archived or deleted entries.
    Show { id: String },
    /// Update local metadata and reversible archival status.
    Annotate {
        id: String,
        #[arg(long, value_parser=parse_label)]
        label: Vec<(String, String)>,
        #[arg(long)]
        remove_label: Vec<String>,
        #[arg(long)]
        note: Option<String>,
        #[arg(long, conflicts_with = "unarchive")]
        archive: bool,
        #[arg(long)]
        unarchive: bool,
    },
    /// Read the history of catalog observations and changes.
    History {
        id: String,
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
}
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Status {
    Retained,
    DeletionPending,
    Deleted,
}
fn parse_label(value: &str) -> std::result::Result<(String, String), String> {
    value
        .split_once('=')
        .map(|(k, v)| (k.into(), v.into()))
        .ok_or_else(|| "Format requis : clé=valeur".into())
}
pub fn run(args: ManagementArgs) -> Result<i32> {
    let registry = if let Some(path) = args.database {
        Registry::new(path)?
    } else {
        Registry::local()?
    };
    let mut exit = 0;
    let value = match args.action {
        Action::Refresh => {
            let report = registry.refresh(&associations::registry()?)?;
            if !report.complete {
                exit = 1;
            }
            serde_json::to_value(report)?
        }
        Action::List {
            project,
            status,
            label,
            include_archived,
            include_deleted,
            after,
            limit,
        } => serde_json::to_value(registry.list(&Filter {
            project,
            status: status.map(|s| match s {
                Status::Retained => RecordedStatus::Retained,
                Status::DeletionPending => RecordedStatus::DeletionPending,
                Status::Deleted => RecordedStatus::Deleted,
            }),
            label,
            include_archived,
            include_deleted,
            after,
            limit,
        })?)?,
        Action::Show { id } => instance_json(registry.get(&id)?)?,
        Action::Annotate {
            id,
            label,
            remove_label,
            note,
            archive,
            unarchive,
        } => {
            let mut labels = BTreeMap::new();
            for (key, value) in label {
                if labels.insert(key, value).is_some() {
                    return Err(Error::InvalidInput {
                        message: "Label répété".into(),
                    });
                }
            }
            instance_json(registry.annotate(
                &id,
                &Annotation {
                    labels,
                    remove_labels: remove_label,
                    note,
                    archived: if archive {
                        Some(true)
                    } else if unarchive {
                        Some(false)
                    } else {
                        None
                    },
                },
            )?)?
        }
        Action::History { id, after, limit } => {
            serde_json::to_value(registry.history(&id, after, limit)?)?
        }
    };
    serde_json::to_writer_pretty(std::io::stdout().lock(), &value)?;
    println!();
    Ok(exit)
}
fn instance_json(instance: ladyshell::management::Instance) -> Result<Value> {
    let mut value = serde_json::to_value(instance)?;
    value["schema_version"] = 1.into();
    value["provider_checked"] = false.into();
    Ok(value)
}
