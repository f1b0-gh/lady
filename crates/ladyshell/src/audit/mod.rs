//! Native audit contracts. Document validity is not a security verdict.
pub mod agent;
pub mod budget;
pub mod cli;
pub mod collect;
pub mod compare;
pub mod config;
pub mod documents;
pub mod export;
pub mod image;
pub mod journal;
pub mod model;
pub mod plan;
pub mod publish;
mod read;
pub mod report;
pub mod run;
pub mod runtime;
pub mod validator;
pub mod verify;
pub mod worker;
use crate::error::{Error, Result};
use serde_json::Value;

pub fn dispatch(args: cli::AuditArgs) -> Result<Value> {
    match args.command {
        cli::AuditCommand::Validate { mode, path } => documents::validate_file(mode.into(), &path),
        cli::AuditCommand::Verify { path } => verify::load(&path).map(|run| verify::summary(&run)),
        cli::AuditCommand::Compare { old, new } => {
            Ok(compare::compare(&verify::load(&old)?, &verify::load(&new)?))
        }
        cli::AuditCommand::Export { path, destination } => {
            export::export(&verify::load(&path)?, &destination)
        }
        cli::AuditCommand::Plan { state, profile } => plan::make(&state, profile, false),
        cli::AuditCommand::Run { state, profile } => run::execute(&state, profile),
        cli::AuditCommand::Recover { path } => runtime::recover(&path),
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}
