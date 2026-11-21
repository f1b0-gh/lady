use clap::{Args, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Prepare the audit scope and diagnose missing capabilities.
    Plan {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        profile: Option<Profile>,
    },
    /// Run the audit, refusing execution when required guarantees are unavailable.
    Run {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        profile: Option<Profile>,
    },
    /// Verify a native audit run and its evidence offline.
    Verify { path: PathBuf },
    /// Resume cleanup of an interrupted run without replaying the target.
    Recover { path: PathBuf },
    /// Compare two runs without transferring their confirmations.
    Compare { old: PathBuf, new: PathBuf },
    /// Write a verified export into a new directory.
    Export {
        path: PathBuf,
        #[arg(long)]
        destination: PathBuf,
    },
    /// Validate a document without confirming a vulnerability.
    Validate { mode: DocumentMode, path: PathBuf },
}
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DocumentMode {
    Findings,
    Coverage,
}
#[derive(Clone, Debug, ValueEnum)]
pub enum Profile {
    Quick,
    Targeted,
}

impl From<AuditArgs> for ladyshell::audit::cli::AuditArgs {
    fn from(args: AuditArgs) -> Self {
        Self {
            command: args.command.into(),
        }
    }
}

impl From<AuditCommand> for ladyshell::audit::cli::AuditCommand {
    fn from(command: AuditCommand) -> Self {
        match command {
            AuditCommand::Plan { state, profile } => Self::Plan {
                state,
                profile: profile.map(Into::into),
            },
            AuditCommand::Run { state, profile } => Self::Run {
                state,
                profile: profile.map(Into::into),
            },
            AuditCommand::Verify { path } => Self::Verify { path },
            AuditCommand::Recover { path } => Self::Recover { path },
            AuditCommand::Compare { old, new } => Self::Compare { old, new },
            AuditCommand::Export { path, destination } => Self::Export { path, destination },
            AuditCommand::Validate { mode, path } => Self::Validate {
                mode: mode.into(),
                path,
            },
        }
    }
}

impl From<DocumentMode> for ladyshell::audit::cli::DocumentMode {
    fn from(mode: DocumentMode) -> Self {
        match mode {
            DocumentMode::Findings => Self::Findings,
            DocumentMode::Coverage => Self::Coverage,
        }
    }
}

impl From<Profile> for ladyshell::audit::model::Profile {
    fn from(profile: Profile) -> Self {
        match profile {
            Profile::Quick => Self::Quick,
            Profile::Targeted => Self::Targeted,
        }
    }
}
