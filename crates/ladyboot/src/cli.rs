//! CLI adapter for the public artifact API.
use crate::artifact;
use clap::{Args, Parser, Subcommand, ValueEnum};
use nickel_util::error::Result;
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Build and verify minimal bootc artifacts with Nickel and Nix"
)]
pub struct Cli {
    #[command(flatten)]
    pub args: ArtifactArgs,
}

#[derive(Debug, Args)]
pub struct ArtifactArgs {
    #[command(subcommand)]
    pub command: ArtifactCommand,
}
#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Validate the public Nickel contract without building an image.
    Check(Input),
    /// Resolve package versions and explain the requested needs without building.
    Explain {
        #[command(flatten)]
        input: Input,
        /// Optional realized rootfs; verify all delivered files before reporting it.
        #[arg(long)]
        rootfs: Option<PathBuf>,
    },
    /// Compare two requested profiles and their resolved selections.
    Diff {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        other: PathBuf,
    },
    /// Render explicit JSON for the Nix recipes.
    Render {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, requires = "output")]
        replace: bool,
    },
    /// Lock the selected configuration and recipes.
    Lock {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        replace: bool,
    },
    /// Verify the lock and describe the build without executing it.
    Plan {
        #[command(flatten)]
        locked: Locked,
        #[arg(long, value_enum, default_value = "bootc-image")]
        target: ArtifactTarget,
    },
    /// Build a Nix artifact from locked inputs.
    Build {
        #[command(flatten)]
        locked: Locked,
        #[arg(long, value_enum, default_value = "bootc-image")]
        target: ArtifactTarget,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        replace: bool,
    },
    /// Compare a receipt with the identity recorded in the local Nix store.
    Inspect {
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Build unit and rootfs checks for the locked profile.
    Test {
        #[command(flatten)]
        locked: Locked,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        replace: bool,
    },
}
#[derive(Debug, Args)]
pub struct Input {
    #[arg(long)]
    config: PathBuf,
    /// Directory of Nix recipes explicitly trusted by the operator.
    #[arg(long)]
    resources: PathBuf,
}
impl From<Input> for artifact::ArtifactRequest {
    fn from(input: Input) -> Self {
        Self {
            config: input.config,
            resources: input.resources,
        }
    }
}
#[derive(Debug, Args)]
pub struct Locked {
    #[command(flatten)]
    input: Input,
    #[arg(long)]
    lock: PathBuf,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ArtifactTarget {
    Rootfs,
    BootcImage,
    BootTestRootfs,
    Kernel,
    Initrd,
    Checks,
}
impl From<ArtifactTarget> for artifact::Target {
    fn from(target: ArtifactTarget) -> Self {
        match target {
            ArtifactTarget::Rootfs => Self::Rootfs,
            ArtifactTarget::BootcImage => Self::BootcImage,
            ArtifactTarget::BootTestRootfs => Self::BootTestRootfs,
            ArtifactTarget::Kernel => Self::Kernel,
            ArtifactTarget::Initrd => Self::Initrd,
            ArtifactTarget::Checks => Self::Checks,
        }
    }
}
pub fn run(args: ArtifactArgs) -> Result<Value> {
    match args.command {
        ArtifactCommand::Check(input) => Ok(serde_json::to_value(artifact::check(&input.into())?)?),
        ArtifactCommand::Explain { input, rootfs } => {
            artifact::explain(&input.into(), rootfs.as_deref())
        }
        ArtifactCommand::Diff { input, other } => {
            let request: artifact::ArtifactRequest = input.into();
            let left = artifact::explain(&request, None)?;
            let right = artifact::explain(
                &artifact::ArtifactRequest {
                    config: other,
                    resources: request.resources,
                },
                None,
            )?;
            Ok(crate::profile::differences(&left, &right))
        }
        ArtifactCommand::Render {
            input,
            output,
            replace,
        } => {
            let value = artifact::render(&input.into())?;
            if let Some(path) = output {
                artifact::publish(&path, &value, replace)?;
            }
            Ok(value)
        }
        ArtifactCommand::Lock {
            input,
            output,
            replace,
        } => Ok(serde_json::to_value(artifact::lock(
            &input.into(),
            &output,
            replace,
        )?)?),
        ArtifactCommand::Plan { locked, target } => {
            artifact::plan(&locked.input.into(), &locked.lock, target.into())
        }
        ArtifactCommand::Build {
            locked,
            target,
            receipt,
            replace,
        } => {
            let value = artifact::build(&locked.input.into(), &locked.lock, target.into())?;
            artifact::publish(&receipt, &value, replace)?;
            Ok(serde_json::to_value(value)?)
        }
        ArtifactCommand::Inspect { receipt } => artifact::inspect(&receipt),
        ArtifactCommand::Test {
            locked,
            receipt,
            replace,
        } => {
            let value = artifact::test(&locked.input.into(), &locked.lock)?;
            artifact::publish(&receipt, &value, replace)?;
            Ok(serde_json::to_value(value)?)
        }
    }
}
