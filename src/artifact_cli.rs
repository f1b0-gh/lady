//! Temporary compatibility entry point for the independently installed bootc CLI.
use clap::Args;
use ladyshell::error::{Error, Result};
use std::{ffi::OsString, os::unix::process::CommandExt, process::Command};

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct ArtifactArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub arguments: Vec<OsString>,
}

pub fn run(args: ArtifactArgs) -> Result<()> {
    let program =
        std::env::var_os("LADYSHELL_BOOTC_BIN").unwrap_or_else(|| OsString::from("ladyboot"));
    let source = Command::new(&program).args(args.arguments).exec();
    Err(Error::ProcessSpawn { program, source }.context(
        "Installer ladyboot dans PATH ou définir LADYSHELL_BOOTC_BIN ; ladyshell artifact est un relais de compatibilité",
    ))
}
