//! Local migration notice for the retired artifact forwarding command.
use clap::Args;
use ladyshell::error::{Error, Result};
use std::{ffi::OsString, io::Write};

const NOTICE: &str = "The ladyshell artifact forwarding command is retired. Run ladyboot directly; for help, run ladyboot --help.";

#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct ArtifactArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub arguments: Vec<OsString>,
}

pub fn run(args: ArtifactArgs) -> Result<()> {
    if args.arguments.len() == 1 && (args.arguments[0] == "--help" || args.arguments[0] == "-h") {
        writeln!(std::io::stdout().lock(), "{NOTICE}")?;
        return Ok(());
    }
    Err(Error::InvalidInput {
        message: NOTICE.into(),
    })
}
