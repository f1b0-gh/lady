use clap::Parser;
use ladyboot::cli::{self, Cli};
use std::io::Write;

fn main() {
    let result = cli::run(Cli::parse().args).and_then(|value| {
        writeln!(
            std::io::stdout().lock(),
            "{}",
            serde_json::to_string(&value)?
        )?;
        Ok(())
    });
    if let Err(error) = result {
        let _ = writeln!(std::io::stderr().lock(), "Error: {error}");
        std::process::exit(error.exit_code());
    }
}
