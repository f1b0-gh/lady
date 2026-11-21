use clap::Parser;

fn main() {
    let code = match ladybom_cli::run(ladybom_cli::Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            error.exit_code()
        }
    };
    std::process::exit(code);
}
