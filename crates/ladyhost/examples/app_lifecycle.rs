//! Explicit host lifecycle runner; no credentials are printed.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use anyhow::{Result, bail, ensure};
use ladyhost::{
    Config,
    lifecycle::{self, RemovalApi},
};
use std::path::Path;
fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(
        a.len() >= 3,
        "usage: app_lifecycle inspect CONFIG | remove CONFIG STATE | register STATE WORKSPACE OWNER REPO NAME"
    );
    let result = match a[1].as_str() {
        "inspect" if a.len() == 3 => {
            let c = Config::load_host(Path::new(&a[2]))?;
            lifecycle::Native::new(&c)?.inventory()?
        }
        "remove" if a.len() == 4 => {
            let c = Config::load_host(Path::new(&a[2]))?;
            lifecycle::remove_with(&c, Path::new(&a[3]), &mut lifecycle::Native::new(&c)?)?
        }
        "register" if a.len() == 7 => {
            lifecycle::registration::serve(Path::new(&a[2]), Path::new(&a[3]), &a[4], &a[5], &a[6])?
        }
        _ => bail!("Invalid lifecycle operation"),
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
