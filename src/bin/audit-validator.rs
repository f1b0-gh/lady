// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
#![forbid(unsafe_code)]
use ladyshell::audit::validator::{validate, Env, Error, Mode, RealEnv};
use std::{
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run(io::stdout().lock(), io::stderr().lock()) {
        Ok(code) => code,
        Err(_) => ExitCode::FAILURE,
    }
}
fn run(mut output: impl Write, mut diagnostics: impl Write) -> io::Result<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    if command.as_deref() == Some(std::ffi::OsStr::new("--version")) && args.next().is_none() {
        writeln!(output, "audit-validator {}", env!("CARGO_PKG_VERSION"))?;
        return Ok(ExitCode::SUCCESS);
    }
    let mode = match command.as_deref().and_then(std::ffi::OsStr::to_str) {
        Some("findings") => Mode::Findings,
        Some("coverage") => Mode::Coverage,
        _ => {
            writeln!(
                diagnostics,
                "Usage: audit-validator <findings|coverage> PATH"
            )?;
            return Ok(ExitCode::FAILURE);
        }
    };
    let Some(path) = args.next() else {
        writeln!(
            diagnostics,
            "Usage: audit-validator <findings|coverage> PATH"
        )?;
        return Ok(ExitCode::FAILURE);
    };
    if args.next().is_some() {
        writeln!(
            diagnostics,
            "Usage: audit-validator <findings|coverage> PATH"
        )?;
        return Ok(ExitCode::FAILURE);
    }
    match RealEnv
        .read_file(std::path::Path::new(&path))
        .and_then(|bytes| validate(mode, &bytes))
    {
        Ok(n) => {
            let label = match mode {
                Mode::Findings => "findings",
                Mode::Coverage => "coverage units",
            };
            writeln!(output, "PASS: {n} {label} valid")?;
            Ok(ExitCode::SUCCESS)
        }
        Err(Error::Validation(errors)) => {
            for e in &errors {
                writeln!(diagnostics, "ERROR: {e}")?;
            }
            writeln!(
                diagnostics,
                "FAIL: {} validation error(s){}",
                errors.len(),
                if errors.len() == 100 {
                    "; output capped at 100"
                } else {
                    ""
                }
            )?;
            Ok(ExitCode::FAILURE)
        }
        Err(e) => {
            writeln!(diagnostics, "FAIL: {e}")?;
            Ok(ExitCode::FAILURE)
        }
    }
}
