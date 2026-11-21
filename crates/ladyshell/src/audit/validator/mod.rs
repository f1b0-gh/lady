// SPDX-License-Identifier: MIT
// Copyright (c) 2025-2026 Cloudflare, Inc.
// License: crates/ladyshell/src/audit/validator/LICENSE-MIT.
//! Imported document validator; MIT applies to this module.
#![forbid(unsafe_code)]
mod common;
mod coverage;
mod findings;
mod json;
mod preflight;
mod unicode_tables;
use std::fmt;
#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Findings,
    Coverage,
}
#[derive(Debug, PartialEq)]
pub enum Error {
    Input,
    Utf8,
    Syntax,
    Limit(&'static str),
    Configuration,
    Validation(Vec<String>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input => write!(f, "input could not be opened or read safely"),
            Self::Utf8 => write!(f, "input is not valid UTF-8"),
            Self::Syntax => write!(f, "invalid JSON syntax"),
            Self::Limit(s) => write!(f, "input exceeds {s}"),
            Self::Configuration => write!(f, "invalid embedded validator configuration"),
            Self::Validation(e) => write!(f, "{} validation error(s)", e.len()),
        }
    }
}
impl std::error::Error for Error {}
pub fn validate(mode: Mode, input: &[u8]) -> Result<usize, Error> {
    if input.len() > 5 * 1024 * 1024 {
        return Err(Error::Limit("5242880 byte limit"));
    }
    let text = std::str::from_utf8(input).map_err(|_| Error::Utf8)?;
    preflight::scan(text, mode)?;
    let value = json::parse(text, mode)?;
    let n = value
        .array()
        .map(<[json::Value]>::len)
        .ok_or_else(|| Error::Validation(vec!["$: expected array".into()]))?;
    let errors = match mode {
        Mode::Findings => findings::validate(&value)?,
        Mode::Coverage => coverage::validate(&value),
    };
    if errors.0.is_empty() {
        Ok(n)
    } else {
        Err(Error::Validation(errors.0))
    }
}
mod input;
pub use input::{Env, RealEnv};
#[cfg(test)]
mod parity_tests {
    use super::*;
    #[test]
    fn upstream_document_fixtures() -> Result<(), Box<dyn std::error::Error>> {
        for (i, line) in include_str!("fixtures.jsonl").lines().enumerate() {
            let fixture = json::parse(line, Mode::Findings)?;
            let mode = if fixture.get("mode").is("findings") {
                Mode::Findings
            } else {
                Mode::Coverage
            };
            let input = fixture.get("text").text().ok_or("fixture text missing")?;
            assert_eq!(
                validate(mode, input.as_bytes()).is_ok(),
                fixture.get("valid") == &json::Value::Bool(true),
                "fixture {i}"
            );
        }
        Ok(())
    }
}
