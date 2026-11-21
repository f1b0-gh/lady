use clap::Subcommand;
use ladybom::{
    deps::{vuln, Report},
    error::{Error, Result},
    files,
};
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

const AUXILIARY_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_MAX_AGE: u64 = 604800;

#[derive(Debug, Subcommand)]
pub enum VulnCommand {
    /// Import local OSV files; no network connection or execution.
    Import {
        /// Each file contains an OSV object or an array of OSV objects.
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        source: String,
        #[arg(long)]
        fetched_at: String,
        #[arg(long, required = true, value_parser = ["crates.io", "npm", "PyPI"])]
        ecosystem: Vec<String>,
        /// Explicit producer assertion about ecosystem coverage.
        #[arg(long)]
        complete: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare a native report with an OSV snapshot at an explicit date.
    Assess {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        as_of: String,
        #[arg(long, default_value_t = DEFAULT_MAX_AGE)]
        max_age_seconds: u64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Recompute the assessment and apply a strict local policy.
    Check {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        as_of: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        decisions: Option<PathBuf>,
        #[arg(long)]
        signals: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Recompute the assessment and export its separate CycloneDX 1.5 VEX.
    Vex {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        snapshot: PathBuf,
        #[arg(long)]
        as_of: String,
        #[arg(long, default_value_t = DEFAULT_MAX_AGE)]
        max_age_seconds: u64,
        #[arg(long)]
        decisions: Option<PathBuf>,
        /// BOM-Link references by default; local components do not establish server qualification.
        #[arg(long, default_value = "bom-link", value_parser = ["bom-link", "local-components"])]
        profile: String,
        /// Public projection by default; private native details require an explicit request.
        #[arg(long, default_value = "public", value_parser = ["public", "private-detailed"])]
        export_profile: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn invalid(message: &str) -> Error {
    Error::InvalidInput {
        message: message.into(),
    }
}
fn read(path: &Path, limit: usize) -> Result<Value> {
    vuln::parse_json(&files::read_limited(path, limit)?)
}
fn assessment(
    report: &Path,
    snapshot: &Path,
    as_of: &str,
    max_age: u64,
) -> Result<vuln::Assessment> {
    let report: Report = serde_json::from_value(read(report, vuln::MAX_INPUT_BYTES)?)?;
    let snapshot: vuln::Snapshot = serde_json::from_value(read(snapshot, vuln::MAX_INPUT_BYTES)?)?;
    vuln::assess(&report, &snapshot, as_of, max_age)
}
struct BoundedWriter<W> {
    inner: W,
    written: usize,
}
impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > vuln::MAX_INPUT_BYTES.saturating_sub(self.written) {
            return Err(std::io::Error::other("Vulnerability output exceeds 64 MiB"));
        }
        let count = self.inner.write(bytes)?;
        self.written += count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
fn emit(value: Value, output: Option<PathBuf>, complete: bool) -> Result<i32> {
    if let Some(path) = output {
        let mut size = BoundedWriter {
            inner: std::io::sink(),
            written: 0,
        };
        serde_json::to_writer_pretty(&mut size, &value)?;
        size.write_all(b"\n")?;
        files::publish_json(&path, &value, false)?;
    } else {
        let mut bytes = BoundedWriter {
            inner: Vec::new(),
            written: 0,
        };
        serde_json::to_writer(&mut bytes, &value)?;
        bytes.write_all(b"\n")?;
        std::io::stdout().lock().write_all(&bytes.inner)?;
    }
    Ok(if complete { 0 } else { 2 })
}

pub fn run(command: VulnCommand) -> Result<i32> {
    match command {
        VulnCommand::Import {
            input,
            source,
            fetched_at,
            mut ecosystem,
            complete,
            output,
        } => {
            let mut remaining = vuln::MAX_INPUT_BYTES;
            let mut advisories = Vec::new();
            for path in input {
                let bytes = files::read_limited(&path, remaining)?;
                remaining = remaining
                    .checked_sub(bytes.len())
                    .ok_or_else(|| invalid("OSV import too large"))?;
                let value = vuln::parse_json(&bytes)?;
                let records = match value {
                    Value::Array(records) => records,
                    Value::Object(_) => vec![value],
                    _ => {
                        return Err(invalid(
                            "An OSV object or an array of OSV objects is required",
                        ))
                    }
                };
                if records.len() > vuln::MAX_RECORDS.saturating_sub(advisories.len()) {
                    return Err(invalid("Too many OSV advisories in the import"));
                }
                advisories.extend(records);
            }
            advisories.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            ecosystem.sort();
            ecosystem.dedup();
            let snapshot = vuln::Snapshot {
                schema_version: 1,
                source,
                fetched_at,
                complete,
                ecosystems: ecosystem,
                advisories,
            };
            vuln::osv::validate_snapshot(&snapshot)?;
            emit(serde_json::to_value(&snapshot)?, Some(output), true)
        }
        VulnCommand::Assess {
            report,
            snapshot,
            as_of,
            max_age_seconds,
            output,
        } => {
            let assessment = assessment(&report, &snapshot, &as_of, max_age_seconds)?;
            emit(
                serde_json::to_value(&assessment)?,
                output,
                assessment.complete,
            )
        }
        VulnCommand::Check {
            report,
            snapshot,
            as_of,
            policy,
            decisions,
            signals,
            output,
        } => {
            let policy: vuln::Policy = policy
                .map(|path| {
                    read(&path, AUXILIARY_BYTES)
                        .and_then(|value| Ok(serde_json::from_value(value)?))
                })
                .transpose()?
                .unwrap_or_default();
            let decisions: Option<vuln::Decisions> = decisions
                .map(|path| {
                    read(&path, AUXILIARY_BYTES)
                        .and_then(|value| Ok(serde_json::from_value(value)?))
                })
                .transpose()?;
            let signals: Option<vuln::Signals> = signals
                .map(|path| {
                    read(&path, AUXILIARY_BYTES)
                        .and_then(|value| Ok(serde_json::from_value(value)?))
                })
                .transpose()?;
            let assessment = assessment(&report, &snapshot, &as_of, policy.max_age_seconds)?;
            let result =
                vuln::policy::evaluate(&assessment, decisions.as_ref(), &policy, signals.as_ref())?;
            emit(serde_json::to_value(&result)?, output, result.allowed)
        }
        VulnCommand::Vex {
            report,
            snapshot,
            as_of,
            max_age_seconds,
            decisions,
            profile,
            export_profile,
            output,
        } => {
            let decisions: Option<vuln::Decisions> = decisions
                .map(|path| {
                    read(&path, AUXILIARY_BYTES)
                        .and_then(|value| Ok(serde_json::from_value(value)?))
                })
                .transpose()?;
            let report: Report = serde_json::from_value(read(&report, vuln::MAX_INPUT_BYTES)?)?;
            let snapshot: vuln::Snapshot =
                serde_json::from_value(read(&snapshot, vuln::MAX_INPUT_BYTES)?)?;
            let assessment = vuln::assess(&report, &snapshot, &as_of, max_age_seconds)?;
            let mut bytes = BoundedWriter {
                inner: Vec::new(),
                written: 0,
            };
            let profile = match profile.as_str() {
                "bom-link" => vuln::vex::Profile::BomLink,
                "local-components" => vuln::vex::Profile::LocalComponents,
                _ => return Err(invalid("Unknown VEX profile")),
            };
            let export_profile = if export_profile == "private-detailed" {
                ladybom::deps::cyclonedx::ExportProfile::PrivateDetailed
            } else {
                ladybom::deps::cyclonedx::ExportProfile::Public
            };
            vuln::vex::write_json_with_export_profile(
                &report,
                &assessment,
                decisions.as_ref(),
                profile,
                export_profile,
                &mut bytes,
            )?;
            emit(
                serde_json::from_slice(&bytes.inner)?,
                output,
                assessment.complete,
            )
        }
    }
}
