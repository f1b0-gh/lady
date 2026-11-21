use clap::{Args, Subcommand};
use ladybom::{
    deps::{
        vuln::{self, vxdf},
        Report,
    },
    error::Result,
    files,
};
use serde_json::Value;
use std::{
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug, Args)]
pub struct VxdfScopeArgs {
    /// Original VXDF document, not the import receipt.
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    report: PathBuf,
    #[arg(long)]
    snapshot: PathBuf,
    #[arg(long)]
    revision: String,
    #[arg(long)]
    target_profile: String,
    #[arg(long)]
    as_of: String,
    #[arg(long, default_value_t = 604800)]
    snapshot_max_age_seconds: u64,
    #[arg(long, default_value_t = 604800)]
    evidence_max_age_seconds: u64,
}
#[derive(Debug, Subcommand)]
pub enum VxdfCommand {
    /// Archive a local VXDF matching the pinned schema; does not establish qualification.
    Import {
        #[arg(long)]
        input: PathBuf,
        /// Archive containing the potentially sensitive original document.
        #[arg(long)]
        output: PathBuf,
    },
    /// Correlate assertions with the exact scope; no VEX decision or qualification.
    Correlate {
        #[command(flatten)]
        scope: VxdfScopeArgs,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Prepare a separate unapproved review; conclusions must still be written.
    ReviewTemplate {
        #[command(flatten)]
        scope: VxdfScopeArgs,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a public VXDF after explicit acceptance of a human review.
    Export {
        #[command(flatten)]
        scope: VxdfScopeArgs,
        #[arg(long)]
        review: PathBuf,
        /// Digest obtained and approved independently of the imported VXDF and receipt.
        #[arg(long)]
        review_sha256: String,
        /// Expected reviewer identity; an operator assertion without cryptographic verification.
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        output: PathBuf,
    },
}
fn read(path: &Path) -> Result<Value> {
    vuln::parse_json(&files::read_limited(path, vuln::MAX_INPUT_BYTES)?)
}
impl VxdfScopeArgs {
    fn load(self) -> Result<(vxdf::ImportedDocument, Report, vuln::Snapshot, vxdf::Scope)> {
        let document = vxdf::import(&files::read_limited(&self.input, vxdf::MAX_DOCUMENT_BYTES)?)?;
        let report: Report = serde_json::from_value(read(&self.report)?)?;
        let snapshot: vuln::Snapshot = serde_json::from_value(read(&self.snapshot)?)?;
        let scope = vxdf::Scope {
            revision: self.revision,
            target_profile: self.target_profile,
            as_of: self.as_of,
            snapshot_max_age_seconds: self.snapshot_max_age_seconds,
            evidence_max_age_seconds: self.evidence_max_age_seconds,
        };
        Ok((document, report, snapshot, scope))
    }
}
pub fn run(command: VxdfCommand) -> Result<i32> {
    match command {
        VxdfCommand::Import { input, output } => {
            let imported = vxdf::import(&files::read_limited(&input, vxdf::MAX_DOCUMENT_BYTES)?)?;
            files::publish_json(&output, &serde_json::to_value(imported)?, false)?;
        }
        VxdfCommand::Correlate { scope, output } => {
            let (document, report, snapshot, scope) = scope.load()?;
            let result =
                serde_json::to_value(vxdf::correlate(&document, &report, &snapshot, &scope)?)?;
            if let Some(output) = output {
                files::publish_json(&output, &result, false)?;
            } else {
                let mut stdout = std::io::stdout().lock();
                serde_json::to_writer(&mut stdout, &result)?;
                stdout.write_all(b"\n")?;
            }
        }
        VxdfCommand::ReviewTemplate { scope, output } => {
            let (document, report, snapshot, scope) = scope.load()?;
            let template = vxdf::review_template(&document, &report, &snapshot, &scope)?;
            files::publish_json(&output, &template, false)?;
        }
        VxdfCommand::Export {
            scope,
            review,
            review_sha256,
            reviewer,
            output,
        } => {
            let (document, report, snapshot, scope) = scope.load()?;
            let review = files::read_limited(&review, vxdf::MAX_DOCUMENT_BYTES)?;
            let acceptance = vxdf::ReviewAcceptance {
                review_digest: review_sha256,
                reviewer,
            };
            let result =
                vxdf::export_reviewed(&document, &report, &snapshot, &scope, &review, &acceptance)?;
            files::publish_json(&output, &result, false)?;
        }
    }
    Ok(0)
}
