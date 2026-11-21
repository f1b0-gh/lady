//! Admit external reports only after independently deriving their entire selected scope.
use super::{invalid, Report};
use crate::{
    error::{ensure, Result},
    files,
    sources::{self, Snapshot, Sources},
};
use std::path::Path;

pub fn verified_report(
    root: &Path,
    selection: &Sources,
    snapshot: &Snapshot,
    report_path: Option<&Path>,
) -> Result<(Report, Option<String>)> {
    let actual = super::scan_snapshot(root, snapshot)?;
    let digest = if let Some(path) = report_path {
        let value = crate::json::parse(&files::read_limited(path, 32 * 1024 * 1024)?)?;
        let external: Report = serde_json::from_value(value)?;
        external.validate()?;
        // Hash lists and complete/locked flags are claims, not authority. Compare
        // the canonical typed model, including packages, sources and diagnostics.
        ensure!(
            serde_json::to_value(&external)? == serde_json::to_value(&actual)?,
            "Rapport Ladybom divergent : régénérer sur le périmètre source sélectionné"
        );
        Some(files::hash(&serde_json::to_vec(&actual)?))
    } else {
        None
    };
    // Detect newly added manifests as well as edits/removals during admission.
    ensure!(
        sources::snapshot(root, selection, None)? == *snapshot,
        "Sources modifiées pendant la vérification Ladybom"
    );
    Ok((actual, digest))
}

/// Rebind an external-report lock against a staged/current project without
/// trusting the original report path or the locked report's own hash list.
pub fn verify_digest(root: &Path, selection: &Sources, expected: &str) -> Result<()> {
    let snapshot = sources::snapshot(root, selection, None)?;
    let (actual, _) = verified_report(root, selection, &snapshot, None)?;
    ensure!(
        files::hash(&serde_json::to_vec(&actual)?) == expected,
        "Sources différentes du rapport Ladybom verrouillé"
    );
    Ok(())
}
