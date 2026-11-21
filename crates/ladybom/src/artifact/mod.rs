//! Explicit, bounded artifact inspection, separate from static source scanning.
mod budget;
mod collect;
mod cyclonedx;
pub use cyclonedx::{coverage, write_cyclonedx, Coverage};
mod evidence;
mod filesystem;
mod go;
pub use go::{ElfFile, GoBinary, GoModule};
mod nix;
pub use collect::collect;
pub use evidence::{ArchiveCheck, ArtifactFile, CollectOptions, Evidence, Gap, NixOutput, Tool};
mod model;
pub use filesystem::inspect_rootfs;
pub use model::{FileEntry, InspectedRoot};

fn invalid(message: impl Into<String>) -> crate::error::Error {
    crate::error::Error::InvalidInput {
        message: message.into(),
    }
}

/// Read bounded strict evidence offline; validate consistency, not authenticity.
pub fn read_evidence(path: &std::path::Path) -> crate::error::Result<Evidence> {
    let bytes = crate::files::read_limited(path, 64 * 1024 * 1024)?;
    let evidence: Evidence = serde_json::from_value(crate::json::parse_with_limits(
        &bytes,
        64 * 1024 * 1024,
        200_000,
    )?)?;
    evidence.validate()?;
    Ok(evidence)
}
