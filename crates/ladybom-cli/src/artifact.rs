use clap::Subcommand;
use ladybom::{
    artifact::{self, CollectOptions},
    error::{Error, Result},
    files,
};
use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    /// Inspecter un artefact avec des outils natifs explicitement fiables, hors ligne.
    Collect {
        #[arg(long)]
        rootfs: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        store_relative: PathBuf,
        #[arg(long)]
        nix: PathBuf,
        #[arg(long)]
        go_reader: PathBuf,
        #[arg(long)]
        archive_checker: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Exporter les preuves locales en CycloneDX sans processus ni réseau.
    Export {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

pub fn run(command: ArtifactCommand) -> Result<i32> {
    let (evidence, output, collect) = match command {
        ArtifactCommand::Collect {
            rootfs,
            manifest,
            archive,
            store_relative,
            nix,
            go_reader,
            archive_checker,
            output,
        } => (
            artifact::collect(&CollectOptions {
                rootfs,
                manifest,
                archive,
                store_relative,
                nix,
                go_reader,
                archive_checker,
            })?,
            output,
            true,
        ),
        ArtifactCommand::Export { evidence, output } => {
            (artifact::read_evidence(&evidence)?, output, false)
        }
    };
    let coverage = artifact::coverage(&evidence)?;
    let mut artifacts = vec![("coverage.json", serde_json::to_vec_pretty(&coverage)?)];
    if collect {
        let mut bytes = EvidenceBytes(Vec::new());
        serde_json::to_writer(&mut bytes, &evidence)?;
        artifacts.push(("evidence.json", bytes.0));
    } else {
        let mut bom = Vec::new();
        artifact::write_cyclonedx(&evidence, &mut bom)?;
        artifacts.push(("bom.cdx.json", bom));
    }
    publish(&output, artifacts)?;
    Ok(if coverage.scope_complete { 0 } else { 2 })
}

fn publish(output: &Path, artifacts: Vec<(&str, Vec<u8>)>) -> Result<()> {
    let invalid = || Error::InvalidInput {
        message: "Invalid artifact output directory".into(),
    };
    let output = files::absolute(output)?;
    let parent = files::open_directory(output.parent().ok_or_else(invalid)?)?;
    let name = output.file_name().ok_or_else(invalid)?;
    let parent_path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
    DirBuilder::new()
        .mode(0o700)
        .create(parent_path.join(name))?;
    let directory = files::open_child(&parent, name, true)?;
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut entries = Vec::new();
    for (name, bytes) in artifacts {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        entries.push(
            serde_json::json!({"path":name,"bytes":bytes.len(),"sha256":files::hash(&bytes)}),
        );
    }
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join(".manifest.pending"))?;
    serde_json::to_writer_pretty(
        &mut manifest,
        &serde_json::json!({"schema_version":1,"artifacts":entries}),
    )?;
    manifest.write_all(b"\n")?;
    manifest.sync_all()?;
    std::fs::hard_link(path.join(".manifest.pending"), path.join("manifest.json"))?;
    std::fs::remove_file(path.join(".manifest.pending"))?;
    directory.sync_all()?;
    parent.sync_all()?;
    Ok(())
}

// Enforce the transport budget before growing the serialized evidence buffer.
struct EvidenceBytes(Vec<u8>);
impl Write for EvidenceBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (64 * 1024 * 1024usize).saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Artifact evidence exceeds 64 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
