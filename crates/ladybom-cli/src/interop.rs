use clap::Subcommand;
use ladybom::{
    deps::{interop, vuln, Report},
    error::{Error, Result},
    files,
};
use std::{
    fs::{DirBuilder, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

#[derive(Debug, Subcommand)]
pub enum InteropCommand {
    /// Prepare a new directory with a public SBOM per lockfile and private reports.
    Bundle {
        #[arg(long)]
        report: PathBuf,
        /// Stable repository identity, retained only in private data.
        #[arg(long)]
        repository: String,
        #[arg(long)]
        revision: String,
        /// Scope label; does not establish dependency activation.
        #[arg(long)]
        target_profile: String,
        /// New directory; no existing content is replaced.
        #[arg(long)]
        output: PathBuf,
    },
}

pub fn run(command: InteropCommand) -> Result<i32> {
    let InteropCommand::Bundle {
        report,
        repository,
        revision,
        target_profile,
        output,
    } = command;
    let report: Report = serde_json::from_value(vuln::parse_json(&files::read_limited(
        &report,
        vuln::MAX_INPUT_BYTES,
    )?)?)?;
    let bundle = interop::bundle(
        &report,
        &interop::Scope {
            repository: &repository,
            revision: &revision,
            target_profile: &target_profile,
        },
    )?;
    // Pin every ancestor before creating output. Generated relative filenames
    // never come from the report. Keep descriptors live through publication.
    let output = files::absolute(&output)?;
    let invalid_path = || Error::InvalidInput {
        message: "Invalid bundle destination".into(),
    };
    let parent = files::open_directory(output.parent().ok_or_else(invalid_path)?)?;
    let name = output.file_name().ok_or_else(invalid_path)?;
    let parent_path = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
    DirBuilder::new()
        .mode(0o700)
        .create(parent_path.join(name))?;
    let directory = files::open_child(&parent, name, true)?;
    let directory_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let mut children = std::collections::BTreeMap::new();
    for name in ["public", "private"] {
        DirBuilder::new()
            .mode(0o700)
            .create(directory_path.join(name))?;
        children.insert(name, files::open_child(&directory, name.as_ref(), true)?);
    }
    for (path, bytes) in bundle.artifacts {
        let (group, name) = path.split_once('/').ok_or_else(invalid_path)?;
        let child = children.get(group).ok_or_else(invalid_path)?;
        let target = PathBuf::from(format!("/proc/self/fd/{}", child.as_raw_fd())).join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(target)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    for child in children.values() {
        child.sync_all()?;
    }
    // Publish the manifest last. Its presence marks a complete bundle; failures
    // preserve the incomplete directory for inspection, never overwrite old data.
    let mut manifest = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory_path.join(".manifest.pending"))?;
    serde_json::to_writer_pretty(&mut manifest, &bundle.manifest)?;
    manifest.write_all(b"\n")?;
    manifest.sync_all()?;
    std::fs::hard_link(
        directory_path.join(".manifest.pending"),
        directory_path.join("manifest.json"),
    )?;
    std::fs::remove_file(directory_path.join(".manifest.pending"))?;
    directory.sync_all()?;
    parent.sync_all()?;
    Ok(if report.complete { 0 } else { 2 })
}
