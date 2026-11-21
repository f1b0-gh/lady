use super::{
    evidence::text,
    filesystem::{hash_file, relative},
    inspect_rootfs, invalid, ArchiveCheck, ArtifactFile, CollectOptions, Evidence, Tool,
};
use crate::{error::Result, files};
use std::{
    ffi::OsString,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub(super) struct ToolRunner<'a> {
    pub options: &'a CollectOptions,
    deadline: Instant,
}
impl ToolRunner<'_> {
    pub(super) fn inspection_deadline(&self) -> Instant {
        self.deadline.min(Instant::now() + Duration::from_secs(300))
    }

    pub(super) fn call(
        &self,
        program: &Path,
        args: Vec<OsString>,
        limit: usize,
        seconds: u64,
    ) -> Result<Vec<u8>> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| invalid("Artifact native collection time limit"))?;
        let mut command = Command::new(program);
        command.args(args).env("LC_ALL", "C");
        nickel_util::process::capture(command, remaining.min(Duration::from_secs(seconds)), limit)
    }
    pub(super) fn nix(&self, args: Vec<OsString>) -> Result<Vec<u8>> {
        let mut complete: Vec<OsString> =
            vec!["--extra-experimental-features".into(), "nix-command".into()];
        complete.extend(args);
        self.call(&self.options.nix, complete, 16 * 1024 * 1024, 60)
    }
}

fn tool(role: &str, path: &Path) -> Result<Tool> {
    if !path.is_absolute() {
        return Err(invalid("Collector tool must be an absolute path"));
    }
    let file = files::open_regular(path)?;
    if file.metadata()?.permissions().mode() & 0o111 == 0 {
        return Err(invalid("Collector tool is not executable"));
    }
    let (sha256, bytes) = hash_file(
        file,
        256 * 1024 * 1024,
        Instant::now() + Duration::from_secs(60),
    )?;
    Ok(Tool {
        role: role.into(),
        sha256,
        bytes,
    })
}

pub fn collect(options: &CollectOptions) -> Result<Evidence> {
    let store = options
        .store_relative
        .to_str()
        .ok_or_else(|| invalid("Non-UTF8 embedded store path"))?;
    relative(store)?;
    let inventory = inspect_rootfs(&options.rootfs, &options.manifest)?;
    let archive_name = options
        .archive
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("Invalid archive name"))?;
    text(archive_name)?;
    let (archive_hash, archive_bytes) = hash_file(
        files::open_regular(&options.archive)?,
        32 * 1024 * 1024 * 1024,
        Instant::now() + Duration::from_secs(300),
    )?;
    let definitions = [
        ("nix", &options.nix),
        ("go-reader", &options.go_reader),
        ("archive-checker", &options.archive_checker),
    ];
    let tools: Vec<_> = definitions
        .iter()
        .map(|(role, path)| tool(role, path))
        .collect::<Result<_>>()?;
    let runner = ToolRunner {
        options,
        deadline: Instant::now() + Duration::from_secs(1800),
    };
    runner.call(
        &options.archive_checker,
        vec![
            options.archive.as_os_str().into(),
            options.rootfs.join(&options.manifest).into_os_string(),
        ],
        1024 * 1024,
        300,
    )?;
    let mut budget = super::budget::Budget::default();
    let (nix_outputs, mut gaps) =
        super::nix::collect_outputs(options, &inventory, &runner, &mut budget)?;
    let (go_binaries, elf_files, go_gaps) =
        super::go::collect_binaries(options, &inventory, &runner, &mut budget)?;
    gaps.extend(go_gaps);
    if Instant::now() > runner.deadline {
        return Err(invalid("Artifact native collection time limit"));
    }
    let final_inventory = inspect_rootfs(&options.rootfs, &options.manifest)?;
    if serde_json::to_vec(&inventory)? != serde_json::to_vec(&final_inventory)? {
        return Err(invalid("Rootfs changed during native collection"));
    }
    let (final_hash, final_bytes) = hash_file(
        files::open_regular(&options.archive)?,
        32 * 1024 * 1024 * 1024,
        Instant::now() + Duration::from_secs(300),
    )?;
    if final_hash != archive_hash || final_bytes != archive_bytes {
        return Err(invalid("Archive changed during native collection"));
    }
    for ((role, path), original) in definitions.iter().zip(&tools) {
        let current = tool(role, path)?;
        if current.sha256 != original.sha256 || current.bytes != original.bytes {
            return Err(invalid("Collector tool changed during execution"));
        }
    }
    let checker = tools
        .iter()
        .find(|t| t.role == "archive-checker")
        .ok_or_else(|| invalid("Archive checker absent"))?;
    let evidence = Evidence {
        schema_version: 1,
        archive: ArtifactFile {
            name: archive_name.into(),
            sha256: archive_hash.clone(),
            bytes: archive_bytes,
        },
        archive_check: ArchiveCheck {
            archive_sha256: archive_hash,
            manifest_sha256: inventory.manifest_sha256.clone(),
            tool_sha256: checker.sha256.clone(),
        },
        inventory,
        store_relative: store.into(),
        nix_outputs,
        go_binaries,
        elf_files,
        tools,
        gaps,
    };
    evidence.validate()?;
    Ok(evidence)
}
