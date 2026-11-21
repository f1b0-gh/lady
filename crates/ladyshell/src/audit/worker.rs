//! Trusted, bounded target worker. This entry point only runs inside the admitted audit sandbox.
use super::{config::Limits, invalid, model::SourceFile};
use crate::{
    config::{identifier, relative_path},
    error::{ensure, Result},
    files,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, Metadata},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::MetadataExt,
            process::{CommandExt, ExitStatusExt},
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;
const RECEIPT_LIMIT: u64 = 64 * 1024 * 1024;
const LOG_LIMIT: usize = 1024 * 1024;
const SOURCE_COUNT_LIMIT: usize = 16_384;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub schema_version: u32,
    pub invocation_id: String,
    pub command: Vec<String>,
    pub limits: Limits,
    pub timeout_seconds: u64,
    pub sources: Vec<SourceFile>,
    pub artifacts: Vec<ArtifactRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRequest {
    pub id: String,
    pub path: String,
    pub max_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReceipt {
    pub schema_version: u32,
    pub invocation_id: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub output_limited: bool,
    pub stopped: bool,
    pub cpu_usage_usec: u64,
    pub artifacts: Vec<WorkerArtifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerArtifact {
    pub id: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub content_base64: String,
}

pub fn validate_request(request: &WorkerRequest) -> Result<()> {
    ensure!(request.schema_version == 1, "Unsupported worker version");
    identifier(&request.invocation_id)?;
    ensure!(request.timeout_seconds > 0, "Zero worker timeout");
    let limits = &request.limits;
    ensure!(
        limits.cpu_seconds >= 5
            && limits.memory_bytes > 0
            && limits.processes > 0
            && limits.processes <= 2048
            && limits.files > 0
            && limits.disk_bytes > 0,
        "Invalid worker limits"
    );
    ensure!(
        !request.command.is_empty()
            && request.command.len() <= 128
            && request
                .command
                .iter()
                .all(|arg| !arg.is_empty() && arg.len() <= 4096 && !arg.contains('\0')),
        "Invalid worker command"
    );
    ensure!(
        request.sources.len() <= SOURCE_COUNT_LIMIT
            && request.sources.len() <= limits.files as usize,
        "Too many sources for the worker"
    );
    let mut source_paths = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut source_bytes = 0u64;
    for source in &request.sources {
        validate_path(&source.path)?;
        ensure!(
            source_paths.insert(source.path.as_str()),
            "Duplicate source"
        );
        ensure!(
            source.sha256.len() == 64
                && source
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Invalid source hash"
        );
        ensure!(source.size <= ARTIFACT_LIMIT, "Source too large");
        source_bytes = source_bytes
            .checked_add(source.size)
            .ok_or_else(|| invalid("Source volume overflow"))?;
        ensure!(
            source_bytes <= limits.disk_bytes && source_bytes <= RECEIPT_LIMIT,
            "Source volume exceeds limit"
        );
        let mut cursor = source.path.as_str();
        while let Some((parent, _)) = cursor.rsplit_once('/') {
            directories.insert(parent);
            cursor = parent;
        }
    }
    reject_path_collisions(&source_paths)?;
    // Producer, work, home, tmp, cargo, target, cache and zig directories consume inodes too.
    ensure!(
        request
            .sources
            .len()
            .saturating_add(directories.len())
            .saturating_add(8)
            <= limits.files as usize,
        "File limit insufficient for sources and caches"
    );
    ensure!(
        request.artifacts.len() <= 1022,
        "Too many artifacts requested, including reserved logs"
    );
    let mut ids = BTreeSet::from(["stdout", "stderr"]);
    let mut paths = BTreeSet::from(["stdout.txt", "stderr.txt"]);
    let mut artifact_bytes = 2 * LOG_LIMIT as u64;
    for artifact in &request.artifacts {
        identifier(&artifact.id)?;
        validate_path(&artifact.path)?;
        ensure!(
            ids.insert(artifact.id.as_str()),
            "Reserved or duplicate artifact ID"
        );
        ensure!(
            paths.insert(artifact.path.as_str()),
            "Reserved or duplicate artifact path"
        );
        ensure!(
            artifact.max_bytes > 0 && artifact.max_bytes <= ARTIFACT_LIMIT,
            "Invalid artifact limit"
        );
        artifact_bytes = artifact_bytes
            .checked_add(artifact.max_bytes)
            .ok_or_else(|| invalid("Artifact volume overflow"))?;
        ensure!(
            artifact_bytes <= RECEIPT_LIMIT,
            "Aggregate artifact volume exceeds limit"
        );
    }
    reject_path_collisions(&paths)?;
    Ok(())
}

fn validate_path(path: &str) -> Result<()> {
    relative_path(path)?;
    ensure!(
        path.len() <= 4096 && path.split('/').all(|part| part.len() <= 255),
        "Path too long"
    );
    Ok(())
}

fn reject_path_collisions(paths: &BTreeSet<&str>) -> Result<()> {
    for path in paths {
        let mut cursor = *path;
        while let Some((parent, _)) = cursor.rsplit_once('/') {
            ensure!(!paths.contains(parent), "File/directory collision");
            cursor = parent;
        }
    }
    Ok(())
}

pub fn execute(request: WorkerRequest) -> Result<WorkerReceipt> {
    validate_request(&request)?;
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "Worker restricted to Linux x86_64"
    );
    let (scratch, source, cgroup) = verify_environment(&request.limits)?;
    protect_worker()?;
    // mkdirat is exclusive: an interrupted or concurrent producer is never adopted.
    let producer = create_directory(&scratch, &request.invocation_id, false)?;
    let work = create_directory(&producer, "work", false)?;
    for directory in ["home", "tmp", "cargo", "target", "cache", "zig"] {
        create_directory(&producer, directory, false)?;
    }
    for entry in &request.sources {
        verify_source_ownership(&source, &entry.path)?;
        copy_source(&source, &work, entry)?;
    }
    let producer_path = Path::new("/audit/scratch").join(&request.invocation_id);
    let work_path = producer_path.join("work");
    let cpu_before = cpu_usage(&cgroup)?;
    // Admission requires >=5 CPU seconds. With at most one CPU and a <=100 ms
    // period, half the budget reserves the bounded 2 s cleanup plus the burst.
    // Cleanup failure never attests a successful CPU bound; cpu.stat is checked below.
    let timeout = Duration::from_secs(request.timeout_seconds)
        .min(Duration::from_secs(request.limits.cpu_seconds).div_f64(2.0));
    let captured = run_target(&request, &work_path, &producer_path, timeout)?;
    let cpu_usage_usec = cpu_usage(&cgroup)?
        .checked_sub(cpu_before)
        .ok_or_else(|| invalid("CPU counter decreased"))?;
    ensure!(
        cpu_usage_usec <= request.limits.cpu_seconds.saturating_mul(1_000_000),
        "CPU limit exceeded; receipt rejected"
    );
    let mut artifacts = vec![
        artifact("stdout", "stdout.txt", captured.stdout),
        artifact("stderr", "stderr.txt", captured.stderr),
    ];
    for requested in &request.artifacts {
        let bytes = read_artifact(&work, &requested.path, requested.max_bytes)?;
        artifacts.push(artifact(&requested.id, &requested.path, bytes));
    }
    Ok(WorkerReceipt {
        schema_version: 1,
        invocation_id: request.invocation_id,
        exit_code: captured.exit_code,
        timed_out: captured.timed_out,
        output_limited: captured.output_limited,
        stopped: true,
        cpu_usage_usec,
        artifacts,
    })
}

fn artifact(id: &str, path: &str, bytes: Vec<u8>) -> WorkerArtifact {
    WorkerArtifact {
        id: id.into(),
        path: path.into(),
        size: bytes.len() as u64,
        sha256: files::hash(&bytes),
        content_base64: STANDARD.encode(bytes),
    }
}

fn protect_worker() -> Result<()> {
    // SAFETY: both prctl options only restrict this process; scalar arguments are valid.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn verify_no_capabilities() -> Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: version 3 requires exactly two initialized capability data words.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        data.iter()
            .all(|word| word.effective == 0 && word.permitted == 0 && word.inheritable == 0),
        "Capabilities forbidden: process limits must remain mandatory"
    );
    Ok(())
}

fn verify_environment(limits: &Limits) -> Result<(File, File, File)> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: the three pointers refer to valid uid_t storage.
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        [real, effective, saved] == [10001; 3],
        "Worker requires real, effective and saved UID 10001 in the audit sandbox"
    );
    verify_no_capabilities()?;
    let scratch = files::open_directory(Path::new("/audit/scratch"))?;
    let metadata = scratch.metadata()?;
    ensure!(
        metadata.uid() == 10001 && metadata.mode() & 0o077 == 0,
        "Scratch is not private or has a different owner"
    );
    // SAFETY: scratch owns its descriptor; statfs points to valid writable storage.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(stat.f_type == libc::TMPFS_MAGIC, "Scratch must use tmpfs");
    ensure!(
        stat.f_bsize > 0 && stat.f_blocks > 0 && stat.f_files > 0,
        "Cannot verify tmpfs quotas"
    );
    let bytes = stat
        .f_blocks
        .checked_mul(stat.f_bsize as u64)
        .ok_or_else(|| invalid("Tmpfs quota overflow"))?;
    ensure!(
        bytes <= limits.disk_bytes && stat.f_files <= u64::from(limits.files),
        "Tmpfs quotas exceed requested limits"
    );
    let source = files::open_directory(Path::new("/audit/source"))?;
    root_owned(&source.metadata()?)?;
    let membership = String::from_utf8(files::read_limited(
        &process_directory().join("cgroup"),
        4096,
    )?)?;
    let mut lines = membership.lines();
    let path = lines
        .next()
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(|| invalid("Unified cgroup v2 required"))?;
    ensure!(
        lines.next().is_none() && path.starts_with('/'),
        "Ambiguous cgroup membership"
    );
    let relative = path.trim_start_matches('/');
    if !relative.is_empty() {
        validate_path(relative)?;
    }
    let cgroup = files::open_directory(&Path::new("/sys/fs/cgroup").join(relative))?;
    // SAFETY: cgroup is a live directory descriptor and stat is valid writable storage.
    if unsafe { libc::fstatfs(cgroup.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        stat.f_type == libc::CGROUP2_SUPER_MAGIC,
        "Native cgroup v2 controls required"
    );
    let memory = finite_number(&read_control(&cgroup, "memory.max")?, "memory.max")?;
    ensure!(
        memory > 0 && memory <= limits.memory_bytes,
        "Insufficient cgroup memory limit"
    );
    verify_cpu_max(&read_control(&cgroup, "cpu.max")?)?;
    let processes = finite_number(&read_control(&cgroup, "pids.max")?, "pids.max")?;
    ensure!(
        processes > 0 && processes <= 2048,
        "Insufficient aggregate cgroup process limit"
    );
    Ok((scratch, source, cgroup))
}

fn process_directory() -> PathBuf {
    Path::new("/proc").join(std::process::id().to_string())
}

fn read_control(root: &File, name: &str) -> Result<String> {
    let file = files::open_child(root, name.as_ref(), false)?;
    Ok(String::from_utf8(files::read_file(file, 4096)?)?)
}

fn finite_number(value: &str, name: &str) -> Result<u64> {
    value
        .trim()
        .parse()
        .map_err(|_| invalid(format!("Finite {name} limit required")))
}

fn verify_cpu_max(value: &str) -> Result<()> {
    let fields: Vec<_> = value.split_whitespace().collect();
    ensure!(fields.len() == 2, "Invalid cpu.max");
    let quota = finite_number(fields[0], "cpu.max quota")?;
    let period = finite_number(fields[1], "cpu.max period")?;
    ensure!(
        quota > 0 && period > 0 && period <= 100_000 && quota <= period,
        "cpu.max requires at most one CPU and a period of at most 100 ms"
    );
    Ok(())
}

fn cpu_usage(root: &File) -> Result<u64> {
    let stat = read_control(root, "cpu.stat")?;
    let mut usage = None;
    for line in stat.lines() {
        if let Some(value) = line.strip_prefix("usage_usec ") {
            ensure!(usage.is_none(), "Duplicate CPU counter");
            usage = Some(finite_number(value, "cpu.stat usage_usec")?);
        }
    }
    usage.ok_or_else(|| invalid("Missing CPU counter"))
}

fn root_owned(metadata: &Metadata) -> Result<()> {
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "Image source not exclusively owned by root"
    );
    Ok(())
}

fn verify_source_ownership(root: &File, path: &str) -> Result<()> {
    let mut current = root.try_clone()?;
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        current = files::open_child(&current, part.as_ref(), index + 1 != parts.len())?;
        root_owned(&current.metadata()?)?;
    }
    Ok(())
}

fn open_relative(root: &File, path: &str) -> Result<File> {
    validate_path(path)?;
    let mut current = root.try_clone()?;
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        current = files::open_child(&current, part.as_ref(), index + 1 != parts.len())?;
    }
    Ok(current)
}

fn create_directory(parent: &File, name: &str, allow_existing: bool) -> Result<File> {
    identifier_component(name)?;
    let name_c = CString::new(name)?;
    // SAFETY: parent is pinned and name_c is one NUL-terminated component.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        if !allow_existing || error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error.into());
        }
    }
    let directory = files::open_child(parent, name.as_ref(), true)?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        directory.metadata()?.uid() == unsafe { libc::geteuid() },
        "Scratch directory owner mismatch"
    );
    Ok(directory)
}

fn identifier_component(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0'),
        "Invalid component"
    );
    Ok(())
}

fn copy_source(source: &File, work: &File, entry: &SourceFile) -> Result<()> {
    let source_file = open_relative(source, &entry.path)?;
    let metadata = source_file.metadata()?;
    ensure!(
        metadata.nlink() == 1 && metadata.len() == entry.size,
        "Source type or size mismatch"
    );
    let bytes = read_stable(source_file, entry.size)?;
    ensure!(files::hash(&bytes) == entry.sha256, "Source hash mismatch");
    let mut parent = work.try_clone()?;
    let mut parts = entry.path.split('/').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_some() {
            parent = create_directory(&parent, part, true)?;
        } else {
            let name = CString::new(part)?;
            let mode = if metadata.mode() & 0o111 == 0 {
                0o600
            } else {
                0o700
            };
            // SAFETY: parent is pinned and name is a single valid component; new descriptor owns a new file.
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    mode,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: fd is a fresh descriptor transferred exactly once.
            let mut destination = unsafe { File::from_raw_fd(fd) };
            destination.write_all(&bytes)?;
        }
    }
    Ok(())
}

fn read_artifact(root: &File, path: &str, limit: u64) -> Result<Vec<u8>> {
    read_stable(open_relative(root, path)?, limit)
}

fn read_stable(file: File, limit: u64) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1 && before.len() <= limit && limit <= ARTIFACT_LIMIT,
        "Artifact type, links or volume rejected"
    );
    let mut bytes = Vec::new();
    let mut reader = file.take(limit + 1);
    reader.read_to_end(&mut bytes)?;
    let after = reader.get_ref().metadata()?;
    ensure!(
        same_file(&before, &after)
            && bytes.len() as u64 == before.len()
            && bytes.len() as u64 <= limit,
        "Artifact changed during reading"
    );
    Ok(bytes)
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.nlink() == 1
        && after.nlink() == 1
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

struct Captured {
    exit_code: i32,
    timed_out: bool,
    output_limited: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

static EXECUTION_LOCK: Mutex<()> = Mutex::new(());
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupted(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

struct ProcessScope {
    previous_subreaper: libc::c_int,
    handlers: Vec<(libc::c_int, libc::sigaction)>,
}

impl ProcessScope {
    fn enter() -> Result<Self> {
        let mut previous_subreaper = 0;
        // SAFETY: GET writes an integer through the valid pointer; SET accepts a scalar boolean.
        if unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &mut previous_subreaper,
                0,
                0,
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut scope = Self {
            previous_subreaper,
            handlers: Vec::new(),
        };
        INTERRUPTED.store(false, Ordering::Relaxed);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGCHLD] {
            // SAFETY: zero is a valid empty initial sigaction; sigemptyset fills its mask.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = if signal == libc::SIGCHLD {
                // Retain exited children until our own reap: a confirmed child PID
                // must not be recycled between waitid(WNOWAIT) and its positive kill.
                libc::SIG_DFL
            } else {
                interrupted as *const () as usize
            };
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            // SAFETY: pointers reference initialized sigaction structures, signal is catchable.
            if unsafe { libc::sigaction(signal, &action, &mut old) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            scope.handlers.push((signal, old));
        }
        // Verify the native children interface before a target can start.
        direct_children()?;
        Ok(scope)
    }
}

impl Drop for ProcessScope {
    fn drop(&mut self) {
        for (signal, action) in &self.handlers {
            // SAFETY: restoring the previously retrieved handler while its structure is live.
            unsafe {
                libc::sigaction(*signal, action, std::ptr::null_mut());
            }
        }
        // SAFETY: restore the previously observed scalar subreaper setting.
        unsafe {
            libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                self.previous_subreaper,
                0,
                0,
                0,
            );
        }
    }
}

struct GroupGuard {
    child: Child,
    stopped: bool,
    cleanup_started: Option<Instant>,
}

impl GroupGuard {
    fn stop(&mut self) -> Result<()> {
        let start = *self.cleanup_started.get_or_insert_with(Instant::now);
        stop_group(self.child.id() as i32, start)?;
        self.stopped = true;
        Ok(())
    }
}

fn stop_group(group: i32, start: Instant) -> Result<()> {
    loop {
        if group_children_absent(group)? {
            return Ok(());
        }
        ensure!(
            start.elapsed() < Duration::from_secs(2),
            "Complete descendant termination not established"
        );
        for pid in direct_children()? {
            ensure!(
                start.elapsed() < Duration::from_secs(2),
                "Complete descendant termination not established"
            );
            kill_owned_group_child(pid, group)?;
        }
        loop {
            ensure!(
                start.elapsed() < Duration::from_secs(2),
                "Complete descendant termination not established"
            );
            let mut status = 0;
            // SAFETY: only children in this invocation's immutable group are
            // reaped; __WALL includes clone children that do not send SIGCHLD.
            let reaped =
                unsafe { libc::waitpid(-group, &mut status, libc::WNOHANG | libc::__WALL) };
            if reaped > 0 {
                continue;
            }
            if reaped < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                if error.raw_os_error() != Some(libc::ECHILD) {
                    return Err(error.into());
                }
            }
            break;
        }
        // /proc children can omit members during concurrent exits. Only the
        // kernel's ECHILD establishes quiescence. Each remaining descendant
        // has a direct ancestor here, or is adopted here before that ancestor
        // becomes waitable; the inherited seccomp filter forbids group escape.
        if group_children_absent(group)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn direct_children() -> Result<BTreeSet<i32>> {
    let process = process_directory();
    let root = files::open_directory(&process)?;
    // SAFETY: root is a live descriptor and stat points to initialized storage.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(root.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        stat.f_type == libc::PROC_SUPER_MAGIC,
        "Native procfs child inventory required"
    );
    let mut children = BTreeSet::new();
    let mut read_threads = 0;
    for (index, entry) in std::fs::read_dir(process.join("task"))?.enumerate() {
        ensure!(index < 2048, "Too many worker threads");
        let entry = entry?;
        let name = entry.file_name();
        ensure!(
            name.to_str()
                .is_some_and(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit())),
            "Invalid procfs thread identity"
        );
        let bytes = match files::read_limited(&entry.path().join("children"), 64 * 1024) {
            Ok(bytes) => bytes,
            // A trusted worker thread can finish during enumeration. This cannot
            // establish quiescence: waitid(P_PGID) independently checks survivors.
            Err(error) if disappeared_proc_thread(&error) => continue,
            Err(error) => return Err(error),
        };
        read_threads += 1;
        for word in std::str::from_utf8(&bytes)
            .map_err(|_| invalid("Child list is not UTF-8"))?
            .split_whitespace()
        {
            let pid: i32 = word.parse().map_err(|_| invalid("Invalid child PID"))?;
            ensure!(
                pid > 0 && children.len() < 2048,
                "Child list exceeds limits"
            );
            children.insert(pid);
        }
    }
    ensure!(read_threads > 0, "Procfs child list unavailable");
    Ok(children)
}

fn disappeared_proc_thread(error: &crate::error::Error) -> bool {
    let mut cause = error;
    while let crate::error::Error::Context { source, .. } = cause {
        cause = source;
    }
    matches!(cause, crate::error::Error::PathIo { source, .. } if source.raw_os_error() == Some(libc::ENOENT))
}

fn kill_owned_group_child(pid: i32, group: i32) -> Result<()> {
    ensure!(pid > 0 && group > 0, "Positive PID and group required");
    // SAFETY: initialized siginfo storage, positive PID, and WNOWAIT retain any
    // exited child. No reap occurs between this ownership proof and the signal.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as u32,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
        )
    } < 0
    {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        return Err(error.into());
    }
    // SAFETY: the confirmed child's PID remains allocated until our later reap.
    let observed_group = unsafe { libc::getpgid(pid) };
    if observed_group < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if observed_group != group {
        return Ok(());
    }
    // A zombie requires only reaping; other workers' children are never signaled.
    if unsafe { info.si_pid() } != 0 {
        return Ok(());
    }
    // SAFETY: pid is a positive, unreaped direct child in this invocation's group.
    if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error.into());
        }
    }
    Ok(())
}

fn group_children_absent(group: i32) -> Result<bool> {
    ensure!(group > 0, "Positive group required");
    // SAFETY: this observes only the invocation's children without reaping them.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PGID,
            group as u32,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
        )
    };
    if result == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ECHILD) {
        return Ok(true);
    }
    Err(error.into())
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.stop();
        }
    }
}

fn run_target(
    request: &WorkerRequest,
    work: &Path,
    producer: &Path,
    timeout: Duration,
) -> Result<Captured> {
    let _lock = EXECUTION_LOCK
        .lock()
        .map_err(|_| invalid("Concurrent or interrupted worker"))?;
    let _scope = ProcessScope::enter()?;
    let mut command = Command::new(&request.command[0]);
    command
        .args(&request.command[1..])
        .current_dir(work)
        .env_clear()
        .env("PATH", "/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    for (name, directory) in [
        ("HOME", "home"),
        ("TMPDIR", "tmp"),
        ("CARGO_HOME", "cargo"),
        ("CARGO_TARGET_DIR", "target"),
        ("XDG_CACHE_HOME", "cache"),
        ("ZIG_GLOBAL_CACHE_DIR", "zig"),
    ] {
        command.env(name, producer.join(directory));
    }
    let limits = request.limits.clone();
    // SAFETY: this closure only invokes async-signal-safe libc operations before exec.
    unsafe {
        command.pre_exec(move || {
            apply_limit(libc::RLIMIT_CPU, limits.cpu_seconds)?;
            apply_limit(libc::RLIMIT_AS, limits.memory_bytes)?;
            apply_limit(libc::RLIMIT_NPROC, u64::from(limits.processes))?;
            apply_limit(libc::RLIMIT_NOFILE, u64::from(limits.files).min(1024))?;
            apply_limit(libc::RLIMIT_FSIZE, limits.disk_bytes)?;
            apply_limit(libc::RLIMIT_CORE, 0)?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            install_child_filter()
        });
    }
    let start = Instant::now();
    let child = command.spawn()?;
    let mut guard = GroupGuard {
        child,
        stopped: false,
        cleanup_started: None,
    };
    let mut out = guard
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("Missing stdout pipe"))?;
    let mut err = guard
        .child
        .stderr
        .take()
        .ok_or_else(|| invalid("Missing stderr pipe"))?;
    set_nonblocking(&out)?;
    set_nonblocking(&err)?;
    let mut captured = Captured {
        exit_code: 137,
        timed_out: false,
        output_limited: false,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    loop {
        captured.output_limited |= drain(&mut out, &mut captured.stdout)?;
        captured.output_limited |= drain(&mut err, &mut captured.stderr)?;
        if let Some(status) = guard.child.try_wait()? {
            captured.exit_code = status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
            break;
        }
        captured.timed_out = start.elapsed() >= timeout;
        if captured.timed_out || captured.output_limited || INTERRUPTED.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    guard.stop()?;
    // Every writer has now terminated. A final read is bounded and cannot hang.
    captured.output_limited |= drain_after_stop(&mut out, &mut captured.stdout)?;
    captured.output_limited |= drain_after_stop(&mut err, &mut captured.stderr)?;
    ensure!(
        !INTERRUPTED.load(Ordering::Relaxed),
        "Worker interrupted; descendants terminated"
    );
    Ok(captured)
}

fn apply_limit(resource: libc::__rlimit_resource_t, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: resource is a known resource constant and limit points to initialized scalars.
    if unsafe { libc::setrlimit(resource, &limit) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_child_filter() -> std::io::Result<()> {
    fn statement(code: u16, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }
    fn jump(code: u16, value: u32, yes: u8, no: u8) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: yes,
            jf: no,
            k: value,
        }
    }
    // seccomp_data offsets: syscall number 0, architecture 4. Unknown arch and
    // the x32 syscall namespace are killed, so neither can bypass the deny list.
    let filter = [
        statement(0x20, 4),
        jump(0x15, 0xc000_003e, 1, 0),
        statement(0x06, 0x8000_0000),
        statement(0x20, 0),
        jump(0x35, 0x4000_0000, 0, 1),
        statement(0x06, 0x8000_0000),
        jump(0x15, libc::SYS_setsid as u32, 0, 1),
        statement(0x06, 0x0005_0000 | libc::EPERM as u32),
        jump(0x15, libc::SYS_setpgid as u32, 0, 1),
        statement(0x06, 0x0005_0000 | libc::EPERM as u32),
        jump(0x15, libc::SYS_unshare as u32, 0, 1),
        statement(0x06, 0x0005_0000 | libc::EPERM as u32),
        jump(0x15, libc::SYS_setns as u32, 0, 1),
        statement(0x06, 0x0005_0000 | libc::EPERM as u32),
        // Classic BPF cannot inspect the pointer argument of clone3. ENOSYS
        // lets libc retry clone for ordinary threads without permitting namespaces.
        jump(0x15, libc::SYS_clone3 as u32, 0, 1),
        statement(0x06, 0x0005_0000 | libc::ENOSYS as u32),
        jump(0x15, libc::SYS_clone as u32, 0, 3),
        statement(0x20, 16),
        jump(0x45, 0x7e02_0080, 0, 1), // Every CLONE_NEW* flag, including CLONE_NEWTIME.
        statement(0x06, 0x0005_0000 | libc::EPERM as u32),
        statement(0x06, 0x7fff_0000),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: program references the initialized BPF array for the synchronous kernel copy.
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn install_child_filter() -> std::io::Result<()> {
    Err(std::io::Error::other("Unsupported seccomp architecture"))
}

fn set_nonblocking(stream: &impl AsRawFd) -> Result<()> {
    let fd = stream.as_raw_fd();
    // SAFETY: the borrowed stream owns fd throughout both fcntl calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn drain(stream: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    let mut buffer = [0; 8192];
    // A continuously writing producer must not starve deadline checks.
    for _ in 0..8 {
        match stream.read(&mut buffer) {
            Ok(0) => return Ok(false),
            Ok(read) => {
                let accepted = read.min(LOG_LIMIT.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&buffer[..accepted]);
                if accepted < read {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

fn drain_after_stop(stream: &mut impl Read, bytes: &mut Vec<u8>) -> Result<bool> {
    loop {
        let before = bytes.len();
        if drain(stream, bytes)? {
            return Ok(true);
        }
        if before == bytes.len() {
            return Ok(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path, time::Duration};

    fn isolated_worker_test(name: &str) -> Result<bool> {
        const MARKER: &str = "LADYSHELL_ISOLATED_WORKER_TEST";
        if std::env::var(MARKER).ok().as_deref() == Some(name) {
            return Ok(false);
        }
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                &format!("audit::worker::tests::{name}"),
                "--nocapture",
            ])
            .env(MARKER, name)
            .output()?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(true)
    }

    fn inherited_signal_filter() -> Result<()> {
        let statement = |code, k| libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        };
        let jump = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
        let filter = [
            statement(0x20, 0),
            jump(0x15, libc::SYS_pidfd_open as u32, 0, 1),
            statement(0x06, 0x0005_0000 | libc::ENOSYS as u32),
            jump(0x15, libc::SYS_kill as u32, 0, 5),
            statement(0x20, 16),
            jump(0x15, 0, 0, 1),
            statement(0x06, 0x0005_0000 | libc::EPERM as u32),
            jump(0x45, 1 << 31, 0, 1),
            statement(0x06, 0x0005_0000 | libc::EPERM as u32),
            statement(0x06, 0x7fff_0000),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: only this isolated test process installs the valid stack-local filter.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
            || unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program, 0, 0) } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    #[test]
    fn inherited_group_signal_denial_does_not_block_worker_cleanup() -> Result<()> {
        if isolated_worker_test("inherited_group_signal_denial_does_not_block_worker_cleanup")? {
            return Ok(());
        }
        inherited_signal_filter()?;
        // SAFETY: signal zero only probes that the inherited group restriction is active.
        assert_eq!(unsafe { libc::kill(0, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        let directory = tempfile::tempdir()?;
        let captured = run_target(
            &request("printf worker-ok"),
            directory.path(),
            directory.path(),
            Duration::from_secs(1),
        )?;
        assert_eq!(captured.exit_code, 0);
        assert_eq!(captured.stdout, b"worker-ok");
        Ok(())
    }

    #[test]
    fn current_process_controls_open_without_following_proc_self_symlink() -> Result<()> {
        let bytes = files::read_limited(&process_directory().join("cgroup"), 4096)?;
        assert!(!bytes.is_empty());
        Ok(())
    }

    #[test]
    fn vanished_thread_read_recognizes_wrapped_enoent_but_preserves_other_errors() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = files::read_limited(&directory.path().join("children"), 64 * 1024)
            .err()
            .ok_or_else(|| invalid("Fixture must be absent"))?;
        // open_regular wraps this real ENOENT in contextual validation information.
        assert!(disappeared_proc_thread(&missing));
        assert!(disappeared_proc_thread(
            &missing.context("Additional context")
        ));
        for errno in [
            libc::EACCES,
            libc::EPERM,
            libc::ELOOP,
            libc::ENOTDIR,
            libc::EIO,
        ] {
            let error = crate::error::Error::PathIo {
                path: directory.path().join("children"),
                source: std::io::Error::from_raw_os_error(errno),
            }
            .context("Reading children");
            assert!(!disappeared_proc_thread(&error), "masked errno {errno}");
        }
        assert!(!disappeared_proc_thread(&invalid("File too large")));
        Ok(())
    }

    #[test]
    fn proc_child_inventory_tolerates_concurrent_thread_exit() -> Result<()> {
        thread::scope(|scope| -> Result<()> {
            scope.spawn(|| {
                for _ in 0..16 {
                    thread::scope(|wave| {
                        for _ in 0..16 {
                            wave.spawn(thread::yield_now);
                        }
                    });
                }
            });
            for _ in 0..128 {
                direct_children()?;
            }
            Ok(())
        })
    }

    #[test]
    fn inherited_filter_cleanup_reaps_adopted_generations_and_preserves_other_children(
    ) -> Result<()> {
        if isolated_worker_test(
            "inherited_filter_cleanup_reaps_adopted_generations_and_preserves_other_children",
        )? {
            return Ok(());
        }
        inherited_signal_filter()?;
        struct ForeignChild(Child);
        impl Drop for ForeignChild {
            fn drop(&mut self) {
                // SAFETY: this dedicated test fixture owns its unreaped child PID.
                unsafe {
                    libc::kill(self.0.id() as i32, libc::SIGKILL);
                }
                let _ = self.0.wait();
            }
        }
        let mut foreign = ForeignChild(
            Command::new("/bin/bash")
                .args(["-c", "while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()?,
        );
        let directory = tempfile::tempdir()?;
        let request = request("printf '%s' \"$$\" > leader; (printf '%s' \"$BASHPID\" > child; (printf '%s' \"$BASHPID\" > grandchild; while :; do :; done) & wait) & wait");
        let result = run_target(
            &request,
            directory.path(),
            directory.path(),
            Duration::from_millis(250),
        )?;
        assert!(result.timed_out);
        for name in ["leader", "child", "grandchild"] {
            assert_gone(&directory.path().join(name))?;
        }
        assert!(
            foreign.0.try_wait()?.is_none(),
            "unrelated child was killed"
        );
        Ok(())
    }

    #[test]
    fn inherited_filter_cleanup_handles_clone_parent_children() -> Result<()> {
        if isolated_worker_test("inherited_filter_cleanup_handles_clone_parent_children")? {
            return Ok(());
        }
        inherited_signal_filter()?;
        let _scope = ProcessScope::enter()?;
        let mut pipe = [-1; 2];
        // SAFETY: the array holds both newly created descriptors.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: each successful pipe descriptor is transferred exactly once.
        let mut read = unsafe { File::from_raw_fd(pipe[0]) };
        let write = unsafe { File::from_raw_fd(pipe[1]) };
        // SAFETY: the child only performs libc calls and stack-local filter setup before _exit.
        let leader = unsafe { libc::fork() };
        if leader < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if leader == 0 {
            // SAFETY: all operations affect only this isolated synthetic process or its child.
            unsafe {
                libc::close(read.as_raw_fd());
                if libc::setpgid(0, 0) < 0 || install_child_filter().is_err() {
                    libc::_exit(91);
                }
                let child = libc::syscall(
                    libc::SYS_clone,
                    libc::CLONE_PARENT as u64,
                    0usize,
                    0usize,
                    0usize,
                    0usize,
                ) as i32;
                if child == 0 {
                    libc::close(write.as_raw_fd());
                    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                    loop {
                        libc::pause();
                    }
                }
                libc::write(
                    write.as_raw_fd(),
                    (&child as *const i32).cast(),
                    std::mem::size_of::<i32>(),
                );
                libc::close(write.as_raw_fd());
                loop {
                    libc::pause();
                }
            }
        }
        drop(write);
        let mut bytes = [0; 4];
        read.read_exact(&mut bytes)?;
        let clone_child = i32::from_ne_bytes(bytes);
        let result = stop_group(leader, Instant::now());
        let gone_before_fallback: Vec<_> = [leader, clone_child]
            .into_iter()
            .map(|pid| {
                // SAFETY: signal zero only observes the synthetic PID before fallback cleanup.
                (unsafe { libc::kill(pid, 0) }) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            })
            .collect();
        // Independent positive-PID cleanup keeps the fixture safe if group logic regresses.
        for pid in [leader, clone_child] {
            if pid > 0 {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: WNOWAIT proves direct-child ownership before any fallback signal.
                unsafe {
                    if libc::waitid(
                        libc::P_PID,
                        pid as u32,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                    ) == 0
                    {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), libc::__WALL);
                    }
                }
            }
        }
        assert!(clone_child > 0, "CLONE_PARENT fixture failed");
        result?;
        assert!(
            gone_before_fallback.into_iter().all(|gone| gone),
            "descendant survived stop_group"
        );
        for pid in [leader, clone_child] {
            // SAFETY: signal zero observes only the recorded fixture PID.
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
        Ok(())
    }

    #[test]
    fn inherited_filter_cleanup_reaps_a_non_sigchld_clone_child() -> Result<()> {
        if isolated_worker_test("inherited_filter_cleanup_reaps_a_non_sigchld_clone_child")? {
            return Ok(());
        }
        inherited_signal_filter()?;
        let _scope = ProcessScope::enter()?;
        let mut pipe = [-1; 2];
        // SAFETY: the array owns the new pipe descriptors after success.
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: each successful descriptor is transferred exactly once.
        let mut read = unsafe { File::from_raw_fd(pipe[0]) };
        let write = unsafe { File::from_raw_fd(pipe[1]) };
        // SAFETY: flags zero produce a separate address space and no SIGCHLD on exit;
        // the child only calls libc and stack-local filter setup before termination.
        let pid = unsafe { libc::syscall(libc::SYS_clone, 0usize, 0usize, 0usize, 0usize, 0usize) }
            as i32;
        if pid < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if pid == 0 {
            // SAFETY: all mutations are confined to this synthetic child.
            unsafe {
                libc::close(read.as_raw_fd());
                if libc::setpgid(0, 0) < 0 || install_child_filter().is_err() {
                    libc::_exit(91);
                }
                libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1);
                libc::close(write.as_raw_fd());
                loop {
                    libc::pause();
                }
            }
        }
        drop(write);
        let mut ready = [0];
        read.read_exact(&mut ready)?;
        // SAFETY: prove that ordinary wait cannot see this particular live clone child.
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        let result = stop_group(pid, Instant::now());
        // SAFETY: capture the observable result before fallback can hide a failure.
        let gone = (unsafe { libc::kill(pid, 0) }) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: the fallback only signals a child whose unreaped identity is confirmed.
        unsafe {
            if libc::waitid(
                libc::P_PID,
                pid as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            ) == 0
            {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), libc::__WALL);
            }
        }
        result?;
        assert!(gone, "non-SIGCHLD child survived cleanup");
        Ok(())
    }

    #[test]
    fn worker_overrides_sigchld_ignore_and_no_cldwait_during_capture() -> Result<()> {
        if isolated_worker_test("worker_overrides_sigchld_ignore_and_no_cldwait_during_capture")? {
            return Ok(());
        }
        // SAFETY: this isolated test starts with explicit auto-reaping to exercise the guard.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        action.sa_flags = libc::SA_NOCLDWAIT;
        if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let directory = tempfile::tempdir()?;
        let result = run_target(
            &request("printf '%s' \"$$\" > leader; exit 37"),
            directory.path(),
            directory.path(),
            Duration::from_secs(1),
        )?;
        assert_eq!(result.exit_code, 37);
        assert_gone(&directory.path().join("leader"))?;
        Ok(())
    }

    fn request(script: &str) -> WorkerRequest {
        WorkerRequest {
            schema_version: 1,
            invocation_id: "unit-test".into(),
            command: vec!["/bin/bash".into(), "-c".into(), script.into()],
            limits: Limits {
                cpu_seconds: 10,
                memory_bytes: 256 * 1024 * 1024,
                processes: 2048,
                files: 128,
                disk_bytes: 1024 * 1024,
            },
            timeout_seconds: 5,
            sources: vec![],
            artifacts: vec![],
        }
    }

    fn assert_gone(path: &Path) -> Result<()> {
        let pid: i32 = fs::read_to_string(path)?
            .trim()
            .parse()
            .map_err(|_| invalid("Invalid synthetic PID"))?;
        // SAFETY: signal zero only observes existence of the recorded synthetic process.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "process {pid} survived");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        Ok(())
    }

    #[test]
    fn timeout_kills_and_reaps_target_and_background_descendant() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let request = request("printf '%s' \"$$\" > leader; (printf '%s' \"$BASHPID\" > descendant; while :; do :; done) & wait");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_millis(100))?;
        assert!(result.timed_out);
        assert_gone(&dir.path().join("leader"))?;
        assert_gone(&dir.path().join("descendant"))
    }

    #[test]
    fn leader_exit_stops_descendants_even_when_they_hold_output_pipes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        // Redirection creates the PID file before printf writes it; publish readiness separately.
        let request = request("(printf '%s' \"$BASHPID\" > descendant && : > descendant-ready; while :; do :; done) & while [[ ! -f descendant-ready ]]; do :; done; exit 37");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_secs(2))?;
        assert_eq!(result.exit_code, 37);
        assert!(!result.timed_out);
        assert_gone(&dir.path().join("descendant"))
    }

    #[test]
    fn cleanup_handles_a_leader_already_reaped_by_the_group_wait() -> Result<()> {
        let _lock = EXECUTION_LOCK
            .lock()
            .map_err(|_| invalid("Test lock poisoned"))?;
        let _scope = ProcessScope::enter()?;
        let directory = tempfile::tempdir()?;
        let child = Command::new("/bin/bash")
            .args(["-c", "(printf '%s' \"$BASHPID\" > descendant && : > descendant-ready; while :; do :; done) & while [[ ! -f descendant-ready ]]; do :; done"])
            .current_dir(directory.path())
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .process_group(0).spawn()?;
        let mut guard = GroupGuard {
            child,
            stopped: false,
            cleanup_started: None,
        };
        let leader = guard.child.id() as i32;
        let mut status = 0;
        // SAFETY: simulate waitpid(-pgid) reaping the leader before Child::try_wait.
        assert_eq!(unsafe { libc::waitpid(leader, &mut status, 0) }, leader);
        let result = guard.stop();
        // Keep the negative test itself leak-free if the guard regresses.
        // SAFETY: only our synthetic group is killed and reaped.
        unsafe {
            libc::kill(-leader, libc::SIGKILL);
            while libc::waitpid(-leader, &mut status, 0) > 0 {}
        }
        assert_gone(&directory.path().join("descendant"))?;
        result
    }

    #[test]
    fn output_flood_is_bounded_and_the_producer_is_reaped() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let request = request("printf '%s' \"$$\" > leader; while :; do printf '%8192s' x; done");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_secs(2))?;
        assert!(result.output_limited);
        assert_eq!(result.stdout.len(), LOG_LIMIT);
        assert_gone(&dir.path().join("leader"))
    }

    #[test]
    fn target_receives_a_clean_environment_and_cannot_spoof_receipt_stdout() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let request = request("printf '%s\\n' '{\"stopped\":true}'; printf '%s\\n' \"$PATH\" \"$HOME\" \"$TMPDIR\" \"${USER-unset}\" >&2");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_secs(2))?;
        assert_eq!(result.stdout, b"{\"stopped\":true}\n");
        let stderr = String::from_utf8(result.stderr)?;
        assert!(stderr.starts_with("/bin\n"));
        assert!(stderr.ends_with("\nunset\n"));
        assert!(stderr.contains(&dir.path().display().to_string()));
        Ok(())
    }

    #[test]
    fn nondumpable_worker_prevents_reopening_its_control_pipe() -> Result<()> {
        const PROBE: &str = "LADYSHELL_TEST_WORKER_CONTROL_PIPE";
        if std::env::var_os(PROBE).is_none() {
            // The synthetic worker runs in a separate test process because making a
            // process nondumpable is an intentional, irreversible production guard.
            let result = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "audit::worker::tests::nondumpable_worker_prevents_reopening_its_control_pipe",
                    "--nocapture",
                ])
                .env(PROBE, "1")
                .output()?;
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(!String::from_utf8_lossy(&result.stdout).contains("forged-control-response"));
            return Ok(());
        }
        protect_worker()?;
        let directory = tempfile::tempdir()?;
        let request =
            request("printf forged-control-response > /proc/$PPID/fd/1; printf '%s' \"$?\"");
        let captured = run_target(
            &request,
            directory.path(),
            directory.path(),
            Duration::from_secs(2),
        )?;
        assert_eq!(captured.stdout, b"1");
        assert!(String::from_utf8_lossy(&captured.stderr).contains("Permission denied"));
        Ok(())
    }

    #[test]
    fn rejects_artifact_symlinks_hardlinks_special_files_and_changed_bytes() -> Result<()> {
        use std::os::unix::{ffi::OsStrExt, fs::symlink};
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("regular"), b"ok")?;
        fs::hard_link(dir.path().join("regular"), dir.path().join("hard"))?;
        symlink("regular", dir.path().join("link"))?;
        fs::create_dir(dir.path().join("sub"))?;
        symlink("sub", dir.path().join("ancestor"))?;
        fs::write(dir.path().join("sub/result"), b"ok")?;
        let fifo = std::ffi::CString::new(dir.path().join("fifo").as_os_str().as_bytes())?;
        // SAFETY: fifo is a valid, owned NUL-terminated path in the private test directory.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let root = crate::files::open_directory(dir.path())?;
        for path in ["hard", "link", "fifo", "ancestor/result"] {
            assert!(read_artifact(&root, path, 1024).is_err(), "accepted {path}");
        }
        fs::write(dir.path().join("large"), [0; 1025])?;
        assert!(read_artifact(&root, "large", 1024).is_err());
        let before = fs::metadata(dir.path().join("large"))?;
        fs::write(dir.path().join("large"), b"changed")?;
        let after = fs::metadata(dir.path().join("large"))?;
        assert!(!same_file(&before, &after));
        assert_eq!(read_artifact(&root, "sub/result", 1024)?, b"ok");
        Ok(())
    }

    #[test]
    fn source_copy_checks_content_and_never_overwrites_existing_files() -> Result<()> {
        let source = tempfile::tempdir()?;
        let destination = tempfile::tempdir()?;
        fs::write(source.path().join("file"), b"original")?;
        let source_root = crate::files::open_directory(source.path())?;
        let work_root = crate::files::open_directory(destination.path())?;
        let entry = SourceFile {
            path: "file".into(),
            size: 8,
            sha256: crate::files::hash(b"original"),
        };
        let mut changed = entry.clone();
        changed.sha256 = "0".repeat(64);
        assert!(copy_source(&source_root, &work_root, &changed).is_err());
        assert!(!destination.path().join("file").exists());
        copy_source(&source_root, &work_root, &entry)?;
        assert_eq!(fs::read(destination.path().join("file"))?, b"original");
        assert!(copy_source(&source_root, &work_root, &entry).is_err());
        Ok(())
    }

    #[test]
    fn captures_all_buffered_output_after_the_process_group_stops() -> Result<()> {
        let mut stream = std::io::Cursor::new(vec![b'x'; 128 * 1024]);
        let mut bytes = Vec::new();
        assert!(!drain_after_stop(&mut stream, &mut bytes)?);
        assert_eq!(bytes.len(), 128 * 1024);
        Ok(())
    }

    #[test]
    fn interrupted_worker_stops_and_reaps_the_target_before_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let request =
            request("printf '%s' \"$$\" > leader; kill -TERM \"$PPID\"; while :; do :; done");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_secs(1));
        assert!(result.is_err());
        assert_gone(&dir.path().join("leader"))
    }

    #[test]
    fn detached_session_attempt_fails_and_descendant_cannot_survive() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let request = request("setsid /bin/bash -c 'printf escaped > escaped' 2>setsid-error; printf '%s' \"$?\" > setsid-status; (printf '%s' \"$BASHPID\" > descendant && : > descendant-ready; while :; do :; done) & while [[ ! -f descendant-ready ]]; do :; done");
        let result = run_target(&request, dir.path(), dir.path(), Duration::from_secs(2))?;
        assert_eq!(result.exit_code, 0);
        assert_eq!(fs::read_to_string(dir.path().join("setsid-status"))?, "1");
        assert!(fs::read_to_string(dir.path().join("setsid-error"))?
            .contains("Operation not permitted"));
        assert!(!dir.path().join("escaped").exists());
        assert_gone(&dir.path().join("descendant"))
    }

    #[test]
    fn cpu_quota_parser_refuses_unbounded_or_bursting_cpu() -> Result<()> {
        verify_cpu_max("100000 100000\n")?;
        verify_cpu_max("10000 100000\n")?;
        for value in [
            "max 100000",
            "200000 100000",
            "1000000 1000000",
            "0 100000",
            "100000 0",
            "100000 100000 extra",
        ] {
            assert!(verify_cpu_max(value).is_err(), "accepted {value}");
        }
        Ok(())
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn seccomp_denies_both_process_group_escape_syscalls_and_compat_abis() -> Result<()> {
        for probe in 0..3 {
            // SAFETY: forked child only uses libc and stack-local seccomp setup, then _exit.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if pid == 0 {
                // SAFETY: only the isolated synthetic child is modified or terminated.
                unsafe {
                    if apply_limit(libc::RLIMIT_CORE, 0).is_err() {
                        libc::_exit(90);
                    }
                    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                        || install_child_filter().is_err()
                    {
                        libc::_exit(91);
                    }
                    if probe == 0 {
                        if libc::setsid() != -1 || *libc::__errno_location() != libc::EPERM {
                            libc::_exit(92);
                        }
                        if libc::setpgid(0, 0) != -1 || *libc::__errno_location() != libc::EPERM {
                            libc::_exit(93);
                        }
                        if libc::unshare(0) != -1 || *libc::__errno_location() != libc::EPERM {
                            libc::_exit(95);
                        }
                        if libc::setns(-1, 0) != -1 || *libc::__errno_location() != libc::EPERM {
                            libc::_exit(96);
                        }
                        if libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) != -1
                            || *libc::__errno_location() != libc::ENOSYS
                        {
                            libc::_exit(97);
                        }
                        libc::_exit(0);
                    }
                    if probe == 1 {
                        libc::syscall(libc::SYS_getpid | 0x4000_0000);
                    } else {
                        std::arch::asm!("int 0x80", inlateout("eax") 20u32 => _, options(nostack));
                    }
                    libc::_exit(94);
                }
            }
            let mut status = 0;
            // SAFETY: pid is the exact newly forked child, status is initialized storage.
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            if probe == 0 {
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
            } else {
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
            }
        }
        Ok(())
    }
}
