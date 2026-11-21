//! Isolated agents return proposals, never controller identities or receipts.
use super::invalid;
use crate::{
    config,
    error::{ensure, Result},
    json, state,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCheck {
    pub argv: Vec<String>,
    pub expected_exit: i32,
    pub expected_stdout: String,
    pub artifacts: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub finding_json: String,
    pub checks: Vec<TargetCheck>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResponse {
    pub summary: String,
    pub reviewed_paths: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub finding_json: Option<String>,
    pub unresolved: Vec<String>,
}
impl AgentResponse {
    fn validate(&self) -> Result<()> {
        if self.summary.is_empty()
            || self.summary.len() > 65536
            || self.reviewed_paths.len() > 5000
            || self.candidates.len() > 16
            || self.unresolved.len() > 128
            || self
                .unresolved
                .iter()
                .any(|s| s.is_empty() || s.len() > 8192)
        {
            return Err(invalid("Réponse d’agent hors limites"));
        }
        for p in &self.reviewed_paths {
            config::relative_path(p)?;
        }
        for candidate in &self.candidates {
            validate_finding(&candidate.finding_json)?;
            if candidate.checks.len() > 4 {
                return Err(invalid("Trop de reproductions proposées"));
            }
            for check in &candidate.checks {
                validate_check(check)?;
            }
        }
        if let Some(finding) = &self.finding_json {
            validate_finding(finding)?;
        }
        Ok(())
    }
}
pub fn validate_check(check: &TargetCheck) -> Result<()> {
    if check.argv.is_empty()
        || check.argv.len() > 128
        || check
            .argv
            .iter()
            .any(|s| s.is_empty() || s.len() > 4096 || s.contains('\0'))
        || check.expected_stdout.len() > 4096
        || !(0..=255).contains(&check.expected_exit)
        || check.artifacts.len() > 16
    {
        return Err(invalid("Commande cible proposée invalide"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for p in &check.artifacts {
        config::relative_path(p)?;
        if !seen.insert(p) {
            return Err(invalid("Artefact proposé dupliqué"));
        }
    }
    Ok(())
}
pub fn validate_finding(text: &str) -> Result<Value> {
    if text.len() > 1024 * 1024 {
        return Err(invalid("Résultat proposé trop volumineux"));
    }
    let finding = json::parse(text.as_bytes())?;
    crate::audit::validator::validate(
        crate::audit::validator::Mode::Findings,
        &serde_json::to_vec(&vec![&finding])?,
    )?;
    Ok(finding)
}
pub fn parse_transcript(bytes: &[u8]) -> Result<AgentResponse> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(invalid("Sortie d’agent trop volumineuse"));
    }
    let mut message = None;
    let mut complete = false;
    let mut started = false;
    let mut startup_warnings = std::collections::BTreeSet::new();
    for line in bytes.split(|b| *b == b'\n').filter(|s| !s.is_empty()) {
        let event = json::parse(line)?;
        if complete {
            return Err(invalid("Événement après clôture de l’invocation"));
        }
        match event["type"].as_str() {
            Some("turn.started") => started = true,
            Some("turn.completed") => {
                if !startup_warnings.is_empty() && !started {
                    return Err(invalid("Avertissement Codex sans début de tour"));
                }
                complete = true;
            }
            Some("error" | "turn.failed") => return Err(invalid("Invocation Codex échouée")),
            Some("item.completed") => {
                let item = &event["item"];
                match item["type"].as_str() {
                    Some("agent_message") => message = Some(state::text(item, "text")?.to_owned()),
                    Some("reasoning") => (),
                    Some("error") if !started && message.is_none() => {
                        // Codex 0.165.0 emits these two capability notices as error
                        // items before the turn. They attest disabled capabilities,
                        // not failed model work. Unknown or in-turn errors fail closed.
                        let warning = item["message"].as_str().unwrap_or("");
                        if ![
                            "Under-development features enabled: skip_host_skill_discovery. Under-development features are incomplete and may behave unpredictably. To suppress this warning, set `suppress_unstable_features_warning = true` in /audit/agent/.codex/config.toml.",
                            "Code Mode is unavailable because code-mode host is disabled. Code mode will fail closed; enable `features.code_mode_host` and install `codex-code-mode-host`.",
                        ].contains(&warning) || !startup_warnings.insert(warning.to_owned()) {
                            return Err(invalid("Avertissement ou erreur Codex non reconnu"));
                        }
                    }
                    _ => {
                        return Err(invalid(format!(
                            "Outil d’exécution interdit dans l’agent d’audit : type {:?}",
                            item["type"].as_str().unwrap_or("<absent ou non textuel>")
                        )))
                    }
                }
            }
            _ => (),
        }
    }
    if !complete {
        return Err(invalid("Invocation Codex sans clôture"));
    }
    let text = message.ok_or_else(|| invalid("Réponse Codex absente"))?;
    let response: AgentResponse = serde_json::from_value(json::parse(text.as_bytes())?)?;
    response.validate()?;
    Ok(response)
}

/// Immutable image helper; never reads host auth or executes target programs.
pub fn remote(
    codex: &std::path::Path,
    cpu_seconds: u64,
    processes: u32,
    file_bytes: u64,
) -> Result<()> {
    use std::{
        os::unix::process::CommandExt,
        path::Path,
        process::{Command, Stdio},
    };
    validate_remote_limits(cpu_seconds, processes, file_bytes)?;
    let path = codex
        .to_str()
        .ok_or_else(|| invalid("Chemin Codex non UTF-8"))?;
    crate::policy::native_policy(path)?;
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 10001
        || !Path::new("/audit/agent-response-schema.json").is_file()
    {
        return Err(invalid("Helper agent réservé à l’image d’audit"));
    }
    apply_remote_limits(cpu_seconds, processes, file_bytes)?;
    verify_agent_confinement(file_bytes)?;
    for p in [
        "/audit/agent/tmp",
        "/audit/agent/.codex",
        "/audit/agent/cache",
    ] {
        state::create_directory(Path::new(p))?;
    }
    let mut version = Command::new(codex);
    version.arg("--version");
    let version = crate::process::capture(version, std::time::Duration::from_secs(10), 1024)?;
    if String::from_utf8_lossy(&version).trim() != "codex-cli 0.165.0" {
        return Err(invalid(
            "Driver d’audit validé pour Codex 0.165.0 uniquement",
        ));
    }
    crate::auth::remote_prepare()?;
    let mut command = Command::new(codex);
    command.args([
        "--no-daemon",
        "--ask-for-approval",
        "never",
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "danger-full-access",
        "--cd",
        "/audit/agent",
        "--json",
        "--color",
        "never",
        "--output-schema",
        "/audit/agent-response-schema.json",
    ]);
    for setting in [
        "web_search=\"disabled\"", "project_doc_max_bytes=0", "mcp_servers={}", "allow_login_shell=false",
        "history.persistence=\"none\"", "analytics.enabled=false", "skills.include_instructions=false", "skills.bundled.enabled=false", "tools.update_plan.enabled=false",
        "features={shell_tool=false,shell_snapshot=false,code_mode=false,code_mode_host=false,apps=false,plugins=false,remote_plugin=false,hooks=false,multi_agent=false,multi_agent_v2=false,computer_use=false,browser_use=false,browser_use_external=false,image_generation=false,view_image=false,artifact=false,memories=false,workspace_dependencies=false,skill_search=false,skill_mcp_dependency_install=false,skip_host_skill_discovery=true,tool_suggest=false,goals=false,sleep_tool=false,daemon_auto_start=false,unbounded_connection_retries=false}",
    ] { command.args(["-c",setting]); }
    command
        .arg("-")
        .env("HOME", "/audit/agent")
        .env("CODEX_HOME", "/audit/agent/.codex")
        .env("TMPDIR", "/audit/agent/tmp")
        .env("XDG_CACHE_HOME", "/audit/agent/cache")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Err(command.exec().into())
}

fn apply_remote_limits(cpu_seconds: u64, processes: u32, file_bytes: u64) -> Result<()> {
    validate_remote_limits(cpu_seconds, processes, file_bytes)?;
    for (resource, requested) in [
        (libc::RLIMIT_CPU, cpu_seconds),
        (libc::RLIMIT_NPROC, u64::from(processes)),
        (libc::RLIMIT_FSIZE, file_bytes),
        (libc::RLIMIT_CORE, 0),
    ] {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: resource is a known constant and current points to initialized storage.
        if unsafe { libc::getrlimit(resource, &mut current) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let ceiling = requested.min(current.rlim_cur).min(current.rlim_max);
        let limit = libc::rlimit {
            rlim_cur: ceiling,
            rlim_max: ceiling,
        };
        // SAFETY: both limits only decrease for the current trusted helper and its descendants.
        if unsafe { libc::setrlimit(resource, &limit) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn validate_remote_limits(cpu_seconds: u64, processes: u32, file_bytes: u64) -> Result<()> {
    if cpu_seconds == 0
        || cpu_seconds == libc::RLIM_INFINITY
        || processes == 0
        || file_bytes == 0
        || file_bytes == libc::RLIM_INFINITY
    {
        return Err(invalid("Limites d’agent positives et finies obligatoires"));
    }
    Ok(())
}

fn verify_agent_confinement(file_bytes: u64) -> Result<()> {
    use std::{
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        path::Path,
    };
    let scratch = crate::files::open_directory(Path::new("/audit/agent"))?;
    let metadata = scratch.metadata()?;
    // SAFETY: scratch owns its descriptor and stat is valid writable storage.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(scratch.as_raw_fd(), &mut stat) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    validate_agent_scratch(metadata.uid(), metadata.mode(), &stat, file_bytes)?;
    verify_agent_access(&scratch, Path::new("/tmp"), Path::new("/audit/source"))
}

fn validate_agent_scratch(
    owner: u32,
    mode: u32,
    stat: &libc::statfs,
    file_bytes: u64,
) -> Result<()> {
    ensure!(
        owner == 10001 && mode & 0o7777 == 0o700,
        "Scratch agent privé UID10001 mode0700 obligatoire"
    );
    ensure!(
        stat.f_type == libc::TMPFS_MAGIC,
        "Scratch agent tmpfs obligatoire"
    );
    ensure!(
        stat.f_bsize > 0 && stat.f_blocks > 0 && stat.f_files > 0 && stat.f_files < u64::MAX,
        "Quotas tmpfs agent finis obligatoires"
    );
    let bytes = stat
        .f_blocks
        .checked_mul(stat.f_bsize as u64)
        .ok_or_else(|| invalid("Quota tmpfs agent débordant"))?;
    ensure!(
        bytes <= file_bytes,
        "Quota disque agent supérieur à la limite demandée"
    );
    Ok(())
}

fn verify_agent_access(
    scratch: &std::fs::File,
    temporary: &std::path::Path,
    source: &std::path::Path,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    // The descriptor pins the exact tmpfs directory whose ownership and quota
    // were checked. This trusted /proc path is never supplied by the project.
    let pinned = format!("/proc/{}/fd/{}", std::process::id(), scratch.as_raw_fd());
    let witness = tempfile::NamedTempFile::new_in(pinned)?;
    ensure!(
        witness.as_file().metadata()?.len() == 0,
        "Témoin scratch agent non vide"
    );
    witness.close()?;
    require_permission_denied(
        tempfile::tempfile_in(temporary),
        "Écriture hors scratch agent",
    )?;
    require_permission_denied(std::fs::read_dir(source), "Lecture des sources par l’agent")
}

fn require_permission_denied<T>(attempt: std::io::Result<T>, operation: &str) -> Result<()> {
    match attempt {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(crate::error::Error::Io(error)
            .context(format!("{operation} : refus PermissionDenied obligatoire"))),
        Ok(_) => Err(invalid(format!(
            "{operation} autorisée ; confinement effectif insuffisant"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_stat() -> libc::statfs {
        // SAFETY: every field is initialized and only the explicit quota fields are inspected.
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        stat.f_type = libc::TMPFS_MAGIC;
        stat.f_bsize = 4096;
        stat.f_blocks = 256;
        stat.f_files = 128;
        stat
    }

    #[test]
    fn agent_scratch_requires_private_ownership_and_finite_tmpfs_quotas() -> Result<()> {
        validate_agent_scratch(10001, 0o700, &scratch_stat(), 1024 * 1024)?;
        for (owner, mode) in [
            (10002, 0o700),
            (10001, 0o755),
            (10001, 0o770),
            (10001, 0o1700),
            (10001, 0o600),
        ] {
            assert!(validate_agent_scratch(owner, mode, &scratch_stat(), 1024 * 1024).is_err());
        }
        let mut invalid = Vec::new();
        let mut stat = scratch_stat();
        stat.f_type = 0xef53;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_bsize = 0;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_blocks = 0;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_blocks = 257;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_blocks = u64::MAX;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_files = 0;
        invalid.push(stat);
        let mut stat = scratch_stat();
        stat.f_files = u64::MAX;
        invalid.push(stat);
        for stat in invalid {
            assert!(validate_agent_scratch(10001, 0o700, &stat, 1024 * 1024).is_err());
        }
        Ok(())
    }

    #[test]
    fn agent_access_probes_refuse_unconfined_directories_without_leaving_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        for name in ["scratch", "temporary", "source"] {
            std::fs::create_dir(directory.path().join(name))?;
        }
        let scratch = crate::files::open_directory(&directory.path().join("scratch"))?;
        assert!(verify_agent_access(
            &scratch,
            &directory.path().join("temporary"),
            &directory.path().join("source")
        )
        .is_err());
        assert_eq!(
            std::fs::read_dir(directory.path().join("scratch"))?.count(),
            0
        );
        assert_eq!(
            std::fs::read_dir(directory.path().join("temporary"))?.count(),
            0
        );
        Ok(())
    }

    fn restrict_probe_filesystem(rules: &[(&std::path::Path, u64)]) -> Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};
        #[repr(C)]
        struct Ruleset {
            handled_access_fs: u64,
        }
        #[repr(C, packed)]
        struct PathRule {
            allowed_access: u64,
            parent_fd: i32,
        }
        // Stable Landlock ABI 1 rights: WRITE_FILE, READ_DIR, REMOVE_FILE, MAKE_REG.
        let ruleset = Ruleset {
            handled_access_fs: (1 << 1) | (1 << 3) | (1 << 5) | (1 << 8),
        };
        // SAFETY: ABI 1 consumes this initialized eight-byte ruleset attribute.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &ruleset,
                std::mem::size_of::<Ruleset>(),
                0,
            )
        } as i32;
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: the new ruleset descriptor is transferred exactly once.
        let ruleset_fd = unsafe { std::fs::File::from_raw_fd(fd) };
        for (path, allowed_access) in rules {
            let directory = crate::files::open_directory_path(path)?;
            let rule = PathRule {
                allowed_access: *allowed_access,
                parent_fd: directory.as_raw_fd(),
            };
            // SAFETY: type 1 is PATH_BENEATH; rule is the initialized packed ABI structure.
            if unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd.as_raw_fd(),
                    1,
                    &rule,
                    0,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // SAFETY: the isolated test thread only restricts itself and its descendants.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0
            || unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd.as_raw_fd(), 0) }
                < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    #[test]
    fn agent_access_probes_check_kernel_denials_and_remove_the_witness() -> Result<()> {
        use std::{fs, path::PathBuf, process::Command};
        const ROOT: &str = "LADYSHELL_AGENT_FS_PROBE_ROOT";
        const CASE: &str = "LADYSHELL_AGENT_FS_PROBE_CASE";
        let Some(root) = std::env::var_os(ROOT) else {
            for case in [
                "confined",
                "writable_tmp",
                "readable_source",
                "unlink_denied",
            ] {
                let root = tempfile::tempdir()?;
                for name in ["scratch", "temporary", "source"] {
                    fs::create_dir(root.path().join(name))?;
                }
                let output = Command::new(std::env::current_exe()?)
                    .args(["--exact", "audit::agent::tests::agent_access_probes_check_kernel_denials_and_remove_the_witness", "--nocapture"])
                    .env(ROOT, root.path()).env(CASE, case).output()?;
                assert!(
                    output.status.success(),
                    "{case}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if case != "unlink_denied" {
                    assert_eq!(fs::read_dir(root.path().join("scratch"))?.count(), 0);
                }
                assert_eq!(fs::read_dir(root.path().join("temporary"))?.count(), 0);
            }
            return Ok(());
        };
        let root = PathBuf::from(root);
        let scratch_path = root.join("scratch");
        let temporary = root.join("temporary");
        let source = root.join("source");
        let case = std::env::var(CASE).map_err(|_| invalid("Cas de test absent"))?;
        let scratch = crate::files::open_directory(&scratch_path)?;
        let rights = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 8);
        let mut rules = vec![(
            scratch_path.as_path(),
            if case == "unlink_denied" {
                rights & !(1 << 5)
            } else {
                rights
            },
        )];
        if case == "writable_tmp" {
            rules.push((temporary.as_path(), rights));
        }
        if case == "readable_source" {
            rules.push((source.as_path(), 1 << 3));
        }
        restrict_probe_filesystem(&rules)?;
        let observed = verify_agent_access(&scratch, &temporary, &source);
        if case == "confined" {
            observed?;
        } else {
            assert!(observed.is_err(), "accepted {case}");
        }
        Ok(())
    }

    #[test]
    fn missing_or_broken_probe_paths_are_not_permission_denials() -> Result<()> {
        require_permission_denied::<()>(
            Err(std::io::Error::from_raw_os_error(libc::EACCES)),
            "synthetic",
        )?;
        for errno in [libc::ENOENT, libc::ENOTDIR, libc::ENOSPC, libc::EIO] {
            assert!(require_permission_denied::<()>(
                Err(std::io::Error::from_raw_os_error(errno)),
                "synthetic"
            )
            .is_err());
        }
        Ok(())
    }

    fn resource_limit(resource: libc::__rlimit_resource_t) -> Result<libc::rlimit> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: resource is a known constant and limit is valid writable storage.
        if unsafe { libc::getrlimit(resource, &mut limit) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(limit)
    }

    #[test]
    fn agent_limits_are_hard_and_never_raise_existing_ceilings() -> Result<()> {
        const PROBE: &str = "LADYSHELL_TEST_AGENT_LIMITS";
        if std::env::var_os(PROBE).is_none() {
            let output = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "audit::agent::tests::agent_limits_are_hard_and_never_raise_existing_ceilings",
                    "--nocapture",
                ])
                .env(PROBE, "1")
                .output()?;
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        let mut existing_file_limit = resource_limit(libc::RLIMIT_FSIZE)?;
        existing_file_limit.rlim_cur = existing_file_limit.rlim_cur.min(1024);
        // SAFETY: only the isolated synthetic test process lowers its own soft limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &existing_file_limit) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let cases = [
            (libc::RLIMIT_CPU, 20),
            (libc::RLIMIT_NPROC, 64),
            (libc::RLIMIT_FSIZE, 4096),
            (libc::RLIMIT_CORE, 0),
        ];
        apply_remote_limits(20, 64, 4096)?;
        assert!(resource_limit(libc::RLIMIT_FSIZE)?.rlim_max <= existing_file_limit.rlim_cur);
        let mut established = Vec::new();
        for (resource, requested) in cases {
            let actual = resource_limit(resource)?;
            assert_eq!(actual.rlim_cur, actual.rlim_max);
            assert!(
                actual.rlim_max <= requested,
                "resource {resource} did not enforce {requested}"
            );
            established.push((resource, actual.rlim_max));
        }
        apply_remote_limits(40, 128, 8192)?;
        for (resource, previous) in established {
            let actual = resource_limit(resource)?;
            assert_eq!(actual.rlim_cur, previous);
            assert_eq!(actual.rlim_max, previous);
        }
        apply_remote_limits(10, 32, 2048)?;
        for (resource, requested) in [
            (libc::RLIMIT_CPU, 10),
            (libc::RLIMIT_NPROC, 32),
            (libc::RLIMIT_FSIZE, 2048),
            (libc::RLIMIT_CORE, 0),
        ] {
            let actual = resource_limit(resource)?;
            assert_eq!(actual.rlim_cur, actual.rlim_max);
            assert!(actual.rlim_max <= requested);
        }
        Ok(())
    }

    #[test]
    fn agent_limits_refuse_zero_and_infinity() {
        for (cpu, processes, bytes) in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (u64::MAX, 1, 1),
            (1, 1, u64::MAX),
        ] {
            assert!(validate_remote_limits(cpu, processes, bytes).is_err());
        }
    }
}
