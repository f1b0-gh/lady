//! Native OpenShell resources. Only this adapter may attest a stopped execution.
use super::{
    agent,
    config::Limits,
    image::BuiltImage,
    invalid,
    journal::{ResourceRecord, RunJournal},
    worker::{WorkerReceipt, WorkerRequest},
};
use crate::{
    error::{Error, Result},
    files,
    openshell::Backend,
    process::{capture, capture_input},
    state,
};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub struct StoppedExecution {
    pub(crate) receipt: WorkerReceipt,
    pub(crate) request: WorkerRequest,
}
impl StoppedExecution {
    pub fn receipt(&self) -> &WorkerReceipt {
        &self.receipt
    }
}
pub fn target_policy() -> Value {
    json!({"version":1,"landlock":{"compatibility":"hard_requirement"},"process":{"run_as_user":"10001","run_as_group":"10001"},"filesystem_policy":{"include_workdir":false,"read_only":["/nix/store","/usr","/bin","/etc","/proc","/sys/fs/cgroup","/dev/urandom","/audit/source"],"read_write":["/audit/scratch","/dev/null"]},"network_policies":{}})
}
pub fn agent_policy(binary: &str) -> Result<Value> {
    let mut value = target_policy();
    value["filesystem_policy"]["read_only"] = json!([
        "/nix/store",
        "/usr",
        "/bin",
        "/etc",
        "/proc",
        "/dev/urandom",
        "/audit/agent-response-schema.json"
    ]);
    value["filesystem_policy"]["read_write"] = json!(["/audit/agent", "/dev/null"]);
    value["network_policies"] = crate::policy::native_policy(binary)?["network_policies"].clone();
    Ok(value)
}
pub fn validate_policy(actual: &Value, expected: &Value, binary: Option<&str>) -> Result<()> {
    for key in ["version", "landlock", "process", "filesystem_policy"] {
        if actual[key] != expected[key] {
            return Err(invalid(format!(
                "Audit policy mismatch: {key}; observed={}; expected={}",
                actual[key], expected[key]
            )));
        }
    }
    if actual.as_object().is_none_or(|m| {
        m.keys().any(|k| {
            ![
                "version",
                "landlock",
                "process",
                "filesystem_policy",
                "network_policies",
            ]
            .contains(&k.as_str())
        })
    }) {
        return Err(invalid("Unknown audit policy field"));
    }
    let rules = actual.get("network_policies").and_then(Value::as_object);
    let Some(binary) = binary else {
        if actual.get("network_policies").is_some() && !rules.is_some_and(|r| r.is_empty()) {
            return Err(invalid("Network forbidden for the audit target"));
        }
        return Ok(());
    };
    let rules = rules.ok_or_else(|| invalid("Missing agent network policy"))?;
    if !rules.contains_key("openai_codex") {
        return Err(invalid("Missing Codex rule"));
    }
    let endpoints = expected["network_policies"]["openai_codex"]["endpoints"]
        .as_array()
        .ok_or_else(|| invalid("Missing expected endpoints"))?;
    for rule in rules.values() {
        let bins = rule["binaries"]
            .as_array()
            .ok_or_else(|| invalid("Missing network identity"))?;
        let hosts = rule["endpoints"]
            .as_array()
            .ok_or_else(|| invalid("Missing network endpoints"))?;
        if bins.is_empty()
            || hosts.is_empty()
            || bins.iter().any(|b| *b != json!({"path":binary}))
            || hosts.iter().any(|h| !endpoints.contains(h))
            || rule.as_object().is_none_or(|o| {
                o.keys()
                    .any(|k| !["name", "binaries", "endpoints"].contains(&k.as_str()))
            })
        {
            return Err(invalid("Additional network permission in the audit agent"));
        }
    }
    Ok(())
}

pub struct NativeRuntime {
    pub backend: Backend,
    pub image: BuiltImage,
    pub limits: Limits,
    pub provider: String,
    pub account: String,
}
impl NativeRuntime {
    fn owner(journal: &RunJournal) -> String {
        files::hash(format!("{}:{}", journal.data().run_id, journal.data().plan_sha256).as_bytes())
            [..32]
            .into()
    }
    fn name(journal: &RunJournal, prefix: &str) -> String {
        format!(
            "{prefix}{}",
            &files::hash(
                format!(
                    "{}:{}",
                    journal.data().run_id,
                    journal.data().resources.len()
                )
                .as_bytes()
            )[..16]
        )
    }
    fn context(&self, kind: &str) -> Value {
        json!({"gateway":self.backend.gateway,"workspace":self.backend.workspace,"kind":kind})
    }
    fn sandbox(
        &self,
        journal: &mut RunJournal,
        policy: &Value,
        volume: Option<&str>,
        agent: bool,
    ) -> Result<String> {
        let name = Self::name(journal, "ea-");
        let owner = Self::owner(journal);
        journal.resource_intent(&name, &owner, self.context("sandbox"))?;
        let path = journal.directory().join(format!("{name}-policy.json"));
        // OpenShell freezes the boundary executor's filesystem at startup.
        // Starting with network/provider rules would add default filesystem
        // grants that a later policy update cannot remove from that executor.
        let mut bootstrap = policy.clone();
        if agent {
            self.backend.verify_provider(&self.provider)?;
            bootstrap["network_policies"] = json!({});
        }
        crate::environment_lock::atomic_json(&path, &bootstrap)?;
        let mut command = self.backend.command();
        command
            .args([
                "sandbox",
                "create",
                "--name",
                &name,
                "--from",
                &self.image.image_id,
                "--policy",
            ])
            .arg(&path)
            .args([
                "--no-auto-providers",
                "--label",
                &format!("ladyshell.audit.owner={owner}"),
                "--cpu",
                "1",
                "--memory",
                &self.limits.memory_bytes.to_string(),
                "--detach",
                "--output",
                "json",
            ]);
        if let Some(volume) = volume {
            command.args(["--driver-config-json",&json!({"docker":{"mounts":[{"type":"volume","source":volume,"target":if agent {"/audit/agent"} else {"/audit/scratch"},"read_only":false}]}}).to_string()]);
        }
        command.args(["--", "/bin/sleep", "infinity"]);
        let result = capture(command, Duration::from_secs(120), 4 * 1024 * 1024);
        if let Some(actual) = self.backend.sandbox_identity(&name)? {
            if actual["labels"]["ladyshell.audit.owner"] != owner {
                return Err(invalid("Audit sandbox ownership mismatch"));
            }
            journal.resource_created(&name, state::text(&actual, "id")?)?;
        }
        result?;
        self.verify_sandbox(journal, &name, &bootstrap, false)?;
        if agent {
            self.attach_provider(journal, &name, &bootstrap)?;
            let final_path = journal
                .directory()
                .join(format!("{name}-agent-policy.json"));
            crate::environment_lock::atomic_json(&final_path, policy)?;
            self.backend.call(&[
                "policy",
                "set",
                &name,
                "--policy",
                final_path
                    .to_str()
                    .ok_or_else(|| invalid("Policy path is not UTF-8"))?,
                "--wait",
                "--timeout",
                "30",
            ])?;
        }
        self.verify_sandbox(journal, &name, policy, agent)?;
        Ok(name)
    }
    fn attach_provider(&self, journal: &RunJournal, name: &str, bootstrap: &Value) -> Result<()> {
        let record = journal
            .data()
            .resources
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| invalid("Sandbox not recorded in the journal"))?;
        retry_provider_attach(
            Duration::from_secs(120),
            |timeout| {
                let started = Instant::now();
                let call = |args: &[&str]| -> Result<Value> {
                    let remaining = attachment_remaining(started, timeout)?;
                    let mut command = self.backend.command();
                    command.args(args);
                    crate::json::parse(&capture(command, remaining, 8 * 1024 * 1024)?)
                };
                let observed = call(&["sandbox", "get", name, "--output", "json"])?;
                validate_sandbox_identity(&observed, record)?;
                let policy = call(&["policy", "get", name, "--full", "--output", "json"])?;
                let providers = call(&["sandbox", "provider", "list", name, "--output", "json"])?;
                validate_attachment_bootstrap(
                    &observed,
                    &policy["policy"],
                    &providers,
                    record,
                    bootstrap,
                )?;
                // Bracket the separate policy/provider observations with identity reads.
                validate_sandbox_identity(
                    &call(&["sandbox", "get", name, "--output", "json"])?,
                    record,
                )
            },
            |timeout| {
                let mut command = self.backend.command();
                command.args([
                    "sandbox",
                    "provider",
                    "attach",
                    name,
                    &self.provider,
                    "--wait",
                    "--timeout",
                    &timeout.as_secs().clamp(1, 30).to_string(),
                    "--output",
                    "json",
                ]);
                capture(
                    command,
                    timeout.min(Duration::from_secs(35)),
                    8 * 1024 * 1024,
                )?;
                Ok(())
            },
        )
    }
    fn verify_sandbox(
        &self,
        journal: &RunJournal,
        name: &str,
        policy: &Value,
        agent: bool,
    ) -> Result<()> {
        let record = journal
            .data()
            .resources
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| invalid("Sandbox not recorded in the journal"))?;
        let observed = self
            .backend
            .sandbox_identity(name)?
            .ok_or_else(|| invalid("Missing audit sandbox"))?;
        validate_sandbox_identity(&observed, record)?;
        let actual = crate::json::parse(
            &self
                .backend
                .call(&["policy", "get", name, "--full", "--output", "json"])?,
        )?;
        validate_policy(
            &actual["policy"],
            policy,
            if agent {
                Some(&self.image.codex_binary)
            } else {
                None
            },
        )?;
        if agent {
            self.backend.verify_provider(&self.provider)?;
            let status = crate::json::parse(&self.backend.call(&[
                "sandbox",
                "provider",
                "status",
                name,
                &self.provider,
                "--wait",
                "--timeout",
                "30",
                "--output",
                "json",
            ])?)?;
            validate_provider_status(
                &status,
                name,
                state::text(&observed, "id")?,
                &self.provider,
                &self.backend.workspace,
            )?;
        }
        Ok(())
    }
    fn volume(&self, journal: &mut RunJournal) -> Result<String> {
        let name = Self::name(journal, "ladyshell-audit-");
        let owner = Self::owner(journal);
        if volume(&name)?.is_some() {
            return Err(invalid("Audit volume already exists"));
        }
        journal.resource_intent(&name, &owner, self.context("volume"))?;
        let mut cmd = Command::new("docker");
        cmd.args([
            "volume",
            "create",
            "--driver",
            "local",
            "--label",
            "openshell.ai/sandbox-attachable=true",
            "--label",
            &format!(
                "openshell.ai/sandbox-attachable-workspace={}",
                self.backend.workspace
            ),
            "--label",
            &format!("ladyshell.audit.owner={owner}"),
            "--opt",
            "type=tmpfs",
            "--opt",
            "device=tmpfs",
            "--opt",
            &format!(
                "o=size={},uid=10001,gid=10001,nr_inodes={},mode=0700,nosuid,nodev",
                self.limits.disk_bytes, self.limits.files
            ),
            &name,
        ]);
        let result = capture(cmd, Duration::from_secs(30), 1024 * 1024);
        if let Some(v) = volume(&name)? {
            verify_volume_owner(&v, &owner, &self.backend.workspace)?;
            journal.resource_created(&name, &volume_id(&v)?)?;
        }
        result?;
        Ok(name)
    }
    pub fn target(
        &self,
        journal: &mut RunJournal,
        mut request: WorkerRequest,
        timeout: Duration,
    ) -> Result<StoppedExecution> {
        let started = Instant::now();
        super::worker::validate_request(&request)?;
        if request.artifacts.iter().map(|a| a.max_bytes).sum::<u64>() > 16 * 1024 * 1024 {
            return Err(invalid(
                "Requested evidence exceeds the 16 MiB transport limit",
            ));
        }
        let volume = self.volume(journal)?;
        let policy = target_policy();
        let name = self.sandbox(journal, &policy, Some(&volume), false)?;
        self.verify_sandbox(journal, &name, &policy, false)?;
        let timeout = timeout.saturating_sub(started.elapsed());
        if timeout.as_secs() == 0 {
            return Err(invalid("Time budget exhausted before target execution"));
        }
        request.timeout_seconds = request.timeout_seconds.min(timeout.as_secs());
        let mut cmd = self.backend.command();
        cmd.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/audit/scratch",
            "--timeout",
            &(timeout.as_secs().max(1) + 10).to_string(),
            &name,
            "--",
            &self.image.runtime_binary,
            "audit-worker",
        ]);
        let raw = capture_input(
            cmd,
            &serde_json::to_vec(&request)?,
            timeout + Duration::from_secs(15),
            32 * 1024 * 1024,
        )?;
        let receipt: WorkerReceipt = serde_json::from_value(crate::json::parse(&raw)?)?;
        if !receipt.stopped || receipt.invocation_id != request.invocation_id {
            return Err(invalid("Target termination not established"));
        }
        self.remove_one(journal, &name)?;
        self.remove_one(journal, &volume)?;
        Ok(StoppedExecution { receipt, request })
    }
    pub fn agent(
        &self,
        journal: &mut RunJournal,
        id: &str,
        prompt: &[u8],
        timeout: Duration,
    ) -> Result<(agent::AgentResponse, Vec<u8>)> {
        let started = Instant::now();
        crate::config::identifier(id)?;
        let volume = self.volume(journal)?;
        let policy = agent_policy(&self.image.codex_binary)?;
        let name = self.sandbox(journal, &policy, Some(&volume), true)?;
        self.verify_sandbox(journal, &name, &policy, true)?;
        let timeout = timeout.saturating_sub(started.elapsed());
        if timeout.as_secs() == 0 {
            return Err(invalid("Time budget exhausted before model invocation"));
        }
        let mut cmd = self.backend.command();
        cmd.args([
            "sandbox",
            "exec",
            "--no-tty",
            "--no-login-shell",
            "--workdir",
            "/audit/agent",
            "--timeout",
            &timeout.as_secs().max(1).to_string(),
            "--env",
            "HOME=/audit/agent",
            "--env",
            "CODEX_HOME=/audit/agent/.codex",
            "--env",
            &format!("CODEX_ACCOUNT_ID={}", self.account),
            &name,
            "--",
            &self.image.runtime_binary,
            "audit-agent",
            "--codex",
            &self.image.codex_binary,
            "--cpu-seconds",
            &self.limits.cpu_seconds.to_string(),
            "--processes",
            &self.limits.processes.to_string(),
            "--file-bytes",
            &self.limits.disk_bytes.to_string(),
        ]);
        let raw = capture_input(
            cmd,
            prompt,
            timeout + Duration::from_secs(5),
            4 * 1024 * 1024,
        )?;
        self.remove_one(journal, &name)?;
        self.remove_one(journal, &volume)?;
        Ok((agent::parse_transcript(&raw)?, raw))
    }
    fn remove_one(&self, journal: &mut RunJournal, name: &str) -> Result<()> {
        let resource = journal
            .data()
            .resources
            .iter()
            .find(|r| r.name == name)
            .cloned()
            .ok_or_else(|| invalid("Unknown resource"))?;
        cleanup_resource(journal, &resource)
    }
    pub fn cleanup(&self, journal: &mut RunJournal) -> Result<()> {
        cleanup(journal)
    }
}
fn validate_provider_status(
    value: &Value,
    name: &str,
    id: &str,
    provider: &str,
    workspace: &str,
) -> Result<()> {
    let targets = value["targets"]
        .as_array()
        .ok_or_else(|| invalid("Missing provider receipt"))?;
    if targets.len() != 1 {
        return Err(invalid("Ambiguous provider receipt"));
    }
    let target = &targets[0];
    let desired = &target["receipt"]["desired"];
    let observed = &target["observed"];
    if target["state"] != "ready"
        || target["wait_outcome"] != "complete"
        || target["receipt"]["provider"] != provider
        || target["receipt"]["workspace"] != workspace
        || desired["sandbox"] != name
        || desired["sandbox_id"] != id
        || desired["provider_id"].as_str().is_none_or(str::is_empty)
        || [
            "credentials_installed",
            "launch_environment_installed",
            "policy_active",
        ]
        .iter()
        .any(|key| observed[key] != true)
        || [
            "attachment_epoch",
            "config_revision",
            "provider_env_revision",
            "policy_hash",
        ]
        .iter()
        .any(|key| desired[key].as_str().is_none_or(str::is_empty) || desired[key] != observed[key])
    {
        return Err(invalid("Provider not ready or receipt mismatch"));
    }
    Ok(())
}

fn retry_provider_attach(
    timeout: Duration,
    mut verify: impl FnMut(Duration) -> Result<()>,
    mut attach: impl FnMut(Duration) -> Result<()>,
) -> Result<()> {
    let started = Instant::now();
    for attempt in 0..3 {
        verify(attachment_remaining(started, timeout)?)?;
        match attach(attachment_remaining(started, timeout)?) {
            Err(error) if attempt < 2 && uncommitted_attachment_conflict(&error) => continue,
            result => return result,
        }
    }
    Err(invalid("Provider attachment attempt limit reached"))
}

fn attachment_remaining(started: Instant, timeout: Duration) -> Result<Duration> {
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return Err(Error::ProcessTimeout {
            program: "openshell".into(),
            timeout,
        });
    }
    Ok(remaining)
}

fn uncommitted_attachment_conflict(error: &Error) -> bool {
    let Error::ProcessExit {
        program,
        status,
        stderr,
    } = error
    else {
        return false;
    };
    if program != "openshell" || status.code() != Some(1) {
        return false;
    }
    // OpenShell 0.1.4 provider.rs emits this exact message only for Aborted
    // before the attachment is saved. CONFIG_OPERATION_STORAGE_UNCERTAIN and
    // readiness failures have different diagnostics and must never be replayed.
    // Accept miette's fixed presentation markers, not a matching substring.
    let message = stderr
        .trim()
        .lines()
        .enumerate()
        .flat_map(|(index, line)| {
            let line = line.trim();
            let line = if index == 0 {
                let line = line.strip_prefix("Error:").unwrap_or(line).trim_start();
                line.strip_prefix('×').unwrap_or(line)
            } else {
                line.strip_prefix('│').unwrap_or(line)
            };
            line.split_whitespace()
        })
        .collect::<Vec<_>>()
        .join(" ");
    message == "Failed to attach provider: sandbox was modified by another operation. Please retry the command."
}

fn validate_sandbox_identity(observed: &Value, record: &ResourceRecord) -> Result<()> {
    if record.id.as_deref().is_none_or(str::is_empty)
        || observed["id"].as_str() != record.id.as_deref()
        || observed["labels"]["ladyshell.audit.owner"] != record.owner
        || observed["phase"] != "Ready"
    {
        return Err(invalid("Audit sandbox identity or state mismatch"));
    }
    Ok(())
}

fn validate_attachment_bootstrap(
    observed: &Value,
    policy: &Value,
    providers: &Value,
    record: &ResourceRecord,
    bootstrap: &Value,
) -> Result<()> {
    validate_sandbox_identity(observed, record)?;
    validate_policy(policy, bootstrap, None)?;
    if *providers != json!({"providers":[],"next_page_token":""}) {
        return Err(invalid(
            "Provider already attached or observation incomplete before attachment",
        ));
    }
    Ok(())
}

fn volume(name: &str) -> Result<Option<Value>> {
    crate::config::identifier(name)?;
    let mut cmd = Command::new("docker");
    cmd.args(["volume", "inspect", name]);
    match capture(cmd, Duration::from_secs(30), 1024 * 1024) {
        Err(Error::ProcessExit { stderr, .. })
            if stderr.to_ascii_lowercase().contains("no such volume") =>
        {
            Ok(None)
        }
        result => {
            let values = crate::json::parse(&result?)?;
            let rows = values
                .as_array()
                .ok_or_else(|| invalid("Invalid volume observation"))?;
            if rows.len() != 1 || rows[0]["Name"] != name {
                return Err(invalid("Volume identity mismatch"));
            }
            Ok(Some(rows[0].clone()))
        }
    }
}
fn volume_id(v: &Value) -> Result<String> {
    crate::plan::digest(
        &json!({"name":v["Name"],"created":v["CreatedAt"],"driver":v["Driver"],"options":v["Options"],"labels":v["Labels"]}),
    )
}
fn verify_volume_owner(v: &Value, owner: &str, workspace: &str) -> Result<()> {
    if v["Driver"] != "local"
        || v["Options"]["type"] != "tmpfs"
        || v["Options"]["device"] != "tmpfs"
        || v["Labels"]["ladyshell.audit.owner"] != owner
        || v["Labels"]["openshell.ai/sandbox-attachable"] != "true"
        || v["Labels"]["openshell.ai/sandbox-attachable-workspace"] != workspace
    {
        return Err(invalid("Volume outside the audit scope"));
    }
    Ok(())
}
fn cleanup_resource(journal: &mut RunJournal, resource: &ResourceRecord) -> Result<()> {
    if resource.deleted {
        return Ok(());
    }
    let backend = Backend::new(&resource.context)?;
    let observed = match resource.context["kind"].as_str() {
        Some("sandbox") => backend.sandbox_identity(&resource.name)?.map(|v| {
            (
                v["id"].as_str().unwrap_or("").to_owned(),
                v["labels"]["ladyshell.audit.owner"].clone(),
            )
        }),
        Some("volume") => match volume(&resource.name)? {
            Some(v) => {
                verify_volume_owner(&v, &resource.owner, &backend.workspace)?;
                Some((volume_id(&v)?, v["Labels"]["ladyshell.audit.owner"].clone()))
            }
            None => None,
        },
        _ => return Err(invalid("Unknown audit resource type")),
    };
    let Some((id, owner)) = observed else {
        if let Some(id) = &resource.id {
            journal.resource_deleted(&resource.name, id)?;
        } else {
            journal.resolve_absent_intent(&resource.name)?;
        }
        return Ok(());
    };
    if id.is_empty()
        || owner != resource.owner
        || resource.id.as_ref().is_some_and(|expected| expected != &id)
    {
        return Err(invalid(
            "Refusing to delete a resource with a different identity",
        ));
    }
    if resource.id.is_none() {
        journal.resource_created(&resource.name, &id)?;
    }
    if resource.context["kind"] == "sandbox" {
        backend.call(&["sandbox", "delete", &resource.name])?;
        if backend.sandbox_identity(&resource.name)?.is_some() {
            return Err(invalid("Sandbox deletion not confirmed"));
        }
    } else {
        let mut cmd = Command::new("docker");
        cmd.args(["volume", "rm", &resource.name]);
        capture(cmd, Duration::from_secs(30), 1024 * 1024)?;
        if volume(&resource.name)?.is_some() {
            return Err(invalid("Volume deletion not confirmed"));
        }
    }
    journal.resource_deleted(&resource.name, &id)
}
pub fn cleanup(journal: &mut RunJournal) -> Result<()> {
    let resources = journal.data().resources.clone();
    let mut failure = None;
    for resource in resources.iter().rev() {
        if let Err(error) = cleanup_resource(journal, resource) {
            failure = Some(error);
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
pub fn recover(path: &Path) -> Result<Value> {
    let mut journal = RunJournal::open(path)?;
    cleanup(&mut journal)?;
    Ok(
        json!({"schema_version":1,"operation":"recover","run_directory":path,"status":journal.data().status,"cleanup_verified":journal.data().cleanup_verified,"target_executed":false}),
    )
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use std::{cell::Cell, os::unix::process::ExitStatusExt, process::ExitStatus};

    fn attachment_error(message: &str) -> Error {
        Error::ProcessExit {
            program: "openshell".into(),
            status: ExitStatus::from_raw(256),
            stderr: message.into(),
        }
    }

    fn conflict() -> Error {
        attachment_error("Error:   × Failed to attach provider: sandbox was modified by another operation.\n  │ Please retry the command.\n\n")
    }

    #[test]
    fn attachment_rechecks_before_retrying_an_uncommitted_conflict() -> Result<()> {
        let checks = Cell::new(0);
        let attempts = Cell::new(0);
        retry_provider_attach(
            Duration::from_secs(1),
            |_| {
                checks.set(checks.get() + 1);
                Ok(())
            },
            |_| {
                attempts.set(attempts.get() + 1);
                assert_eq!(checks.get(), attempts.get());
                if attempts.get() < 3 {
                    Err(conflict())
                } else {
                    Ok(())
                }
            },
        )?;
        assert_eq!(attempts.get(), 3);
        Ok(())
    }

    #[test]
    fn attachment_stops_after_three_conflicting_attempts() {
        let attempts = Cell::new(0);
        let result = retry_provider_attach(
            Duration::from_secs(1),
            |_| Ok(()),
            |_| {
                attempts.set(attempts.get() + 1);
                Err(conflict())
            },
        );
        assert!(matches!(result, Err(Error::ProcessExit { .. })));
        assert_eq!(attempts.get(), 3);
    }

    #[test]
    fn attachment_does_not_retry_other_errors_or_uncertain_writes() {
        for message in [
            "provider attachment failed (Unavailable)",
            "provider change may already be saved (CONFIG_OPERATION_STORAGE_UNCERTAIN)",
            "Failed to attach provider: sandbox was modified by another operation. Please retry the command. CONFIG_OPERATION_STORAGE_UNCERTAIN",
            "Failed to detach provider: sandbox was modified by another operation. Please retry the command.",
            "Failed to attach provider: sandbox was modified by another operation.",
            "Error: × Failed to attach provider: sandbox was modified by another operation. Please retry the command.\nError:",
        ] {
            let attempts = Cell::new(0);
            assert!(retry_provider_attach(
                Duration::from_secs(1),
                |_| Ok(()),
                |_| {
                    attempts.set(attempts.get() + 1);
                    Err(attachment_error(message))
                },
            ).is_err());
            assert_eq!(attempts.get(), 1, "{message}");
        }
    }

    #[test]
    fn attachment_does_not_retry_process_timeout() {
        let attempts = Cell::new(0);
        assert!(matches!(
            retry_provider_attach(
                Duration::from_secs(1),
                |_| Ok(()),
                |_| {
                    attempts.set(attempts.get() + 1);
                    Err(Error::ProcessTimeout {
                        program: "openshell".into(),
                        timeout: Duration::from_secs(1),
                    })
                },
            ),
            Err(Error::ProcessTimeout { .. })
        ));
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn attachment_deadline_prevents_a_retry_after_slow_conflict() {
        let attempts = Cell::new(0);
        let checks = Cell::new(0);
        assert!(matches!(
            retry_provider_attach(
                Duration::from_millis(5),
                |_| {
                    checks.set(checks.get() + 1);
                    Ok(())
                },
                |_| {
                    attempts.set(attempts.get() + 1);
                    std::thread::sleep(Duration::from_millis(10));
                    Err(conflict())
                },
            ),
            Err(Error::ProcessTimeout { .. })
        ));
        assert_eq!(attempts.get(), 1);
        assert_eq!(checks.get(), 1);
    }

    #[test]
    fn attachment_zero_deadline_does_not_verify_or_mutate() {
        let observations = Cell::new(0);
        let mutations = Cell::new(0);
        let result = retry_provider_attach(
            Duration::ZERO,
            |_| {
                observations.set(observations.get() + 1);
                Ok(())
            },
            |_| {
                mutations.set(mutations.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::ProcessTimeout { .. })));
        assert_eq!(observations.get(), 0);
        assert_eq!(mutations.get(), 0);
    }

    #[test]
    fn attachment_refuses_identity_policy_or_provider_changes_before_retry() {
        let record = ResourceRecord {
            name: "agent".into(),
            id: Some("original-id".into()),
            owner: "original-owner".into(),
            context: json!({}),
            deleted: false,
        };
        let bootstrap = target_policy();
        for (document, pointer, changed) in [
            ("identity", "/id", json!("replacement")),
            (
                "identity",
                "/labels/ladyshell.audit.owner",
                json!("replacement"),
            ),
            ("identity", "/phase", json!("Pending")),
            ("policy", "/filesystem_policy/read_write", json!(["/tmp"])),
            ("policy", "/network_policies", json!({"unwanted":{}})),
            ("providers", "/providers", json!([{"name":"unexpected"}])),
            ("providers", "/next_page_token", json!("another-page")),
        ] {
            let checks = Cell::new(0);
            let attempts = Cell::new(0);
            let result = retry_provider_attach(
                Duration::from_secs(1),
                |_| {
                    checks.set(checks.get() + 1);
                    let mut documents = json!({
                        "identity":{"id":"original-id","phase":"Ready","labels":{"ladyshell.audit.owner":"original-owner"}},
                        "policy":bootstrap,
                        "providers":{"providers":[],"next_page_token":""}
                    });
                    if checks.get() > 1 {
                        assert!(
                            documents[document].pointer(pointer).is_some(),
                            "Missing fixture pointer: {document}{pointer}"
                        );
                        *documents[document]
                            .pointer_mut(pointer)
                            .ok_or_else(|| invalid("Missing fixture pointer"))? = changed.clone();
                    }
                    validate_attachment_bootstrap(
                        &documents["identity"],
                        &documents["policy"],
                        &documents["providers"],
                        &record,
                        &bootstrap,
                    )
                },
                |_| {
                    attempts.set(attempts.get() + 1);
                    Err(conflict())
                },
            );
            assert!(
                matches!(result, Err(Error::InvalidInput { .. })),
                "{document}{pointer}: {result:?}"
            );
            assert_eq!(checks.get(), 2);
            assert_eq!(attempts.get(), 1);
        }
    }
    #[test]
    fn readiness_requires_current_identity_and_applied_revisions() -> Result<()> {
        let desired = json!({"sandbox":"agent", "sandbox_id":"id", "provider_id":"provider-id", "attachment_epoch":"epoch", "config_revision":"config", "provider_env_revision":"env", "policy_hash":"hash"});
        let mut observed = desired.clone();
        for key in [
            "credentials_installed",
            "launch_environment_installed",
            "policy_active",
        ] {
            observed[key] = json!(true);
        }
        let good = json!({"targets":[{"state":"ready","wait_outcome":"complete","receipt":{"provider":"provider","workspace":"default","desired":desired},"observed":observed}]});
        validate_provider_status(&good, "agent", "id", "provider", "default")?;
        for pointer in [
            "/targets/0/state",
            "/targets/0/wait_outcome",
            "/targets/0/receipt/provider",
            "/targets/0/receipt/workspace",
            "/targets/0/receipt/desired/provider_id",
            "/targets/0/receipt/desired/sandbox",
            "/targets/0/receipt/desired/sandbox_id",
            "/targets/0/observed/credentials_installed",
            "/targets/0/observed/launch_environment_installed",
            "/targets/0/observed/policy_active",
            "/targets/0/observed/attachment_epoch",
            "/targets/0/observed/config_revision",
            "/targets/0/observed/provider_env_revision",
            "/targets/0/observed/policy_hash",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer)
                .ok_or_else(|| invalid("Missing test pointer"))? = Value::Null;
            assert!(
                validate_provider_status(&bad, "agent", "id", "provider", "default").is_err(),
                "{pointer}"
            );
        }
        for bad in [
            json!({}),
            json!({"targets":[]}),
            json!({"targets":[good["targets"][0],good["targets"][0]]}),
        ] {
            assert!(validate_provider_status(&bad, "agent", "id", "provider", "default").is_err());
        }
        Ok(())
    }
}
