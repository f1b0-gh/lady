use clap::{Args, Parser, Subcommand};
use ladyshell::error::Result;
pub use ladyshell::request::{Desired, Destroy, Existing, SyncArgs};
use std::path::PathBuf;
#[derive(Debug, Parser)]
#[command(
    name = "ladyshell",
    version,
    about = "Manage declarative native OpenShell environments",
    after_help = "Help:\n  ladyshell help <COMMAND> [SUBCOMMAND]\n  ladyshell <COMMAND> [SUBCOMMAND] --help\n\nExamples:\n  ladyshell list\n  ladyshell help apply\n  ladyshell cs checkpoint --help\n  ladyshell run --state /path/to/state -- cargo test\n\nHelp does not load configuration, credentials, or sandbox state."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Validate dependency changes inside verified sandboxes.
    #[command(
        after_help = "Examples:\n  ladyshell deps prune validate --state /path/to/state --plan /path/to/plan.json"
    )]
    Deps(crate::deps_cli::DepsArgs),
    /// Explain the retired artifact command; use ladyboot directly.
    #[command(
        long_about = "The ladyshell artifact forwarding command is retired.\nRun ladyboot directly; for help, run ladyboot --help.",
        after_help = "Examples:\n  ladyshell help artifact\n  ladyshell artifact --help"
    )]
    Artifact(crate::artifact_cli::ArtifactArgs),
    /// Plan, run, and verify bounded security audits.
    #[command(after_help = "Examples:\n  ladyshell audit verify /path/to/audit-run")]
    Audit(crate::audit_cli::AuditArgs),
    #[command(hide = true)]
    AuditWorker,
    #[command(hide = true)]
    AuditAgent {
        #[arg(long)]
        codex: PathBuf,
        #[arg(long)]
        cpu_seconds: u64,
        #[arg(long)]
        processes: u32,
        #[arg(long)]
        file_bytes: u64,
    },
    /// Write a lock receipt for the selected mission and runtime inputs.
    #[command(
        after_help = "Examples:\n  ladyshell lock --config mission.ncl --project . --state /path/to/state --resources resources --codex /path/to/codex --codex-code-mode-host /path/to/host"
    )]
    Lock(DesiredOptions),
    /// Explain proposed sandbox changes and dependency requirements.
    #[command(
        after_help = "Examples:\n  ladyshell plan --config mission.ncl --project . --state /path/to/state --resources resources --codex /path/to/codex --codex-code-mode-host /path/to/host"
    )]
    Plan(DesiredOptions),
    /// Provision or reconcile the sandbox from the selected mission.
    #[command(
        after_help = "Examples:\n  ladyshell apply --config mission.ncl --project . --state /path/to/state --resources resources --codex /path/to/codex --codex-code-mode-host /path/to/host"
    )]
    Apply(DesiredOptions),
    /// Open an interactive shell inside the verified sandbox.
    #[command(after_help = "Examples:\n  ladyshell shell --state /path/to/state")]
    Shell(SessionOptions),
    /// Start a Codex chat inside the verified sandbox.
    #[command(after_help = "Examples:\n  ladyshell chat --state /path/to/state")]
    Chat(SessionOptions),
    /// Resume a Codex session inside the verified sandbox.
    #[command(after_help = "Examples:\n  ladyshell resume --state /path/to/state")]
    Resume(SessionOptions),
    /// List locally registered instances without querying OpenShell.
    #[command(after_help = "Examples:\n  ladyshell list --json")]
    List {
        /// Print the local inventory and diagnostics as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Manage the local SQLite catalog, labels, and history.
    #[command(after_help = "Examples:\n  ladyshell manage list\n  ladyshell help manage annotate")]
    Manage(crate::management_cli::ManagementArgs),
    /// Install, submit and inspect retained OpenShell executions.
    Execution(crate::execution_cli::ExecutionArgs),
    /// Inspect retained state and current sandbox status.
    #[command(after_help = "Examples:\n  ladyshell status --state /path/to/state")]
    Status(ExistingOptions),
    /// Run the checks declared by the retained mission inside the verified sandbox.
    #[command(after_help = "Examples:\n  ladyshell check --state /path/to/state")]
    Check(ExistingOptions),
    /// Export sandbox changes and reconcile them with the host checkout.
    #[command(after_help = "Examples:\n  ladyshell sync --state /path/to/state --dry-run")]
    Sync(SyncArgsOptions),
    /// Execute an experiment inside the verified sandbox.
    #[command(
        after_help = "Examples:\n  ladyshell run --state /path/to/state -- cargo test\n  ladyshell run --state /path/to/state --sync --timeout 600 -- cargo test"
    )]
    Run(RunOptions),
    /// Inspect and recover retained publication attempts.
    #[command(
        after_help = "Examples:\n  ladyshell publication status --state /path/to/state\n  ladyshell help publication publish"
    )]
    Publication(PublicationOptions),
    /// Manage isolated agent tasks and preserved sandbox work.
    #[command(after_help = "Examples:\n  ladyshell task inspect --state /path/to/state --live")]
    Task(TaskOptions),
    /// Submit exact Tangled review rounds and inspect their feedback.
    #[command(
        after_help = "Examples:\n  ladyshell review status --state /path/to/state --config review.json\n  ladyshell help review merge-check"
    )]
    Review(ReviewOptions),
    /// Track and restack dependent snapshot checkpoints.
    #[command(after_help = "Examples:\n  ladyshell stack status --directory /path/to/stack")]
    Stack(StackOptions),
    /// Continue a task across verified source handoffs and sandbox incarnations.
    #[command(
        after_help = "Examples:\n  ladyshell cs status --state /path/to/state\n  ladyshell help cs checkpoint"
    )]
    Cs(ContinuousOptions),
    #[command(hide = true)]
    CsWorker,
    #[command(hide = true)]
    CsWorkerProfile,
    #[command(hide = true)]
    BrokerStorageProbe,
    #[command(hide = true)]
    BrokerExport,
    #[command(hide = true)]
    SnapshotList(Worker),
    #[command(hide = true)]
    SnapshotPreview(Worker),
    #[command(hide = true)]
    SnapshotFile(WorkerFile),
    #[command(hide = true)]
    RemoteAuth,
    /// Export then delete only the current owned sandbox; retain host state.
    #[command(alias = "delete")]
    #[command(
        after_help = "Examples:\n  ladyshell destroy --state /path/to/state\n  ladyshell destroy --all --dry-run"
    )]
    Destroy(DestroyOptions),
}
#[derive(Debug, Args)]
pub struct DesiredOptions {
    /// Nickel mission configuration file.
    #[arg(long)]
    pub config: PathBuf,
    /// Host project directory whose selected sources enter the sandbox.
    #[arg(long)]
    pub project: PathBuf,
    /// Host directory containing retained Ladyshell sandbox state.
    #[arg(long)]
    pub state: PathBuf,
    /// Directory containing the mission runtime resources.
    #[arg(long)]
    pub resources: PathBuf,
    /// Host Codex executable to include in the runtime.
    #[arg(long)]
    pub codex: PathBuf,
    /// Host Codex code-mode executable to include in the runtime.
    #[arg(long)]
    pub codex_code_mode_host: PathBuf,
    /// Explicit environment lock receipt; otherwise use the mission default.
    #[arg(long)]
    pub lock: Option<PathBuf>,
    /// Ladybom JSON report verified against the selected sources.
    #[arg(long)]
    pub ladybom: Option<PathBuf>,
    /// Mission name selected from the Nickel configuration.
    #[arg(long, default_value = "dev")]
    pub mission: String,
}

#[derive(Debug, Args)]
pub struct ContinuousOptions {
    #[command(subcommand)]
    pub action: ContinuousAction,
}
#[derive(Debug, Subcommand)]
pub enum ContinuousAction {
    /// Enroll a freshly provisioned sandbox under a stable task identifier.
    #[command(after_help = "Examples:\n  ladyshell cs init --state /path/to/state --task task-1")]
    Init {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        task: String,
    },
    /// Inspect retained handoff evidence and current runtime generation.
    #[command(after_help = "Examples:\n  ladyshell cs status --state /path/to/state")]
    Status(ExistingOptions),
    /// Export, stop/start to terminate writers, and verify the retained source.
    /// Repeat the same attempt to recover an interrupted checkpoint.
    #[command(
        after_help = "Examples:\n  ladyshell cs checkpoint --state /path/to/state --attempt checkpoint-1 --epoch 1"
    )]
    Checkpoint {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        attempt: String,
        #[arg(long)]
        epoch: u64,
    },
    /// Acknowledge both retained sides of a stop/start discrepancy before selecting a reconciled candidate.
    ReconcileCheckpoint {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        before_tree: String,
        #[arg(long)]
        after_tree: String,
    },
    /// Resolve a frozen host-selected candidate and apply compatible source changes.
    /// Repeat identical inputs to recover an interrupted refresh.
    Refresh {
        #[command(flatten)]
        desired: DesiredOptions,
        #[arg(long)]
        attempt: String,
        /// Bounded JSON task objective, upstream changes, and next steps.
        #[arg(long)]
        context: PathBuf,
    },
    /// Admit execution of the exact acknowledged epoch.
    #[command(after_help = "Examples:\n  ladyshell cs resume --state /path/to/state --epoch 1")]
    Resume {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        epoch: u64,
    },
    /// Provision a fresh sandbox from the retained incompatible selection.
    #[command(after_help = "Examples:\n  ladyshell cs replace --state /path/to/state")]
    Replace(ExistingOptions),
}
#[derive(Debug, Args)]
pub struct ExistingOptions {
    /// Host directory containing retained Ladyshell sandbox state.
    #[arg(long)]
    pub state: PathBuf,
}
#[derive(Debug, Args)]
pub struct SessionOptions {
    /// Host directory containing retained Ladyshell sandbox state.
    #[arg(long)]
    pub state: PathBuf,
    /// Export on exit; apply changes only after a successful session.
    #[arg(long)]
    pub sync: bool,
    /// Commit the applied export and push to this configured host Git remote.
    #[arg(long, requires_all = ["sync", "branch", "message"])]
    pub publish: Option<String>,
    /// Existing checkout branch to publish, with remote compare-and-swap.
    #[arg(long, requires = "publish")]
    pub branch: Option<String>,
    #[arg(long, requires = "publish")]
    pub message: Option<String>,
    /// Host-owned publication policy outside the exported project.
    #[arg(long, requires = "publish")]
    pub policy: Option<PathBuf>,
    /// Export and delete the owned sandbox after the session finishes.
    #[arg(long, requires = "sync")]
    pub cleanup: bool,
}
impl SessionOptions {
    pub fn publication(&self) -> Option<ladyshell::publish::Options> {
        Some(ladyshell::publish::Options {
            remote: self.publish.clone()?,
            branch: self.branch.clone()?,
            message: self.message.clone()?,
            policy: self.policy.clone(),
        })
    }
}
#[derive(Debug, Args)]
pub struct RunOptions {
    #[command(flatten)]
    pub session: SessionOptions,
    /// Maximum command runtime in seconds (1 through 86400).
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub timeout: u32,
    /// Program and arguments to execute; place them after --.
    #[arg(required = true, last = true, num_args = 1..)]
    pub command: Vec<std::ffi::OsString>,
}
#[derive(Debug, Args)]
pub struct DestroyOptions {
    #[arg(long, required_unless_present = "all", conflicts_with = "all")]
    pub state: Option<PathBuf>,
    /// Export and delete every currently registered Lady instance.
    #[arg(long)]
    pub all: bool,
    /// Preview --all without writes or OpenShell calls.
    #[arg(long, requires = "all")]
    pub dry_run: bool,
    /// Explicitly skip export, including when the sandbox cannot execute it.
    #[arg(long)]
    pub discard_work: bool,
}
pub fn validate_args(args: &[&str]) -> Result<()> {
    Cli::try_parse_from(args).map_err(|error| ladyshell::error::Error::InvalidInput {
        message: error.to_string(),
    })?;
    Ok(())
}

#[derive(Debug, Args)]
pub struct SyncArgsOptions {
    /// Explicit state directory; otherwise use the sandbox associated with the current project.
    #[arg(long)]
    pub state: Option<PathBuf>,
    /// Preview changes without modifying the host checkout.
    #[arg(long, conflicts_with_all = ["apply", "export"])]
    pub dry_run: bool,
    /// Compatibility flag: applying changes is now the default.
    #[arg(long, hide = true, conflicts_with = "export")]
    pub apply: bool,
    /// Export only, without applying changes to the checkout.
    #[arg(long)]
    pub export: bool,
    /// Print JSON for scripts.
    #[arg(long)]
    pub json: bool,
}
impl SyncArgsOptions {
    pub fn applies(&self) -> bool {
        SyncArgs::from(self).applies()
    }
}
#[derive(Debug, Args)]
pub struct Worker {
    #[arg(long)]
    pub exclude: Vec<String>,
}
#[derive(Debug, Args)]
pub struct WorkerFile {
    #[command(flatten)]
    pub filters: Worker,
    pub path: String,
}

impl From<DesiredOptions> for Desired {
    fn from(args: DesiredOptions) -> Self {
        Self {
            config: args.config,
            project: args.project,
            state: args.state,
            resources: args.resources,
            codex: args.codex,
            codex_code_mode_host: args.codex_code_mode_host,
            lock: args.lock,
            ladybom: args.ladybom,
            mission: args.mission,
        }
    }
}

impl From<ExistingOptions> for Existing {
    fn from(args: ExistingOptions) -> Self {
        Self { state: args.state }
    }
}

impl TryFrom<DestroyOptions> for Destroy {
    type Error = ladyshell::error::Error;
    fn try_from(args: DestroyOptions) -> Result<Self> {
        if args.all || args.dry_run {
            return Err(ladyshell::error::Error::InvalidInput {
                message: "Use the bulk deletion API".into(),
            });
        }
        Ok(Self {
            state: args
                .state
                .ok_or_else(|| ladyshell::error::Error::InvalidInput {
                    message: "Explicit state required".into(),
                })?,
            discard_work: args.discard_work,
        })
    }
}

impl From<SyncArgsOptions> for SyncArgs {
    fn from(args: SyncArgsOptions) -> Self {
        Self {
            state: args.state,
            dry_run: args.dry_run,
            apply: args.apply,
            export: args.export,
            json: args.json,
        }
    }
}

impl From<&SyncArgsOptions> for SyncArgs {
    fn from(args: &SyncArgsOptions) -> Self {
        Self {
            state: args.state.clone(),
            dry_run: args.dry_run,
            apply: args.apply,
            export: args.export,
            json: args.json,
        }
    }
}

#[derive(Debug, Args)]
pub struct PublicationOptions {
    #[command(subcommand)]
    pub action: PublicationAction,
}
#[derive(Debug, Subcommand)]
pub enum PublicationAction {
    /// Commit and push a retained export to the configured host remote.
    #[command(
        after_help = "Examples:\n  ladyshell publication publish --state /path/to/state --export /path/to/export --remote origin --branch task-1 --message \"Publish task work\""
    )]
    Publish {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        message: String,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Inspect retained publication attempts.
    #[command(after_help = "Examples:\n  ladyshell publication status --state /path/to/state")]
    Status(ExistingOptions),
    /// Run the host publication policy against a retained export.
    #[command(
        after_help = "Examples:\n  ladyshell publication check --state /path/to/state --export /path/to/export --policy /path/to/policy.json"
    )]
    Check {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Recover a retained attempt, optionally retrying or abandoning it.
    #[command(after_help = "Examples:\n  ladyshell publication reconcile --state /path/to/state")]
    Reconcile {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, conflicts_with = "abandon")]
        retry: bool,
        #[arg(long)]
        abandon: bool,
    },
}
#[derive(Debug, Args)]
pub struct TaskOptions {
    #[command(subcommand)]
    pub action: TaskAction,
}
#[derive(Debug, Subcommand)]
pub enum TaskAction {
    /// Create an isolated task checkout from a repository and base.
    Prepare {
        #[arg(long)]
        repository: PathBuf,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        branch: String,
        #[arg(long, default_value = "HEAD")]
        base: String,
    },
    /// Create a task checkout and provision its sandbox.
    Start(TaskStartOptions),
    /// Inspect retained task and sandbox state.
    Status(ExistingOptions),
    /// Inspect a retained export or live worker metadata.
    Inspect {
        /// Observe current worker metadata, including before the first export.
        #[arg(long, conflicts_with = "export")]
        live: bool,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        export: Option<PathBuf>,
    },
    /// Preserve work from a selected retained export.
    Salvage {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        export: PathBuf,
    },
    /// Refresh the task checkout from an explicit upstream revision.
    Refresh {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        upstream: String,
    },
    /// Export task work and delete its owned sandbox.
    Complete(ExistingOptions),
}
#[derive(Debug, Args)]
pub struct TaskStartOptions {
    #[arg(long)]
    pub repository: PathBuf,
    #[arg(long)]
    pub directory: PathBuf,
    #[arg(long)]
    pub branch: String,
    #[arg(long, default_value = "HEAD")]
    pub base: String,
    /// Nickel mission configuration file.
    #[arg(long)]
    pub config: PathBuf,
    /// Directory containing the mission runtime resources.
    #[arg(long)]
    pub resources: PathBuf,
    /// Host Codex executable to include in the runtime.
    #[arg(long)]
    pub codex: PathBuf,
    /// Host Codex code-mode executable to include in the runtime.
    #[arg(long)]
    pub codex_code_mode_host: PathBuf,
    /// Explicit environment lock receipt; otherwise use the mission default.
    #[arg(long)]
    pub lock: Option<PathBuf>,
    #[arg(long)]
    pub ladybom: Option<PathBuf>,
    /// Mission name selected from the Nickel configuration.
    #[arg(long, default_value = "dev")]
    pub mission: String,
}

#[derive(Debug, Args)]
pub struct ReviewOptions {
    #[command(subcommand)]
    pub action: ReviewAction,
}
#[derive(Debug, Args)]
pub struct ReviewExisting {
    /// Host directory containing retained Ladyshell sandbox state.
    #[arg(long)]
    pub state: PathBuf,
    /// Host-owned Tangled review configuration JSON file.
    #[arg(long)]
    pub config: PathBuf,
}
#[derive(Debug, Subcommand)]
pub enum ReviewAction {
    /// Reserve a checked signed successor for an existing ticket without publishing.
    Handoff {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        from_state: PathBuf,
        #[arg(long)]
        from_attempt: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        policy: PathBuf,
    },
    /// Publish an exact review round or resubmit it to an existing ticket.
    Submit {
        #[command(flatten)]
        existing: ReviewExisting,
        /// Actual allocated ticket key, required only when resubmitting.
        #[arg(long, requires = "resubmit")]
        ticket: Option<String>,
        #[arg(long)]
        created_at: String,
        #[arg(long)]
        target_base: String,
        #[arg(long, default_value = "main")]
        target_branch: String,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        body: String,
        #[arg(long, requires = "ticket")]
        resubmit: bool,
    },
    /// Record local host-owner metadata for an explicitly named immutable round.
    OwnerDecision {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long, value_parser = ["approved", "changes_requested", "withdrawn"])]
        decision: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        base: String,
        #[arg(long)]
        patch_uri: String,
        #[arg(long)]
        patch_cid: String,
        #[arg(long)]
        explanation: Option<String>,
    },
    /// Inspect the retained review and its remote status.
    Status(ReviewExisting),
    /// Collect review feedback, optionally delivering it to the task.
    Feedback {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        deliver: bool,
    },
    /// Recover an uncertain retained review operation.
    Reconcile(ReviewExisting),
    /// Bind an explicitly selected remote ticket to an uncertain creation intent.
    SelectTicket {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        ticket_uri: String,
        #[arg(long)]
        ticket_cid: String,
    },
    /// Retain an uncertain new-ticket intent without claiming remote rollback.
    AbandonTicket {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        explanation: String,
    },
    /// Explicitly bind retained review intents to newer same-owner credentials.
    RebindCredentials(ReviewExisting),
    /// Merge the exact reviewed head under a host publication policy.
    Merge {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long, default_value = "main")]
        branch: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        expected_target: String,
    },
    /// Observe exact current technical readiness without publishing.
    #[command(
        after_help = "Examples:\n  ladyshell review merge-check --state /path/to/state --config review.json --policy /path/to/policy.json --remote origin --branch main --head <HEAD_COMMIT> --expected-target <TARGET_COMMIT>"
    )]
    MergeCheck {
        #[command(flatten)]
        existing: ReviewExisting,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        remote: String,
        #[arg(long)]
        branch: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        expected_target: String,
    },
    /// Recover a retained merge attempt, optionally retrying it.
    MergeReconcile {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        retry: bool,
    },
}

#[derive(Debug, Args)]
pub struct StackOptions {
    #[command(subcommand)]
    pub action: StackAction,
}
#[derive(Debug, Subcommand)]
pub enum StackAction {
    /// Record a task checkpoint and its optional parent in a stack.
    Record {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        parent: Option<PathBuf>,
    },
    /// Inspect retained stack checkpoints and their relationships.
    Status {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Rebase a task checkpoint onto its selected stack parent.
    Restack {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        onto: Option<PathBuf>,
    },
}
