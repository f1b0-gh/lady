use clap::{Args, Subcommand, ValueEnum};
use ladyshell::{
    error::{Error, Result},
    execution::{self, Admission, Invocation, Key, OwnerFence, Store, Stream, TaskDefinition},
    files,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const TASKS_FILE_LIMIT: usize = 3 * 1024 * 1024;
const INVOCATION_FILE_LIMIT: usize = 32 * 1024;
const OWNER_FILE_LIMIT: usize = 4096;

#[derive(Debug, Args)]
pub struct ExecutionArgs {
    #[command(subcommand)]
    command: ExecutionCommand,
}

#[derive(Debug, Subcommand)]
enum ExecutionCommand {
    /// Install an approved task catalogue for a verified native environment.
    Install {
        /// Existing Ladyshell environment state.
        #[arg(long)]
        state: PathBuf,
        /// New private receiver directory outside the project and environment state.
        #[arg(long)]
        receiver: PathBuf,
        /// Host-approved JSON array of task definitions.
        #[arg(long)]
        tasks: PathBuf,
    },
    /// Admit original intent and start one detached supervisor on first acceptance.
    Submit {
        #[command(flatten)]
        receiver: Receiver,
        /// JSON file containing only the original invocation and its catalogue selection.
        #[arg(long)]
        invocation: PathBuf,
        /// Reference chosen by the trusted host for this admission.
        #[arg(long)]
        reference: String,
        /// Exclusive host admission deadline in Unix seconds.
        #[arg(long)]
        admit_before: u64,
        #[command(flatten)]
        authority: Authority,
        /// Exact positive claim epoch established by the host.
        #[arg(long)]
        claim: u64,
    },
    /// Read retained history and current supervisor presence.
    Status(SelectedInvocation),
    /// Read a verified byte range of retained stdout or stderr.
    Output {
        #[command(flatten)]
        invocation: SelectedInvocation,
        /// Retained stream to read.
        #[arg(long)]
        stream: OutputStream,
        /// Starting byte offset in the retained stream.
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Maximum bytes to return, up to 1048576.
        #[arg(long)]
        length: u32,
    },
    /// Establish scope ownership and advance claim epochs as the trusted host.
    Fence {
        #[command(subcommand)]
        command: FenceCommand,
    },
    /// Consume orphaned work or repair a completed invocation's state fence.
    Recover(SelectedInvocation),
    /// Record evidence of the externally stopped original runtime and clear its fence.
    Reconcile {
        #[command(flatten)]
        invocation: SelectedInvocation,
        /// Host reason for reconciling this uncertain invocation.
        #[arg(long)]
        reason: String,
    },
    #[command(hide = true)]
    Worker(SelectedInvocation),
}

#[derive(Debug, Args)]
struct Receiver {
    /// Absolute path of the private receiver.
    #[arg(long)]
    receiver: PathBuf,
    /// Independently pinned receiver identity from installation.
    #[arg(long)]
    receiver_id: String,
}

impl Receiver {
    fn open(&self) -> Result<Store> {
        Store::open(&self.receiver, &self.receiver_id)
    }
}

#[derive(Debug, Args)]
struct SelectedInvocation {
    #[command(flatten)]
    receiver: Receiver,
    /// Original invocation scope.
    #[arg(long)]
    scope: String,
    /// Original invocation ID within the scope.
    #[arg(long)]
    id: String,
}

impl SelectedInvocation {
    fn open(self) -> Result<(Store, Key)> {
        let store = self.receiver.open()?;
        let key = Key {
            scope: self.scope,
            id: self.id,
        };
        Ok((store, key))
    }
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct Authority {
    /// Use standalone host authority for this scope.
    #[arg(long)]
    standalone: bool,
    /// Read the host-selected owner fence from a bounded JSON file.
    #[arg(long)]
    owner: Option<PathBuf>,
}

impl Authority {
    fn owner(self) -> Result<Option<OwnerFence>> {
        self.owner
            .map(|path| {
                Ok(serde_json::from_value(input_json(
                    &path,
                    OWNER_FILE_LIMIT,
                )?)?)
            })
            .transpose()
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputStream {
    Stdout,
    Stderr,
}

impl From<OutputStream> for Stream {
    fn from(stream: OutputStream) -> Self {
        match stream {
            OutputStream::Stdout => Self::Stdout,
            OutputStream::Stderr => Self::Stderr,
        }
    }
}

#[derive(Debug, Args)]
struct FenceScope {
    #[command(flatten)]
    receiver: Receiver,
    /// Scope whose host authority is being administered.
    #[arg(long)]
    scope: String,
    #[command(flatten)]
    authority: Authority,
}

#[derive(Debug, Subcommand)]
enum FenceCommand {
    /// Bind the scope to standalone or a selected owner generation.
    Bind(FenceScope),
    /// Advance the scope's claim epoch under its current owner.
    Advance {
        #[command(flatten)]
        scope: FenceScope,
        /// New claim epoch, with zero reserved for initialization.
        #[arg(long)]
        claim: u64,
    },
}

fn input_json(path: &Path, limit: usize) -> Result<Value> {
    ladyshell::json::parse(&files::read_limited(path, limit)?)
}

fn spawn_worker(store: &Store, key: &Key) -> Result<()> {
    let mut command = Command::new("/proc/self/exe");
    command
        .args(["execution", "worker", "--receiver"])
        .arg(store.directory())
        .args(["--receiver-id", &store.binding().receiver_id])
        .arg(format!("--scope={}", key.scope))
        .arg(format!("--id={}", key.id))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ladyshell::process::detached_session(&mut command);
    command.spawn().map_err(|source| {
        Error::from(source).context(
            "Invocation was retained, but supervisor startup failed. Inspect its original history",
        )
    })?;
    Ok(())
}

pub fn run(args: ExecutionArgs) -> Result<Option<Value>> {
    let response = match args.command {
        ExecutionCommand::Install {
            state,
            receiver,
            tasks,
        } => {
            let tasks: Vec<TaskDefinition> =
                serde_json::from_value(input_json(&tasks, TASKS_FILE_LIMIT)?)?;
            let binding = execution::install(&state, &receiver, tasks)?;
            let store = Store::open(&files::absolute(&receiver)?, &binding.receiver_id)?;
            let mut definitions = BTreeMap::new();
            for task in &store.catalog().tasks {
                definitions.insert(&task.id, store.catalog().definition_digest(&task.id)?);
            }
            json!({"binding":binding, "definitions":definitions})
        }
        ExecutionCommand::Submit {
            receiver,
            invocation,
            reference,
            admit_before,
            authority,
            claim,
        } => {
            let invocation: Invocation =
                serde_json::from_value(input_json(&invocation, INVOCATION_FILE_LIMIT)?)?;
            let store = receiver.open()?;
            let accepted = if let Some(record) = store.lookup(&invocation)? {
                execution::Acceptance {
                    record,
                    is_new: false,
                }
            } else {
                let admission = Admission {
                    reference,
                    admit_before,
                    owner: authority.owner()?,
                    claim,
                };
                execution::submit(&store, &invocation, &admission)?
            };
            if accepted.is_new {
                spawn_worker(&store, &invocation.key())?;
            }
            serde_json::to_value(accepted)?
        }
        ExecutionCommand::Status(selected) => {
            let (store, key) = selected.open()?;
            serde_json::to_value(execution::status(&store, &key)?)?
        }
        ExecutionCommand::Output {
            invocation,
            stream,
            offset,
            length,
        } => {
            let (store, key) = invocation.open()?;
            let bytes = store.read_output(&key, stream.into(), offset, length)?;
            io::stdout().lock().write_all(&bytes)?;
            return Ok(None);
        }
        ExecutionCommand::Fence { command } => match command {
            FenceCommand::Bind(options) => {
                let store = options.receiver.open()?;
                let owner = options.authority.owner()?;
                store.bind_owner(&options.scope, owner.as_ref())?;
                json!({"scope":options.scope, "owner":owner})
            }
            FenceCommand::Advance { scope, claim } => {
                let store = scope.receiver.open()?;
                let owner = scope.authority.owner()?;
                store.advance_claim(&scope.scope, owner.as_ref(), claim)?;
                json!({"scope":scope.scope, "owner":owner, "claim":claim})
            }
        },
        ExecutionCommand::Recover(selected) => {
            let (store, key) = selected.open()?;
            serde_json::to_value(execution::recover(&store, &key)?)?
        }
        ExecutionCommand::Reconcile { invocation, reason } => {
            let (store, key) = invocation.open()?;
            serde_json::to_value(execution::reconcile(&store, &key, &reason)?)?
        }
        ExecutionCommand::Worker(selected) => {
            let (store, key) = selected.open()?;
            execution::worker(&store, &key)?;
            return Ok(None);
        }
    };
    Ok(Some(response))
}
