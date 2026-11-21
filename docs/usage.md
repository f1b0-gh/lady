# Using Ladyshell

Ladyshell prepares and executes tasks in OpenShell sandboxes. It checks source
selection, runtime identity, ownership, provider and effective policy before
execution. Ladybom's static inventory grants no network or installation rights.
Git credentials, signing keys and publication authority stay on the host.

## Prerequisites

Use the [build instructions](development.md) from the Lady repository root.
The native environment requires Linux, Nix, Bubblewrap (`bwrap`), `prlimit`,
OpenShell and an explicitly configured gateway/provider. The current CS backend
requires a local Docker Unix-socket daemon. Remote gateways, other Docker
transports and WASI need separate qualification. Do not expose the host Docker
socket, Nix daemon or raw credentials to the sandbox.

```sh
python3 scripts/check_sources.py
cargo build -p ladyshell-cli --locked
export PATH="$PWD/target/debug:$PATH"
nix --extra-experimental-features 'nix-command flakes' build \
  path:./nix#nickel --no-link --no-update-lock-file --no-write-lock-file
ladyshell help
ladyshell help apply
```

`--resources` selects trusted distribution inputs, normally the Lady root.
Keep `config/`, `nix/` and `resources/audit/` together. Native auditing also
requires the runtime sources, manifests, lock and bundled `vendor/nickel-util`.
Installing the CLI alone does not install this complete resource tree.
`lock` resolves the prepared evaluator offline; it does not build the evaluator
or an image automatically. Refused isolation never falls back to host execution.

## Create an environment

Choose absolute paths without symlink components. Keep private state outside
the project. Set the actual gateway, workspace and provider names in the config;
this example does not create or authorize them. Select existing source paths
and checks appropriate to your project.

A Python project with a `src/` directory can use `.sandbox/sandbox.ncl`:

```nickel
{
  schema_version = 1,
  name = "example-dev",
  sources = { include = ["src"], exclude = [] },
  tools = { python = { version = "3.12.15" } },
  missions.dev = {
    tools = ["python"], include = [], depends_on = [],
    checks = [["python", "-m", "compileall", "src"]],
  },
  sandbox = {
    gateway = "openshell", workspace = "default", provider = "your-provider",
  },
}
```

Only `.ncl` files beneath the config directory are exposed to the confined
Nickel evaluator. Absolute host imports, symlink inputs and omitted cache paths
are refused. Tool versions must exist in the selected recipes. Rust selections
include 1.98.1 (Cargo 1.98.0) and 1.99.1 (Cargo 1.99.1); adding a tool does not
allow downloading its dependencies. See [dependency preparation](dependencies.md).

Set the two Codex paths to actual native ELF files, not wrapper scripts or links:

```sh
LADY_ROOT="$PWD"
PROJECT_DIR=/absolute/project
STATE_DIR=/absolute/private/project-state
CODEX_BINARY=/absolute/tools/codex
CODEX_HOST_BINARY=/absolute/tools/codex-code-mode-host
CONFIG="$PROJECT_DIR/.sandbox/sandbox.ncl"
LOCK=/absolute/private/project.dev.lock.json

ladyshell lock --config "$CONFIG" --project "$PROJECT_DIR" \
  --state "$STATE_DIR" --resources "$LADY_ROOT" --mission dev \
  --codex "$CODEX_BINARY" --codex-code-mode-host "$CODEX_HOST_BINARY" --lock "$LOCK"
ladyshell plan --config "$CONFIG" --project "$PROJECT_DIR" \
  --state "$STATE_DIR" --resources "$LADY_ROOT" --mission dev \
  --codex "$CODEX_BINARY" --codex-code-mode-host "$CODEX_HOST_BINARY" --lock "$LOCK"
ladyshell apply --config "$CONFIG" --project "$PROJECT_DIR" \
  --state "$STATE_DIR" --resources "$LADY_ROOT" --mission dev \
  --codex "$CODEX_BINARY" --codex-code-mode-host "$CODEX_HOST_BINARY" --lock "$LOCK"
```

Inspect the plan before applying it. `lock` binds configuration, recipes and
binary identities; it is not permission to execute. With `--ladybom`, the project
is also read to verify the supplied report against an independent source snapshot.
`apply` requires a valid plan, builds the image, creates the sandbox and verifies
its effective policy before publishing state. Changed inputs require explicit
reconciliation; existing states are never silently migrated.

## Run, inspect and recover work

```sh
ladyshell status --state "$STATE_DIR"
ladyshell run --state "$STATE_DIR" -- python -m compileall src
ladyshell check --state "$STATE_DIR"
ladyshell shell --state "$STATE_DIR"
ladyshell chat --state "$STATE_DIR"
ladyshell resume --state "$STATE_DIR"
ladyshell sync --state "$STATE_DIR" --dry-run
ladyshell sync --state "$STATE_DIR"
ladyshell sync --state "$STATE_DIR" --export
```

`check` uses the checks retained by `apply`, stops at the first failure and
preserves its exit code. An empty check list is refused. `run` passes arguments
after `--` directly to OpenShell in `/sandbox/workspace/project`; its timeout
is 300 seconds by default, with `--timeout` accepting 1–86400 seconds. Sessions
hold a lease that blocks environment mutation. Provider credentials remain in
the gateway; the agent receives an opaque reference and account routing identity.

`sync` applies nonconflicting changes to the host checkout by default. `--export`
only retains an export; `--json` selects machine output. `--dry-run` leaves the
checkout unchanged but writes an export and updates `last_sync`. Source changes
are compared against the common base; different concurrent edits refuse the
application rather than guessing a merge. Existing host modes are preserved.

Exports and pre-change backups remain in the private state. An interrupted
checkout application leaves `checkout-pending.json`; repeat `sync` to recover
it, even if the sandbox is unavailable. Do not remove journals to bypass refusal.
Publication is atomic per file, not across the entire checkout; avoid concurrent
host edits. Git metadata, excluded paths, links and special files are not
exported. Exclusions are not a complete secret detector: independently select
safe source contents. Limits are 5,000 files, 16 MiB per file and 256 MiB total.

```sh
ladyshell run --state "$STATE_DIR" --sync --timeout 600 -- python experiment.py
```

`--sync` also works with `shell`, `chat` and `resume`. Success exports and applies
changes; a failed command retains an export without applying it. The experiment
is never retried automatically. A pre-existing pending checkout operation needs
explicit recovery first. Manual sync never stages or commits Git changes.

## Continuous Sandboxing

CS replaces source while retaining a compatible environment and caches.
Processes and conversation memory do not survive checkpoints. Begin with the
current native `lock → plan → apply` flow, then enroll the state:

```sh
ladyshell cs init --state "$STATE_DIR" --task task-123
ladyshell cs checkpoint --state "$STATE_DIR" --attempt checkpoint-1 --epoch 0
ladyshell cs status --state "$STATE_DIR"
```

Finish managed sessions before checkpointing. The checkpoint retains exports
before and after stop/start, terminates old writers and fences execution.
Reconcile the retained export on the host. Keep `.git`, `.jj`, secrets and
host sockets outside the next source tree. Create a context file outside it:

```json
{
  "objective": "Continue after upstream changes",
  "upstream_commit": "host-selected-revision",
  "next_steps": ["Preserve both intended behaviors", "Run declared checks"]
}
```

Select the full candidate and reviewed lock with the same environment inputs:

```sh
ladyshell cs refresh --state "$STATE_DIR" --attempt refresh-1 \
  --config "$CONFIG" --project /absolute/candidate --resources "$LADY_ROOT" \
  --codex "$CODEX_BINARY" --codex-code-mode-host "$CODEX_HOST_BINARY" \
  --lock "$LOCK" --context /absolute/private/context.json
# If the returned phase is refreshed, use its acknowledged epoch:
ladyshell cs resume --state "$STATE_DIR" --epoch 1
# If it is replacement_required:
ladyshell cs replace --state "$STATE_DIR"
```

Replacement creates and verifies a fresh owned sandbox, advances the epoch and
retires the recorded old instance. Interrupted retirement blocks execution;
repeat the same command to recover. Retry checkpoint/refresh with the same
attempt and exact inputs. If sources changed during stop/start, inspect both
exports before `cs reconcile-checkpoint --state STATE --before-tree HASH --after-tree HASH`.
That acknowledgement does not replace the separate candidate/context selection.

Context is bounded to 256 KiB and grants no authority. Agents read
`/sandbox/workspace/.ladyshell-cs/context.json`; chat/resume use this explicit
handoff. Incomplete dependency analysis refuses warm replacement. Current limits:
regular source files, no explicit source exclusions in this profile, at most
32 handoffs per incarnation. Native dependency preparation binds full sources,
so changed prepared projects conservatively require a fresh sandbox.

## Catalog and cleanup

```sh
ladyshell list --json
ladyshell manage refresh
ladyshell manage list --project "$PROJECT_DIR"
ladyshell manage show ID
ladyshell manage annotate ID --label team=core --note "Keep this work"
ladyshell manage history ID
ladyshell destroy --state "$STATE_DIR"
ladyshell destroy --all --dry-run
```

`list` reads registered local states without querying OpenShell. `manage` keeps
an explicit SQLite snapshot under `$XDG_STATE_HOME/ladyshell/management`
(or `~/.local/state/ladyshell/management`). Only `refresh` creates it; stale or
missing observations never establish deletion. Labels, notes and reversible
archiving are host metadata. `status` performs the separate provider observation.

`destroy` exports work and deletes only the verified owned sandbox; state and
exports survive. `--discard-work` explicitly abandons export. `destroy --all`
affects registered current instances, refuses incomplete discovery and reports
per-instance failures. Historical retained instances lacking ownership/export
proof remain blocked. No unrelated sandbox is discovered or adopted for cleanup.

## Host publication and recovery

For GitHub/Jujutsu setup and reviewed integration, use
[Ladyhost](../crates/ladyhost/README.md). Ladyshell also supports explicit Git
publication to a configured `knot` remote. Use a dedicated clean host checkout
on the selected branch, with host Git identity and credentials already prepared:

```sh
ladyshell run --state "$STATE_DIR" --sync \
  --publish knot --branch agent/experiment --message "Publish experiment" \
  --policy /absolute/private/publish.json -- python experiment.py
```

The three publication options require `--sync`. A host policy outside exported
sources can select signing and independent checks; neither is inferred from
agent reports. Example policy:

```json
{
  "schema_version": 1,
  "signing": {
    "key": "/host/keys/signer", "allowed_signers": "/host/keys/allowed_signers",
    "principal": "selected-principal", "program": "/usr/bin/ssh-keygen"
  },
  "checks": {"commands": [["python", "-m", "compileall", "src"]], "timeout": 60}
}
```

Checks run in a separate disposable confined verifier. Agent-editable tests alone
are not independent acceptance criteria; select trusted assertions on the host.
Publication binds exact changed bytes/modes, disables hooks/content filters and
pushes the exact commit with the original remote-ref lease. Signing is required
only when selected by policy; a required signing failure never falls back.
A signature proves neither correctness nor human review. No PR or merge is implied.

```sh
ladyshell publication status --state "$STATE_DIR"
ladyshell publication reconcile --state "$STATE_DIR"
ladyshell publication reconcile --state "$STATE_DIR" --retry
ladyshell publication check --state "$STATE_DIR" --export "$EXPORT" --policy "$POLICY"
ladyshell publication publish --state "$STATE_DIR" --export "$EXPORT" \
  --policy "$POLICY" --remote knot --branch agent/experiment --message "Publish checked work"
```

Uncertain pushes retain receipts and block new automatic publication. Observe
before retrying; retry retains the same object and lease. `reconcile --abandon`
archives an attempt without undoing remote effects or discarding evidence.
Changed signing trust requires a new explicit policy/attempt, not edited receipts.

## Managed tasks and review

`task prepare --repository REPO --directory TASK --branch agent/task --base main`
creates an isolated worktree. `task start` additionally provisions its environment.
Use `task inspect --state TASK/state --export EXPORT` for verified retained files;
`--live` requires the worker's preview capability and provides metadata only.
`task complete --state TASK/state` exports and removes its owned sandbox.

`stack record`, `stack status` and `stack restack` retain parent identities.
Changed parents block descendant publication. Restack creates a separate candidate
requiring new checks, signatures and review; it preserves earlier work.
`task refresh` supports independent tasks only, not retained stack membership.
Use `ladyshell help task` and `ladyshell help stack` for exact inputs.

Tangled review uses an explicitly trusted host configuration. Schema 2 requires
an external compatible AT host connector; Lady does not install or authorize
that service. Credentials and its configuration remain outside exported sources.
Use `review submit`, `status`, `feedback`, and `reconcile` for immutable rounds.
Resubmission selects both `--resubmit` and the actual `--ticket`; an old approval
cannot authorize a new head. Feedback is untrusted data, never host instructions.

Select `require_owner_review: true` before submitting to require an explicit
local `review owner-decision` for the exact head/base/patch. These decisions are
host metadata, not native provider approvals. Keep the command outside agent
capabilities. Without this policy, human review remains unknown/unsupported.
`review merge-check` observes current readiness; `review merge` is a separate
explicit host operation that rechecks signatures, checks, review and exact refs.
Unknown outcomes require readback. Never replay uncertain ticket/patch writes
or edit recovery journals. Use each subcommand's help for its required bindings.

## Audits and development checks

[Native audit usage](audits/usage.md) distinguishes document validation from
confined execution and explains recovery. [The run contract](audits/run-format.md)
defines retained evidence; successful verification is not proof of authenticity.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Native Nickel tests require Nix and Bubblewrap; missing prerequisites are failures,
not passing skips. Fixture tests do not establish a live gateway qualification.
