# Using Ladyshell

Ladyshell prepares and executes tasks in OpenShell sandboxes. It checks source
selection, runtime identity, ownership, provider and effective policy before
execution. Ladybom's static inventory grants no network or installation rights.
Git credentials, signing keys and publication authority stay on the host.

Use `ladyshell help COMMAND [SUBCOMMAND]` for exact syntax, or add `--help`
to a command. Help does not load configuration, credentials or sandbox state.
`--version` prints the installed version. The retired `artifact` command provides
local help through `ladyshell help artifact`, `ladyshell artifact --help` or
`ladyshell artifact -h`. Other invocations exit with status 2 and guidance to use
`ladyboot` directly; they never start an external executable.

## First run

1. Prepare the [native tools and trusted resources](#prerequisites).
2. [Create an environment](#create-an-environment): select your project, private
   state, mission and existing OpenShell gateway/workspace/provider, then follow
   `lock → plan → apply`. Inspect the plan before applying it.
3. [Run and retain work](#run-inspect-and-recover-work) using that same state
   directory. Start with `status`, then a configured `check` or explicit `run`.

The [glossary](#glossary) explains the configuration terms. For an inventory
without a sandbox, start with [Ladybom](../crates/ladybom-cli/README.md).

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

`lock`, `plan` and `apply` share these options:

| Option | Meaning |
| --- | --- |
| `--config FILE` | Required Nickel configuration; its directory bounds evaluator imports. |
| `--project DIR` | Required host checkout from which the configured sources are selected. |
| `--state DIR` | Required private directory for this environment's state, exports and recovery records. Reuse it for later commands. |
| `--resources DIR` | Required trusted Lady resource tree described above. |
| `--codex FILE`, `--codex-code-mode-host FILE` | Both required; native executables whose identities enter the lock. |
| `--mission NAME` | Select a configured mission; defaults to `dev`. |
| `--lock FILE` | Override the lock location. Otherwise `sandbox.ncl` with mission `dev` uses sibling `sandbox.dev.lock.json`. `lock` writes it; `plan` and `apply` verify it. |
| `--ladybom FILE` | Optional Ladybom JSON inventory, verified against the independently selected sources and bound into the lock. Use the same input throughout preparation. |

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

`status`, `check`, `run`, `shell`, `chat` and `resume` require `--state DIR`.
`shell` opens an interactive shell, `chat` starts Codex and `resume` opens its
session-resumption flow. The last three take no trailing program arguments.
Only `run` takes `--timeout`; `check` selects the retained mission checks without
a command argument.

`sync` applies nonconflicting changes to the host checkout by default. `--export`
only retains an export; `--json` selects machine output. `--dry-run` leaves the
checkout unchanged but writes an export and updates `last_sync`. Source changes
are compared against the common base; different concurrent edits refuse the
application rather than guessing a merge. Existing host modes are preserved.
For `sync` alone, omitting `--state` selects the sandbox associated with the
current project. `--dry-run` and `--export` are mutually exclusive.

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
`--cleanup` on `run`, `shell`, `chat` or `resume` requires `--sync` and requests
export and deletion of the owned sandbox after the session finishes, including
after a failed command. Retained state and exports remain available. Leave it
unset when you intend to continue using the environment.

For fixed host-approved commands with reconnectable history and output,
see [retained OpenShell execution](retained-execution.md).

## Continuous Sandboxing

CS replaces source while retaining a compatible environment and caches.
Processes and conversation memory do not survive checkpoints. Begin with the
current native `lock → plan → apply` flow, then enroll the state:

```sh
ladyshell cs init --state "$STATE_DIR" --task task-123
ladyshell cs checkpoint --state "$STATE_DIR" --attempt checkpoint-1 --epoch 0
ladyshell cs status --state "$STATE_DIR"
```

`cs init` requires the stable `--task` identifier. `checkpoint` requires a unique
`--attempt` for a new operation and the current `--epoch` from `cs status`;
reuse that attempt only to recover the same operation. `cs status`, `resume`
and `replace` all require `--state`; `resume` also requires the acknowledged
`--epoch`. These generation checks prevent a stale session from resuming work.

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

`cs refresh` uses all the preparation options in the table above, plus required
`--attempt` and `--context FILE`. Here `--project` selects the complete next
source tree. `reconcile-checkpoint` requires both `--before-tree` and
`--after-tree` hashes from the retained discrepancy, never guessed values.

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

All `manage` commands print JSON. `--database FILE` selects another SQLite file
in a private directory and can appear before or after its subcommand:

| Command | Options and selection |
| --- | --- |
| `manage refresh` | Import current local associations into the catalog. No filters. |
| `manage list` | Filter by `--project DIR`, `--status retained\|deletion-pending\|deleted`, or `--label KEY=VALUE`. `--include-archived` and `--include-deleted` reveal hidden entries; selecting `--status deleted` also reveals deleted entries. `--limit` defaults to 100 (range 1–1000); `--after ID` continues after a catalog identity. |
| `manage show ID` | Inspect one identity, including archived or deleted entries. |
| `manage annotate ID` | Set repeatable `--label KEY=VALUE`, remove repeatable `--remove-label KEY`, or replace `--note TEXT`. `--archive` and `--unarchive` are mutually exclusive and do not delete a sandbox. |
| `manage history ID` | Read changes after the numeric `--after` sequence (default 0), with `--limit` defaulting to 100 (range 1–1000). |

`destroy` exports work and deletes only the verified owned sandbox; state and
exports survive. `--discard-work` explicitly abandons export. `destroy --all`
affects registered current instances, refuses incomplete discovery and reports
per-instance failures. Historical retained instances lacking ownership/export
proof remain blocked. No unrelated sandbox is discovered or adopted for cleanup.
Select exactly one of `--state DIR` and `--all`. `--dry-run` is available only
with `--all` and makes no writes or OpenShell calls. `delete` is an alias for
`destroy`; `--discard-work` can be used for either selection and skips export.

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

`--publish REMOTE` requires `--sync`, `--branch NAME` and `--message TEXT` on
`run`, `shell`, `chat` and `resume`. The branch must be the existing selected
checkout branch; the message becomes the commit message. Optional `--policy FILE`
requires `--publish`. This host policy outside exported sources can select
signing and independent checks; neither is inferred from agent reports.
Example policy:

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
Every `publication` command requires `--state`. `check` requires both a retained
`--export DIR` and `--policy FILE`. `publish` requires `--export`, `--remote`,
`--branch` and `--message`; its `--policy` is optional. `reconcile` without flags
observes the retained attempt; `--retry` and `--abandon` are mutually exclusive.

## Managed tasks and review

`task prepare --repository REPO --directory TASK --branch agent/task --base main`
creates an isolated worktree in `TASK/project`, with state in `TASK/state`.
The repository, directory and new branch are required; `--base` defaults to
`HEAD`. Keep `TASK` outside the source checkout. `task start` takes the same
options plus required `--config`, `--resources`, `--codex` and
`--codex-code-mode-host`, and optional `--mission` (default `dev`), `--lock`
and `--ladybom`. It prepares the worktree and provisions its environment using
an existing lock.

Other task commands require `--state TASK/state`. `status` reads retained task
and recovery state. `inspect --export EXPORT` selects verified retained files;
without `--export`, it uses `last_sync`. Its mutually exclusive `--live` mode
requires the worker's preview capability and provides metadata only.
`salvage --export EXPORT` applies selected retained work to the host checkout;
`refresh --upstream REVISION` explicitly selects an upstream revision.
`complete` exports and removes the owned sandbox.

`stack record`, `stack status` and `stack restack` retain parent identities.
Changed parents block descendant publication. Restack creates a separate candidate
requiring new checks, signatures and review; it preserves earlier work.
`task refresh` supports independent tasks only, not retained stack membership.
Each `stack` command requires `--directory DIR` for its manifest. `record` also
requires `--state DIR`, whose checkpoint must have a confirmed publication;
optional `--parent STATE` selects an already recorded parent. `restack` requires
`--state` and uses its recorded parent unless `--onto PARENT_STATE` selects another
recorded checkpoint. `status` needs only the stack directory.

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
or edit recovery journals.

All `review` commands except `merge-reconcile` require `--state DIR` and
`--config FILE` for the host-owned review JSON configuration:

| Command | Additional inputs and behavior |
| --- | --- |
| `submit` | Requires `--created-at YYYY-MM-DDTHH:MM:SSZ`, `--target-base COMMIT` and `--title TEXT`. `--target-branch` defaults to `main`; `--body` defaults to empty. `--resubmit` and `--ticket KEY` require each other. |
| `status`, `reconcile` | Observe a retained round or recover an uncertain operation. No additional options. |
| `feedback` | Collect feedback; optional `--deliver` also sends it into the task. |
| `owner-decision` | Requires `--decision approved\|changes_requested\|withdrawn` and exact `--head`, `--base`, `--patch-uri`, `--patch-cid`; optional `--explanation TEXT` records the reason. |
| `handoff` | Reserve a successor using required `--from-state`, `--from-attempt`, `--head`, `--base` and `--policy`; does not publish it. |
| `select-ticket` | Resolve uncertain ticket creation with required `--ticket-uri` and `--ticket-cid`. |
| `abandon-ticket` | Retain an uncertain creation intent with required `--explanation`; does not claim remote rollback. |
| `rebind-credentials` | Explicitly bind retained intents to newer credentials for the same owner. |
| `merge-check`, `merge` | Require `--policy`, `--remote`, `--head` and `--expected-target` to bind exact commits and host acceptance policy. `--branch` is required for `merge-check`, but defaults to `main` for `merge`. |
| `merge-reconcile` | Requires only `--state`; optional `--retry` retries the retained merge attempt. |

## Dependency validation and system images

`deps prune validate --state DIR --plan FILE` runs the declared checks inside a
verified sandbox against a Ladybom removal plan. It prints the validation receipt
to stdout unless `--output FILE` selects a new receipt file. Exit status is 0 for
passed checks and 2 for a completed validation whose checks failed. Use
[dependency graphs](dependency-graphs.md) to analyze and plan removals first;
[dependency preparation](dependencies.md) explains how inputs reach the sandbox.

```sh
ladyshell deps prune validate --state "$STATE_DIR" \
  --plan /absolute/private/prune-plan.json --output /absolute/private/prune-receipt.json
```

Use `ladyboot` directly for profiles, locks and bootc image construction; see its
[command guide](../crates/ladyboot/README.md). `ladyshell artifact` no longer
forwards commands or reads `LADYSHELL_BOOTC_BIN`. Update existing scripts to invoke
the trusted Ladyboot executable directly. Ladyboot builds system images;
Ladyshell's `apply` prepares OpenShell sandboxes.

## Audits and development checks

[Native audit usage](audits/usage.md) distinguishes document validation from
confined execution and explains recovery. [The run contract](audits/run-format.md)
defines retained evidence; successful verification is not proof of authenticity.

`audit plan --state DIR` previews scope and missing capabilities; `audit run`
uses the same state and executes the audit. Both accept `--profile quick|targeted`
to override the profile retained in the audit configuration. Other audit commands
use positional paths: `verify RUN`, `recover RUN`, `compare OLD NEW`,
`export RUN --destination NEW_DIR`, and `validate findings|coverage FILE`.
`recover` resumes cleanup without replaying the target. `validate` checks the
document format; `verify` checks a native run's evidence. Export destinations
must be new directories. See the audit guide for configuration and result limits.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

Native Nickel tests require Nix and Bubblewrap; missing prerequisites are failures,
not passing skips. Fixture tests do not establish a live gateway qualification.

## Glossary

| Term | Meaning here |
| --- | --- |
| Mission | A named selection of tools, source additions, dependencies on other missions and checks in the Nickel configuration. |
| State | The private host directory retaining an environment's identities, operation journals and exports. Reuse it for later commands. |
| Resources | The trusted Lady configuration, Nix recipes and runtime inputs selected by `--resources`. |
| Lock | A receipt binding configuration, recipes and binary identities. It records inputs; it does not authorize execution. |
| Gateway / workspace | The explicitly selected OpenShell context in which Ladyshell manages the sandbox. |
| Provider | The configured OpenShell provider supplying access to the model service; its credentials stay on the host/gateway. |
| Export | Retained sandbox changes for inspection or application to the host checkout. An export alone does not change that checkout. |
