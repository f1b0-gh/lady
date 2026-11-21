# Ladyhost

Set up GitHub projects and publish/integrate signed Jujutsu candidates from the
host. Forge tokens, signing keys and repository authority stay outside sandboxes.
[Ladyshell](../../docs/usage.md) owns sandbox execution and source handoff.

The Rust library depends on pinned upstream jjpr; it has no Ladyshell, Nickel,
LO checkout or direct Clap dependency. Two executables share it:

- `ladyhost`: setup, diagnosis, owned-resource removal and conflict inspection.
- `ladyhost-jjpr`: candidate planning/publication, Git helper and exact integration.

A repository can also be published with your existing SSH key and jj directly.
Ladyhost is for workflows requiring an App, checks and integration after review.

## Build and prerequisites

From the Lady repository root:

```sh
python3 scripts/check_sources.py
cargo build -p ladyhost --locked --release --bins
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/ladyhost target/release/ladyhost-jjpr "$HOME/.local/bin/"
ladyhost help
ladyhost help init
```

Select Git, `/usr/bin/openssl`, `ssh-keygen`, `sha256sum`, GitHub CLI and jj on
the host. Existing fixture qualification covers Linux and jj 0.47.1; other
platforms/tool versions need qualification. `--gh` and `--jj` select explicit
binaries; otherwise PATH resolution is retained with tool hashes. Keep a durable
binary location: the private Git credential helper binds that executable.

## Initialize a project

Create the repository first and select its actual local Git checkout root.
Choose a globally unique lowercase App name. Declare your project's checks and
any dependency/tool preparation needed on the Ubuntu GitHub Actions runner.
This Python check is an example, not a default project policy:

```sh
ladyhost init --repo OWNER/REPO --app-name owner-project-host \
  --workspace /absolute/project --target main \
  --check '["python3","-m","unittest","discover","-s","tests"]' \
  --state "$HOME/.local/state/ladyhost/project"
```

The command prints a plan without contacting GitHub or creating state. Repeat
with `--apply` to execute it. `--spec FILE` accepts JSON `setup::Spec` with the
same selections and absolute paths; `--json` selects machine output. Private
state must be outside sources. Setup preserves the source checkout and Git config.

The guided flow:

1. Authorize an isolated owner GitHub CLI session for administration/signing-key
   registration; no existing personal CLI login is required.
2. Follow the printed local manifest link, create the private App and install it
   on only the selected repository. Setup captures its ID, PEM and installation.
   Ordinary publisher tokens exclude workflow writes and administration.
3. Generate a separate SSH signing key or select an existing private Ed25519 key
   with `--signing-key`. Register its public half with the owner. Git transport
   remains HTTPS; SSH is the signature format.
4. Prepare a signed workflow commit in a private checkout. Repeated `--check`
   arguments run sequentially. Alternatively adopt an existing exact-push workflow
   with `--adopt-workflow --workflow-path PATH --ci-check NAME`; its bytes are
   preserved and successful matching CI is required.
5. Verify the exact candidate's signature and Actions CI. Protected targets use
   a setup PR and their existing review process. Unprotected targets use an exact
   expected-ref update. Empty remotes require a local initial commit and create
   the selected target before CI/final protection.
6. Install/read back separate App-only update and quality rules: fresh native
   approval, signed linear history, the App's `fixture/verify` and selected Actions
   check, with no quality bypass. Existing rules remain; additional effective
   policies need explicit adoption.
7. Prepare the private Git/jj checkout, `config.json` and
   `integration-defaults.json`; run diagnosis and remove isolated owner credential
   files. This does not revoke account-wide GitHub CLI authorization.

Pending browser, installation, CI or review work returns code 2 with a next action.
Resume the same setup, keeping its receipts:

```sh
ladyhost init --state "$HOME/.local/state/ladyhost/project" --apply
ladyhost doctor --state "$HOME/.local/state/ladyhost/project"
```

`doctor` inspects custody, tools/signer, App scope, workflow bytes and effective
rules; it does not repair drift or authorize merging. Runtime App visibility into
the full bypass roster can be limited and is reported. Exit 0 means healthy,
plan or uninstalled; 2 pending/incomplete/unknown; 1 failure.
`doctor --config FILE --integration FILE [--workflow FILE]` inspects an existing
adapter configuration without adopting its resources. Workflow evidence is JSON
with `path` and exact UTF-8 `content`.

Private repository rulesets depend on the GitHub plan. Public fixtures do not
qualify those permissions. Disabled Actions or organization policy are reported,
not bypassed. Setup is not a background scheduler or unattended approval service.

### Command options

Use `ladyhost help COMMAND` or `ladyhost COMMAND --help` for offline help.
Options take separate values (`--state PATH`); only `--check` may repeat.
`--json` is available on all four commands below and prints machine-readable
results instead of the human summary.

| Command | Required selection and optional behavior |
| --- | --- |
| `init` | `--state DIR` selects private setup state. For new setup, supply `--repo OWNER/REPO`, `--app-name SLUG` and project checks, or use `--spec FILE`. Without `--apply`, show the plan; with it, perform or resume setup. |
| `doctor` | Use `--state DIR`, or `--config FILE --integration FILE` for an existing host configuration and retained integration defaults. The latter accepts `--workflow FILE`, a JSON object with `path` and exact UTF-8 `content`. |
| `uninstall` | `--state DIR` selects owned resources; `--apply` performs the removal shown by the default plan. |
| `review-conflict` | `--config FILE --candidate FULL_OID` selects the host package and exact commit. `--render` produces review text before signing; add `--json` to include it in structured output. |

New `init` setups accept these project selections:

| Option | Meaning and default |
| --- | --- |
| `--repo OWNER/REPO` | Required existing GitHub repository. |
| `--app-name SLUG` | Required globally unique App name: lowercase ASCII letters, digits and hyphens, at most 34 characters. |
| `--workspace PATH` | Actual local Git checkout root; defaults to the current directory. |
| `--target BRANCH` | Target branch; defaults to `main`. |
| `--check JSON_ARGV` | One CI command as a JSON array, such as `'["cargo","test","--locked"]'`. Supply 1–16 commands, in execution order, unless adopting a workflow. |
| `--gh PATH`, `--jj PATH` | Select the host executables; otherwise resolve `gh` and `jj` on PATH. |
| `--signing-key PATH` | Existing private Ed25519 key; otherwise generate a separate signing key. |
| `--ci-check NAME` | Actions check required for integration; defaults to `ci/ladyhost`. |
| `--workflow-path PATH` | Repository-relative workflow path; defaults to `.github/workflows/ladyhost.yml`. |
| `--adopt-workflow` | Preserve an existing exact-push workflow instead of generating one; select its path and check name with the preceding options. |
| `--spec FILE` | Read a JSON `setup::Spec` instead of project flags. Combine only with `--state`, `--apply` and `--json`; host filesystem paths inside the spec must be absolute. |

For a saved setup, `init --state DIR --apply` reuses the recorded selections.
Keep the same directory through browser consent, CI and review steps.

## Publish and integrate

Use the private configuration produced by setup. Independently check the
candidate before binding its exact bookmark/commit in the per-attempt
`publication` configuration. Checks and receipts stay outside exported sources.

```sh
ladyhost-jjpr preflight /private/task/config.json
ladyhost-jjpr plan /private/task/config.json agent/task
ladyhost-jjpr submit /private/task/config.json agent/task
ladyhost-jjpr inspect-integration /private/task/config.json /private/task/request.json
ladyhost-jjpr integrate /private/task/config.json /private/task/request.json
```

`plan` may contact the forge; `submit` changes branches/PRs. Inspection observes
the selected candidate. Integration rechecks its exact signatures, ancestry,
fresh native human approval, required checks/CI and effective protection before
updating the target. It preserves the approved signed commit, without creating
a replacement merge commit. A new head needs fresh approval.

`integration::IntegrationRequest` selects task/PR identity, source/target branches,
full expected head/target OIDs, reviewer numeric ID/login, ruleset IDs,
allowed-signers path, unique receipt directory, superseded review IDs and CI
requirement. Setup's integration defaults supply policy, not candidate authority.

`ladyhost-jjpr git-helper CONFIG` installs the private checkout's credential
helper. Moving/rebuilding the bound executable requires explicit verification
and rebinding. `credential CONFIG <get|store|erase>` is a Git protocol entry point,
not an agent credential API. Keep App keys and forge/signing credentials on the host.

`ladyhost-jjpr` takes positional arguments, with no `--json` or `--apply` flag.
`CONFIG` is the private host configuration, `BOOKMARK` is the selected Jujutsu
bookmark, and `REQUEST` is an integration-request JSON file:

| Invocation | Purpose |
| --- | --- |
| `preflight CONFIG` | Query and verify the authenticated forge account and repository identity; print JSON. |
| `plan CONFIG BOOKMARK` | Preview publication of the selected bookmark; may query the forge. |
| `submit CONFIG BOOKMARK` | Publish the selected candidate and update its PR. |
| `inspect-integration CONFIG REQUEST` | Inspect the exact integration candidate and policy; print JSON. |
| `integrate CONFIG REQUEST` | Recheck and integrate the candidate selected by the request; print JSON. |
| `git-helper CONFIG` | Install the bound credential helper in the private checkout. |

## Conflict review

A resolved conflict requires a host-composed package binding original base,
previous task/upstream revisions, resolved tree, both task intents, observed
conflicts, agent decisions/uncertainty, and digests of export/check/policy evidence.
A clean merge or agent test report does not establish that both intents survive.

The agent supplies schema-2 handoff data. The trusted host selects independent
assertions covering task behavior, upstream behavior and their interaction.
The native gate binds commands/results, verifier identity and exact Git bytes/modes.
The package digest and canonical review text enter the signed commit; the PR must
contain the complete body directly or in jjpr's managed-description format.
Extra wrapping text can hide it and is refused; use comments for discussion.

```sh
ladyhost help review-conflict
ladyhost review-conflict --config /private/task/config.json \
  --candidate FULL_COMMIT_OID --render
ladyhost review-conflict --config /private/task/config.json \
  --candidate FULL_COMMIT_OID --json
```

The config's `conflict_review: {"path": "...", "sha256": "..."}` selects the
host package. `--render` validates inputs and produces text before final signing;
ordinary inspection also requires it in the candidate commit. Incomplete checks
can be displayed but cannot authorize integration. Every newly introduced marked
ancestor requires its selected package; an ordinary child cannot hide it.
Legacy unmarked history is not retroactively classified.

Current bounds: 256 KiB receipts/packages, 48 KiB review text, 4,096 files,
4 MiB per blob and 64 MiB total. A selected package covers one candidate tree;
other stack elements need separate publication. This is host evidence, not
hardware attestation or proof of semantic/test-author independence.

## Recovery and removal

Only one process may operate on a state directory. Restart inspects durable
intents and exact remote readback; it never blindly repeats uncertain creation,
push or deletion. Tool changes, policy drift and ambiguous results require
inspection. Keep old binaries and receipts while operations are pending.
No historical state is adopted by moving a directory or editing a tool hash.

If isolated owner authentication expires, log out only that session using
`GH_CONFIG_DIR=STATE/owner-auth gh auth logout --hostname github.com`, then resume
for fresh authorization. Do not delete effect receipts to force a retry.
An interrupted registration without its conversion response may have an unknown
remote outcome; inspect it as owner before attempting another registration.

```sh
ladyhost uninstall --state "$HOME/.local/state/ladyhost/project"
ladyhost uninstall --state "$HOME/.local/state/ladyhost/project" --apply
```

Removal first revokes the verified installation, then deletes only unchanged
owned rulesets. Changed/unowned resources, history, PRs, branches, tracked workflows
and SSH signing keys remain. App registration deletion uses the printed owner URL.
Keep private receipts/App keys until remote cleanup is resolved.

## Tests and dependency maintenance

```sh
cargo test -p ladyhost --all-targets --offline --locked
cargo clippy -p ladyhost --all-targets --offline --locked -- -D warnings
python3 -m unittest discover -s examples/ladyhost/scenario
```

Tests cover refusals/recovery, App setup, publication journaling,
signatures/approval/CI and conflict review. [Scenario instructions](../../examples/ladyhost/README.md)
separate synthetic tests, native jj and live fixture requirements. Passing them
does not qualify private plans, new platforms, large projects or unattended merge.

Registry requirements are centralized in the root manifest: jjpr 0.45.1,
anyhow 1.0.104, serde 1.0.229 and serde_json 1.0.154. Cargo.lock is authoritative.
Inherited base64/windows-sys splits are maintenance debt, not blanket exceptions.
Ladyhost maintainers review these contexts with the next jjpr/parent update,
no later than 2027-02-06. Follow the [dependency policy](../../docs/dependencies.md)
for exact source/version comparisons and fresh all-platform advisory coverage;
historical publication tests do not provide a current security clearance.
