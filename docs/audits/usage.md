# Native audit

Ladyshell validates audit documents, verifies and compares retained runs, exports
results and runs isolated agents. `audit plan` has no execution effect and reports
`runtime_preflight_required`; `audit run` verifies native confinement before any
project command or model invocation. A static inventory grants no permissions.

## Commands

From the Lady root, build with `cargo build -p ladyshell-cli --locked`, then use:

```sh
./target/debug/ladyshell audit validate findings /path/findings.json
./target/debug/ladyshell audit validate coverage /path/coverage-ledger.json
./target/debug/ladyshell audit verify /path/run
./target/debug/ladyshell audit compare /path/old-run /path/new-run
./target/debug/ladyshell audit export /path/run --destination /path/new-export
./target/debug/ladyshell audit plan --state /path/private/state --profile quick
./target/debug/ladyshell audit run --state /path/private/state --profile quick
./target/debug/ladyshell audit recover /path/private/state/audits/audit-ID
```

Validate, verify, compare and export are offline operations: no Node, OpenShell
or project program is launched. Exit codes are 0 for operation success, 1 for
I/O/operational failure and 2 for invalid data or missing guarantees.
`audit-validator findings|coverage FILE` is the compatibility binary from
`ladyshell-cli`; it retains exit 1 for every failure and its scoped
[MIT notice](../../crates/ladyshell/src/audit/validator/LICENSE-MIT).

Validation preserves upstream acceptance, including repeated JSON keys. Native
verification additionally refuses duplicate keys, unknown versions and unknown
metadata fields. Documents are bounded to 5 MiB. The [run contract](run-format.md)
defines the required files and relations. Historical incomplete reports are not
native runs; do not manufacture missing execution metadata.

## Configure and prepare

First provision a native environment through the [lock/plan/apply workflow](../usage.md).
State stays outside the project. Add an optional `audit` block to the config:

```nickel
audit = {
  profile = "quick",
  scope_paths = ["src"], exclude_paths = [], tools = {},
  checks = [["cargo", "test", "--offline", "--locked"]],
  budget = { invocations = 10, seconds = 1200 },
  limits = {
    cpu_seconds = 30, memory_bytes = 1073741824,
    processes = 256, files = 2048, disk_bytes = 268435456,
  },
},
```

Choose commands and tools for the actual project. Declaring a check does not
execute it on the host or install its tools. Renew the lock and apply explicitly
after changes. The plan narrows the already allowed source scope, fingerprints
inputs and reports budgets/obstacles; it does not attest runtime enforcement.

The trusted resource tree includes manifests, Rust sources, audit method/schema,
Nix recipes and bundled `vendor/nickel-util`. Verify it using
`python3 scripts/check_sources.py`. The runtime package can be built separately:

```sh
nix-build --extra-experimental-features 'nix-command flakes' \
  --impure nix/runtime.nix --no-out-link
```

This builds the CLI/compatibility binary from source and installs audit resources
and separate license notices. Package smoke checks do not qualify a live sandbox.

## Runtime prerequisites and limits

The native profile requires a configured local Docker/OpenShell gateway with
volume admission and Docker driver parameters enabled. Host bind mounts remain
forbidden. Audit volumes carry `openshell.ai/sandbox-attachable=true`, the matching
`openshell.ai/sandbox-attachable-workspace` label and a run ownership identity.
Gateway configuration is operator-managed; this source distribution does not
include a portable, qualified gateway configuration template.

Each target/agent receives a private bounded tmpfs volume. No host socket or raw
provider token enters it. Identity, effective filesystem policy, mandatory
Landlock and provider readiness are verified before execution. The agent starts
without network; provider attachment and the pinned Codex network rules are
checked before use. The driver accepts Codex CLI 0.165.0 only. Other versions or
unrecognized driver errors block the run. Do not broaden policy to pass preflight.

A wave reserves four reconnaissance invocations, a hunter, a critic and at least
one independent verifier. At least seven invocations are required. Checks run in
networkless targets before hunting; reproductions run in fresh verifier targets.
An explicit oracle and matching evidence are required for confirmation. Unproven
candidates remain `needs_validation` without severity or receive a justified rejection.

Text sent to agents is limited to 256 KiB per wave; narrow the scope if necessary.
Execution copies are bounded to 64 MiB and promoted evidence to 48 MiB. Targets
require at least five CPU seconds. The supervisor verifies descendant termination
before collecting evidence; exec completion alone is insufficient. Cleanup failure
prevents a complete result. External deletion delays do not provide a strict
upper bound on total CPU usage during that failure path. UID-wide Linux process
limits can also cause refusal when other retained sandboxes share the UID.

## Results and recovery

The controller announces its private run directory on stderr. It retains durable
intents, owned resource identities and cleanup obligations. `audit recover RUN`
reobserves ownership, cleans matching resources and marks interrupted execution;
it never reruns the model or target. Unknown or unrelated resources are preserved.
Use the announced `run_directory`, not an inferred metadata identifier.

Inspect `status`, `open_obligations` and `cleanup_verified`. Exit zero can mean a
successfully published partial result. Quick and targeted profiles always report
partial coverage. Verification checks relationships and hashes, not third-party
authenticity or real-world observations: `authenticity_verified` remains false.
Comparison never transfers confirmation automatically across changed inputs.
Export uses verified bytes, omits undeclared files and derives `REPORT.md`; its
destination must be new. Interrupted `.audit-export-*` staging is not a complete
run. No audit result authorizes installation, network access or policy expansion.
