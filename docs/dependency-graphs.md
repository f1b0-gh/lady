# Dependency graphs and LadybugDB

Ladybom projects static inventories into in-memory graphs. The
[ladybom-graph library](../crates/ladybom-graph/README.md) persists them in
immutable Parquet snapshots and powers the default CLI graph and prune commands. Export,
inspection, diff and alignment need no native engine. Traversal and removal
simulation explicitly run trusted LadybugDB **0.17.1**; they never execute the
scanned project, install dependencies or change sandbox/network policy.

## Start from the repository root

```sh
cargo build -p ladybom-cli --locked
./target/debug/ladybom graph export --project /absolute/project --output /outside-project/s1
./target/debug/ladybom graph inspect --snapshot /outside-project/s1
./target/debug/ladybom graph alignment --snapshot /outside-project/s1 --check
./target/debug/ladybom graph diff --before /outside-project/s1 --after /outside-project/s2
```

Create `s2` separately before comparing. `export --sources selection.json` uses
the same bounded source selection as `scan`. Output directories must be new,
even if an existing directory is empty. JSON exit code 0 means complete analysis;
2 means partial coverage or a failed requested policy. Integrity and engine
errors abort; a partial snapshot remains inspectable with its limitations.

For native queries, explicitly build the pinned engine:

```sh
nix --extra-experimental-features 'nix-command flakes' build ./nix#ladybugdb --out-link /tmp/ladybom-ladybug
./target/debug/ladybom graph query --snapshot /outside-project/s1 \
  --engine /tmp/ladybom-ladybug/bin/lbug --purl 'pkg:npm/example@1.0.0'
./target/debug/ladybom graph impact --snapshot /outside-project/s1 \
  --engine /tmp/ladybom-ladybug/bin/lbug --purl 'pkg:npm/example@1.0.0'
```

Choose a PURL actually present in `inspect`. Each `components[].key` contains
`graph` and `purl`; provide `--graph graphs/<digest>` if the PURL is ambiguous.
`impact` and `query --reverse` follow dependants. `--target-purl` and, when
needed, `--target-graph` select a shortest explanatory path. Closures exclude
the start; a path from the start to itself has one node at distance zero.

Repeatable `--kind` and `--context`, plus `--unconditional-only`, filter edges
before traversal. Both endpoints must satisfy selected contexts. Kinds include
`runtime`, `dev`, `build`, `optional`, `peer`, `extra:<name>`, `group:<name>` and
`unknown`. Defaults retain all kinds and conditions. Depth defaults to 32
(range 1–256); the next level detects truncation. A target filter never hides
truncation. Timeout defaults to 60 seconds (maximum 300); expiry terminates the
process group and cannot produce a successful result.

## Identities and limits

Identity is `(graph, purl)`, not a universal installation. Context directory
names are deterministic hashes of their retained JSON. npm resolves nested
`node_modules` paths and aliases separately; optional dependencies override
matching ordinary dependencies. Cargo resolves lockfile name/version/source;
transitive kinds, targets and features remain unknown or conditional. Shared
locks share components, while member roots and independent locks stay distinct.
uv preserves markers, extras and groups; ambiguous edges and unexpanded group
includes remain incomplete. Recognized version constraints are checked before
linking; unsupported sources do not produce arbitrary links.

Roots reference projected components without creating extra application nodes.
Qualified local components use `pkg:generic/cargo-local/...`, `npm-local/...`
or `python-local/...`, distinct from public registry identities. Missing PURLs,
links and unevaluated conditions remain limitations. Absence in a partial result
proves neither dependency absence nor safety. `impact` is potential; it is not
code reachability or advisory matching. `diff` does not establish build equivalence.

A snapshot contains `manifest.json`, `inventory.json` and per-context
`context.json`, `components.parquet`, `dependencies.parquet`. Schema 1 uses
uncompressed Parquet and explicit destination contexts. Readers verify declared
sizes, SHA-256 hashes, schemas, references and duplicates, refusing symlinks and
traversal. Undeclared files are never imported. Exclusive atomic publication
never replaces snapshots. Hashes detect changes; they do not authenticate origin.

Native operations use a fresh private in-memory database, verify imports and
full output, clear the environment and check engine version. Project strings
are not interpolated as Cypher. A zero engine exit alone is insufficient.
Limits: 100,000 nodes, 500,000 edges, 4,096 contexts and 128 MiB per snapshot;
32 MiB engine output, 256 MiB buffer pool, 4 GiB address space and 256 MiB process
files. The engine is an operator-trusted executable, not confined project code.

## Removal analysis and validation

With `ladybom` on PATH, or using `./target/debug/ladybom`:

```sh
ladybom prune analyze --project /project --snapshot /snapshots/before \
  --manifest crates/app/Cargo.toml --output /reports/usage.json
ladybom prune roots --snapshot /snapshots/before
ladybom prune request --snapshot /snapshots/before --remove-root ROOT_ID --output /reports/request.json
ladybom prune simulate --snapshot /snapshots/before --request /reports/request.json \
  --engine /tmp/ladybom-ladybug/bin/lbug --output /reports/simulation.json
```

Usage evidence is `referenced`, `candidate` or `unknown`; none authorizes removal.
Lexical analysis retains uncertainty around macros, generated code, dynamic
imports and configurations. Optional `--machete-report`, `--knip-report` and
`--deptry-report` read already-produced JSON; they do not run tools or erase
found references. Imported source paths must be project-relative. Record tool
versions and production conditions separately.

Requests bind the snapshot digest and exact declaration IDs. Duplicate, stale,
ambiguous or out-of-scope requests are refused. `--retain-manifest` selects
retained projects; by default all remain. Simulation compares closures before
and after removing declarations, preserving dependencies reachable through other
parents and cycles. `freed_in_model` excludes `already_unreachable` nodes; depth
truncation suppresses both gains. Counts do not predict binary size or build time.

Edit an isolated copy and update its lockfile explicitly, then:

```sh
ladybom graph export --project /edited-copy --output /snapshots/after
ladybom prune validation-plan --before /snapshots/before --after /snapshots/after \
  --request /reports/request.json --project /edited-copy --output /reports/plan.json
# Prepare this copy through Ladyshell lock, plan and apply with declared checks.
ladyshell deps prune validate --state /copy-state --plan /reports/plan.json --output /reports/result.json
```

A version change alone is not removal. Plans reject missing projects, ambiguous
declarations and mismatched sources; `--exclude` must match reconciled state.
Ladyshell checks session ownership, provider, effective policy and full inventory
before/after each command. Limits are 32 commands, 300 seconds each, 600 seconds
total and 512 KiB output each. Failure stops the sequence. A passing receipt
covers only those checks/configurations, not every feature or downstream user.

## Verification and workspace example

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
export LADYBOM_LADYBUG_BIN=/tmp/ladybom-ladybug/bin/lbug
cargo test -p ladybom-cli --locked --test deps_graph --test alignment -- --ignored
cargo test -p ladybom-graph --locked --test deps_alignment_explain --test deps_prune -- --ignored
cargo run --locked -p ladybom-graph --example deps_explorer -- /absolute/project /absolute/new-experiment
```

The six ignored native cases cover alignment explanations, removal simulation
and graph traversal, including filters, depth, timeouts and an independent
test-only BFS oracle. `deps_explorer` selects explicit
Cargo/npm workspace members, refusing globs; it exports inventory, Parquet and
Explorer CSV without package-manager execution. Explorer databases are rebuilt
separately; their format is not assumed compatible with the qualified CLI.
See the [CLI](../crates/ladybom-cli/README.md#alignment-policy) for baseline policy.
