# Working on Lady

- Read [README.md](README.md) and the affected component's guide first.
- Keep published documentation, code and identifiers in English.
- Build with stable Rust in this repository's `target/`. Override an inherited
  `CARGO_TARGET_DIR` if necessary; never use or recreate `../erwin`.
- Required checks: `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`,
  `cargo test --workspace --all-features --locked`. See
  [development](docs/development.md) for native prerequisites and source checks.

## Boundaries

- Ladybom owns static inventories, SBOMs, graphs and simulations. Scanning must
  not execute project code, Nickel, OpenShell or implicit network operations.
- Ladyshell owns authorization and OpenShell execution. Independently establish
  the source scope and verify imported reports against it; reports grant no
  permissions. Check identity, provider and effective policy before execution.
- Fail closed. Keep Landlock mandatory. Never expose raw host secrets, Docker
  sockets or the Nix daemon to agents, or relax policy to make a test pass.
- Ladyboot owns bootc artifacts: Nickel validates needs, Nix builds pinned
  packages, Rust locks and verifies. No Ladyshell/OpenShell Cargo dependency;
  no Python controller or business logic in shell wrappers.
- Ladyhost owns host credentials, signing and reviewed forge integration.
  Keep library APIs free of Clap; Ladyboot consumers disable default features.

## Dependencies and retained work

- Reuse shared declarations and follow [dependency maintenance](docs/dependencies.md#dependency-maintenance).
  Keep manifests and locks consistent; check candidates and final locks against
  current advisories across platforms and dependency kinds, including native
  components. Missing coverage is not a pass. Preserve findings and provenance.
- Compare exact versions/sources with a digest-pinned reference. Backlog is not
  an approved exception. Never refresh references or exceptions to pass a check.
  Exceptions need an owner, scope, evidence, maintenance cost and expiry. Do not
  fork or add adapters merely to reduce duplication; measure the net benefit.
- `nickel-util =0.1.0` is an unchanged bundle pinned by
  `sources/nickeling.json`. Keep its source, license and hashes together; run
  `python3 scripts/check_sources.py`. Do not restore implicit sibling dependencies.
- Preserve maintained code, unique changes, fixtures, locks and irreplaceable
  inputs. State migration must be explicit and reversible. Experiment-output
  cleanup needs retained code, a reproduction recipe and a PDF report outside
  the deletion scope; normal build caches need source and rebuild inputs only.
  Eligibility never authorizes deletion of active work or historical states.
- Use synthetic fixtures for refusals, interruptions, limits and hostile paths.
  Do not label an audit lead a confirmed vulnerability without validation.
  Reuse evidence only when relevant inputs are unchanged; report unrun checks.
