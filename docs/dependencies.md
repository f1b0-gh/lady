# Dependency inventory, maintenance and preparation

Ladybom statically reads Cargo, Python and npm inputs without package-manager
execution, network access or project code. Ladyshell separately authorizes and
prepares dependencies; a Ladybom report never grants installation or network
permission. See the [CLI](../crates/ladybom-cli/README.md) for build instructions.

```sh
ladybom scan --project /absolute/project --json
ladybom scan --project /absolute/project --sources /outside-project/sources.json --json
```

Native report v2 retains requirements, tool constraints, markers, sources,
artifacts, fingerprints and locked components. Shared-lock members use
`components_from`; `Report::components_for(project)` resolves ownership.
Regenerate v1 reports/snapshots explicitly. `complete` describes parser coverage;
a missing lock can leave a complete scan with `locked=false`, but preparation
refuses it. Invalid/unsupported inputs produce partial results and exit 2.

Source snapshots allow 5,000 files and 256 MiB total, with 8 MiB per manifest or
lockfile. Protected paths are excluded and selected symlinks refused.
`--sources` accepts strict JSON `include`/`exclude` arrays of relative paths,
limited to 1 MiB. Match the mission selection; Ladyshell independently checks
scope instead of trusting a supplied report's claims.

## Inventory boundaries

Cargo workspaces share locked components. Git PURLs require a supported remote
URL without credentials and a full 40-hex SHA-1 commit from `Cargo.lock`.
HTTP(S), Git and SSH with a host are supported; local/user-bearing URLs,
short/missing commits, unknown selectors and ambiguity stay unqualified.
Provenance is declared, not authenticated; no checkout or public advisory
coverage is inferred. Supplier changes remain alignment-policy gaps.

Local npm/uv graph identity requires matching selected manifest evidence;
missing, conflicting, ambiguous or out-of-scope evidence remains unknown.
Directories stay distinct and never become public registry identities.
Preparation permissions do not expand with static identity support.

Python recognizes case-sensitive `requirements.txt`, `.in`, `.lock`, nonempty
context variants separated by `-`, `_`, `.` and those extensions directly in
`requirements/`. Each file is independent; arbitrary names are not discovered.
Unsupported directives including `-r`/`-c` block without following files.
Hash-bearing files and `.lock` files are flat inventories requiring exact,
non-wildcard PEP 440 `==` and unquoted SHA-256/384/512 hashes. Markers, extras
and record hash sets survive; `# via` creates no edges. `locked=true` means read,
not reproducible. `{"pip-index":"unverified"}` and blocking
`pip_inventory_incomplete` retain unknown provenance, graph and artifact choice;
no public advisory equivalence or preparation support is inferred.

Selected Go manifests/checksum files are fingerprinted but block coverage with
`unsupported_go_input`; directives are not followed. Explicit
[Nix/Go artifact collection](artifact-sbom.md) is separate.

## Dependency maintenance

Prefer one compatible version per identity, source and resolution context.
Search existing declarations and reuse shared workspace dependencies before
adding one. Preserve features, optionality, `no_std`, build/dev categories and
target conditions. Update manifests and relevant reproducible locks together;
independent workspaces retain independent locks. Path/registry/fork packages
are not interchangeable merely because names and versions match.

1. Inspect every maintained context and parent path before migration. Review
   the latest upstream stable candidate first, then pin the version that passes
   compatibility and security checks. Record date/source, constraints, migration
   cost and a revisit trigger if latest stable is not adopted. Floating `latest`
   is not a retained input. Verified prebuilt packages/caches may avoid rebuilds;
   freshness alone proves neither safety nor convergence.
2. For a reduction, state expected and observed net package identities,
   identity/version pairs, multiversion families and excess versions removed,
   additions, affected consumers and recurring maintenance cost. Keep individual
   locks, their union and image closures distinct; npm occurrences are not extra
   versions, and Nix outputs are not necessarily libraries. Removing a declaration
   removes no package retained through another parent. A five-to-two reduction
   removes three excess versions but leaves a divergent family. A version change
   without measurable net reduction must not be presented as dependency removal;
   security fixes may still be necessary independently.
3. Prefer compatible resolution or supported upstream parent upgrades. Do not
   create forks, adapters, modified local copies or feature unions just to reduce
   counts. Existing forks require an owner, cumulative maintenance cost, bounded
   tests and an explicit upstream return condition. Intact reproducibility inputs
   are distinct from maintained forks. Evaluate actual constraints and usage
   before costly validation. Stop unsupported or disproportionate approaches,
   record their blocker and a concrete resumption trigger; do not repeat unchanged
   tests or work around failures for a numerical gain.
4. Check candidates against current advisories in every ecosystem, then check
   final locks again, including transitive, optional, build/test and all-platform
   dependencies. Check wrappers, bindings and native libraries separately.
   Cross-check upstream maintainer reports and preserve source disagreements.
   Do not introduce a known-affected version for alignment. Record provenance,
   revision/hash, collection time, freshness, tool version, parameters, filters,
   suppressions and results. Missing, stale or unsupported sources remain gaps,
   never favorable results. Acquisition and native tool execution are explicit,
   separate from static scanning. [Advisory coverage](vulnerabilities.md) details
   the supported matcher; a finding does not by itself prove exploitability.
5. Compare exact version sets by identity, source and context against a verified
   baseline whose digest is versioned. Numeric ceilings are insufficient: new
   divergence or any new version in a still-divergent family requires review,
   even at unchanged counts. Inherited debt remains backlog, not approval.
   Incomplete coverage or changed scope blocks non-regression conclusions; do
   not hide platforms or change suppliers to improve counts. Exceptions require
   owner, exact versions/sources, scope, reason, evidence, recurring cost and
   expiry. Never automatically renew references or exceptions to pass checks.
6. Use native managers to update locks deliberately and inspect their diffs.
   Select tests by local policy and concrete risk; reuse evidence whose relevant
   inputs are unchanged. Keep existing findings visible. Check pins with
   `graph alignment --check`, non-regression with `graph alignment-policy` and
   advisories with `vuln check`; none replaces consumer tests. If CI is not wired
   or qualified, report that work as outstanding: written policy is not execution
   evidence. Inventory covers all platforms without proving their activation.

`graph alignment-plan --snapshot PATH [--markdown]` prepares a static plan bound
to a verified snapshot. It preserves contexts and known parents but does not
choose compatible/security-fixed versions or approve remediation. Full parent
constraints, advisory checks, consumer tests and independent scope verification
remain required. See [baseline policy](../crates/ladybom-cli/README.md#alignment-policy).

Flat Python exports require separate provenance: retain upstream revision,
manifest, native lock and export hashes; verify their relationship with explicit
locked regeneration where possible. Registry metadata/hashes do not prove
installed bytes. Inspect selected distribution metadata, parent constraints,
markers and every supported Python/platform context. Preserve full upstream
optional/dev inventory separately. Prefer renewing the upstream lock over a
local divergent export or downgrade made only to improve counts.

## Prepare a development image

Ladyshell uses explicit `lock → plan → apply`: plan validates inputs without
installation; apply builds with Nix after ownership, provider and policy checks.
Configure `dependencies.projects` with selected manifests and
`dependencies.allowed_hosts` with permitted download hosts, then select exact
`tools` versions and mission sources/checks. All manifests, locks and necessary
local files must belong to the selected sources. Inspect the pinned tool catalog
before configuration; see [Ladyshell usage](usage.md) for a complete configuration.

```sh
nix --extra-experimental-features 'nix-command flakes' eval --json ./nix#lib.packageVersions
```

Unavailable/incompatible versions are refused without substitution. npm comes
from the selected Node package and is checked during the build. Python packages
provided as Nix tools do not substitute for a project's `uv.lock`. Explicit
native tools include cmake, make, Perl, pkg-config, OpenSSL, TPM2-TSS and maturin.
Native libraries are read-only under `/usr/local/lib/ladyshell`; execution passes
`PKG_CONFIG_PATH`/`LD_LIBRARY_PATH` explicitly because OpenShell exec does not
inherit OCI environment. This grants no host device/service access.

Downloads require HTTPS, SHA-256/512 and an allowed host; redirects are refused.
Fixed-output fetchers precede offline Nix preparation. Host Nix trust governs
binary caches and tools; the daemon must enable Linux sandboxing. Recipes and
source inputs are locked into the environment/image receipt. Changed recipes
require explicit relocking; changed manifests require replanning. Historical
state is never rewritten implicitly.

| Inputs | Preparation | Offline use |
| --- | --- | --- |
| `pyproject.toml` + `uv.lock` v1 | Locked export, all extras/groups, verified wheels per project | `.venv/bin/python` |
| `Cargo.toml` + `Cargo.lock` | `importCargoLock`, frozen/offline metadata verification, vendored crates | `cargo build --frozen --offline` |
| npm manifest + package lock v2/v3 or shrinkwrap | Verified tarball cache, `npm ci --offline --ignore-scripts`, dev included | `node`, `node_modules/.bin/tsc` |

Cargo configuration stays in `CARGO_HOME`, outside exported sources; `.venv` and
`node_modules` remain excluded from normal transfers. Python project/backends
are not installed. Only static Cargo aliases are accepted in `.cargo/config*`;
shell aliases and compiler, command, environment, network or source overrides
are refused. Selecting a Cargo workspace root requires bin/test/example/bench
sources for all members; selecting a member requires its own targets. Locks,
local dependencies, libraries, build scripts and all target paths remain checked.

npm workspaces require explicit members with manifests and root-lock evidence.
Globs, nested workspaces and member locks are refused; member/project install
scripts are ignored. Preparation rejects uv workspaces, Git sources, alternate
Cargo registries, undeclared local Python/npm dependencies, npm aliases and
registry packages with install scripts. Python sdists are not built: a missing
compatible wheel fails. Poetry, pylock, pnpm, Yarn, Bun and historical/dynamic
Python metadata have no qualified preparation path. `audit run` uses separate
images. These refusals never broaden network policy.

## Native packaging checks

`nix/openssl.nix` pins OpenSSL 3.5.9; `nix/tpm2-tss.nix` pins TPM2-TSS 4.2.1.
The explicit `openssl` and `tpm` shells select Rust 1.99.1 and native libraries,
with `OPENSSL_NO_VENDOR=1`, `OPENSSL_STATIC=0` and target-specific equivalents.
Overriding them leaves the qualified profile. In Ladyshell checks, pass those
variables explicitly through `env`. Inspect actual linkage and run consumer
tests; selecting a native tool does not update the whole image closure.

Packaging maintainers must review applicable advisories and overrides by
2026-12-05 for OpenSSL and 2026-12-07 for TPM/network tools. Retire overrides when
reviewed upstream recipes satisfy the same checks. The OpenSSL IPv6 socket test
adjustment skips only `EAFNOSUPPORT`; IPv6 remains unqualified on a host with it
disabled. Git's optional Perl/Python tools are disabled by native package options;
Cargo/rustfmt and network tools are recomposed in `nix/network-tools.nix`.
Installed SWTPM tests are separate from runtime. These scoped checks do not
establish image-wide advisory coverage or qualify untested transports/platforms.

Run native checks explicitly, never during a Ladybom scan. Additional closure,
installed-test, Git/Rust and TLS checks are listed in [`nix/flake.nix`](../nix/flake.nix).

```sh
nix --extra-experimental-features 'nix-command flakes' build --no-link --no-write-lock-file \
  path:./nix#checks.x86_64-linux.openssl path:./nix#checks.x86_64-linux.tpm2-tss
cargo test --release --locked --test deps_image -- --ignored --nocapture
```

The image test uses synthetic inputs under UID 10001 and Docker `--network none`;
it creates no OpenShell provider/sandbox. Native TPM tests use software/synthetic
inputs, not physical-key custody. Retain actual results before claiming success.
