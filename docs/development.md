# Build and development

## Prerequisites

Lady targets Linux, including Ladybom's use of `/proc/self/fd`. Building the
workspace requires stable Rust and a C compiler. Nix recipes currently select
`x86_64-linux`; this is not a claim of other-platform qualification.

Cargo uses `target/` in Lady. If your shell sets a target directory for another
project, unset it or set `CARGO_TARGET_DIR="$PWD/target"` from the repository root.
No sibling repository is needed. Package downloads during a build are separate
from Ladybom scanning.

## Rust consumers

The workspace pins the published `nickel-util =0.1.0` helper from crates.io.
`Cargo.lock` records the registry source and archive checksum. Fetch the locked
dependencies before building offline.

```sh
cargo fetch --locked
cargo build --workspace --locked --offline
```

Ladyshell hashes the runtime workspace, including `Cargo.lock`, before audit
preparation. Nix vendors registry crates using the checksums in that lockfile
and builds the runtime from source. Follow the
[dependency policy](dependencies.md#dependency-maintenance) when updating pins.

## Required checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 tests/check_boundaries.py --bootc crates/ladyboot
```

Set `CARGO_BUILD_JOBS=2` when limiting build concurrency. Library checks preserve
CLI independence; Ladyboot is checked with default features disabled by the
boundary checker.

Python helper tests use the existing hash-pinned interoperability requirements.
Acquire them explicitly, then run the synthetic suites without live services:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --isolated --disable-pip-version-check \
  --index-url https://pypi.org/simple --require-hashes --only-binary=:all: \
  -r tests/requirements-interop.txt
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
python3 -m unittest discover -s examples/ladyhost/scenario -p 'test_*.py'
(cd crates/ladyboot/tests && python3 -m unittest test_assembly test_vm_drivers)
```

The Ladyhost scenario suite skips its native Jujutsu case unless `JJPR_TEST_JJ`
selects a prepared executable. Other Ladyboot test drivers require explicit
native inputs; do not run them through unrestricted test discovery.

The test suite uses synthetic fixtures, but some tests require native tools:
Nix, Bubblewrap, `prlimit` and the pinned Nickel evaluator. Prepare the evaluator
explicitly before running those tests:

```sh
nix --extra-experimental-features 'nix-command flakes' build \
  path:./nix#nickel --no-link --no-update-lock-file --no-write-lock-file
```

Run confinement-dependent tests on a Linux host that supports their namespaces.
Do not bypass confinement when a restricted development environment refuses it.
Missing native prerequisites are failures or explicit qualification gaps, never
proof that a deployment works. The current catalogue selects Rust 1.99.1,
Node 24.22.2 and Python 3.11.18, 3.12.16, 3.13.18 or 3.14.10. Explicit Rust
1.99.1 image requests select the pinned official compiler and reconstructed
Cargo even when Nixpkgs supplies the same version. Exact matching remains
mandatory; old requests require explicit configuration migration and relocking.
Retain historical plans, locks and receipts unchanged. Ignored tests for LadybugDB, images, OpenShell,
Jujutsu and VMs have separate commands in the relevant guides. Build outputs,
state, exports and credentials stay outside published sources.

## Ladybom packages

Qualify `ladybom`, `ladybom-graph` and `ladybom-cli` together with the stable Rust
and Python 3.11 or newer toolchain, a C compiler and Git on Linux. Fetch inputs
once before the offline check.

```sh
cargo fetch --locked
python3 tests/check_ladybom_packages.py
```

The check verifies the core with Cargo's package verifier and stages all three
Cargo archives. It checks archive assets and tests extracted sources outside the
checkout. The pinned Cargo's verifier cannot look up the staged core package's
checksum for its consumers, so isolated Cargo workspaces resolve the unpublished
dependencies to extracted packages while retaining locked registry inputs. The
check installs and scans with both CLI configurations and exercises Ladyshell's
report admission against packaged core source. Native LadybugDB, live services
and native artifact collectors have separate qualification paths.

Review the package set, dependency findings, and core/graph/CLI version pins
before release. The additional workspace archive gate checks all seven archives,
builds and tests Ladyshell, Ladyboot and Ladyhost outside the checkout, and runs
safe binary smoke checks with an empty home and PATH:

```sh
python3 tests/check_workspace_packages.py
```

With publication authorization, publish `ladybom` before `ladybom-graph` and
`ladyshell`, `ladybom-graph` before `ladybom-cli`, and `ladyshell` before
`ladyshell-cli`. `ladyboot` and `ladyhost` depend only on already published
registry crates. Wait for each prerequisite to appear in crates.io before
publishing its consumers. Review exact archive contents and checksums, and
verify locked registry installations afterward, including Ladybom's default
and `--no-default-features` configurations. Use release tags `ladybom-vVERSION`,
`ladyshell-vVERSION`, `ladyboot-vVERSION` and `ladyhost-vVERSION` so components
can advance independently.

Cargo installs executables, not the operator's trusted recipe directory.
Ladyshell and Ladyboot still require their documented native prerequisites and
explicit version-matched resources. Publication does not qualify a live
OpenShell deployment, OS image lifecycle, or GitHub App installation.

## Known dependency findings

The 2026-11-22 OSV query covers all 291 crates.io package versions in `Cargo.lock`,
without platform, feature or dependency-kind filtering. The
[review record](../resources/dependency-review.json) binds the exact lock, query,
response and advisory dates.

`rustix 1.1.6` fixes the reported extended-attribute soundness issue. Upgrading
Parquet to `59.3.3` removes the affected `thrift 0.17.0` dependency and unmaintained
`paste 1.0.15`. The remaining finding is
[`chrono 0.4.45` being unmaintained](https://osv.dev/vulnerability/RUSTSEC-2026-0543),
still required by Parquet. It remains maintenance work, not an approved exception.

The workspace has 298 packages and 14 multiversion families. The reviewed
Dependabot updates change eleven crate versions without adding packages or version
splits. The `webpki-roots` update belongs to Ladyhost’s `jjpr → ureq` HTTPS client;
its CDLA-Permissive-2.0 license is unchanged. TLS trust configuration remains in
`jjpr`. Extracting the local `ladybom-graph` crate added no registry packages or
versions. Ladyboot’s separate bootupd lock retains older regex packages, so the
combined maintained Cargo inventory gains two version splits; the review record
tracks their follow-up.

The earlier security update introduces a reviewed `num-bigint 0.4.8`/`0.5.1` split while removing two other
splits; the record names its parents, maintenance owner and review date. Reduced
counts do not establish non-regression. Native closures, local packages and
future advisories are outside the Cargo query; recheck before release.

The maintained-manifest `graph alignment --check` still exits 2: version ranges,
path overrides and multiple versions remain. Inventory and version projection
are complete for the selected manifests; platform and feature activation remain
unknown. No verified baseline or alignment-policy exception is established by
this review.

## Maintained update inputs

Review every update candidate under the
[dependency policy](dependencies.md#dependency-maintenance). Record current
advisory coverage and the tested build and runtime combinations separately from
update proposals.

| Input | Update coverage and review trigger |
| --- | --- |
| Root `Cargo.lock` and GitHub Actions | Weekly Dependabot proposals. Cargo fixtures are excluded. |
| `nix/flake.lock` | Weekly Dependabot proposals for the flake input. Review the resulting native closures. |
| `nix/flake.nix` and native overrides | Manually update pinned Rust archives and native patches during catalogue, upstream release or advisory reviews. Follow the [tracked OpenSSL and network-tool reviews](dependencies.md#native-packaging-checks) and qualify affected outputs. |
| `crates/ladyboot/flake.nix` and `flake.lock` | Coordinated manual catalogue migration on an applicable advisory or release review. Dependabot updates flake locks and cannot advance the manifest's exact SHA. Update the manifest, lock, plan provenance and affected overrides together, then verify the delivered closure and affected profile, image, kernel and lifecycle paths. |
| Ladyboot Go overlays in `crates/ladyboot/nix/locks/` | Review the [container tools](../crates/ladyboot/nix/container-security.md) by the next release or 2026-12-15, whichever comes first. Regenerate each module pair and vendor hash from its pinned source and compiler, then verify the delivered binaries. |
| Ladyboot native Cargo overlays | Review [bootupd](../crates/ladyboot/nix/bootupd-dependencies.md) by 2026-12-15 and [ntpd-rs](../crates/ladyboot/nix/ntpd-rs-dependencies.md) by its next release or 2026-12-18, whichever comes first. Regenerate with the pinned upstream sources and verify the affected packages. |
| Ladyhost GitHub CLI overlay in `examples/ladyhost/tool-locks/github-cli/` | On an applicable advisory or release review, regenerate the module pair, compiler and source provenance and binary digest together. Verify host authentication with the resulting binary. |
| Explorer npm fixture manifests and locks | Retain the synthetic inputs unchanged for reproduction. Review upstream Explorer revisions and their runtime separately when refreshing the demo. |

The audit driver pins Codex CLI 0.165.0. Review an exact candidate when a
protocol change or applicable advisory requires an update. Qualify its strict
configuration, transcript, refusals, limits and cleanup on the reviewed
confinement and provider configuration before changing the pin. See
[native audit requirements](audits/usage.md#runtime-prerequisites-and-limits).

## Continuous integration

[GitHub Actions](../.github/workflows/ci.yml) runs the checks above on pushes to
`main`, pull requests and manual dispatches. It uses Ubuntu 22.04 and the pinned
`nix#ci` development shell, prepares both Nickel evaluators, then runs Cargo
offline after explicit dependency acquisition. It also runs the Python suites
above. The independent Ladybom package job uses the same pinned Rust toolchain
and qualifies the archives without preparing Nickel or LadybugDB.

Two other jobs use the locked Nix toolchain with sandboxing enabled. The graph job
installs the official LadybugDB 0.17.1 Linux CLI archive, verifies its pinned
SHA-256 before extraction and checks its version. It passes the absolute executable
path to six exact Ladybom fixtures, without compiling the engine. The dependency
job prepares the pinned Cargo and Node tools
and runs three exact Ladyshell fixtures for offline preparation, npm workspace
layout and fixed-output hash refusal. The
[`check_native_fixtures.sh` runner](../tests/check_native_fixtures.sh) checks
each selected test reports one pass.

The required `Rust and native fixtures` check succeeds only when the Rust
workspace, Ladybom packages, native graph and Nix dependency jobs all succeed.
Jobs use commit-pinned actions, read-only repository permissions and checkout
without retained credentials. They limit build and test concurrency and keep
build output in Lady's `target/`.

To enter the same tool environment locally:

```sh
nix --extra-experimental-features 'nix-command flakes' develop path:./nix#ci
```

Live OpenShell, providers, Docker images and VMs require separate
qualification. Bootc lifecycle, private GitHub policy and deployment checks
have dedicated validation paths. Keep advisory and alignment review tied to the
exact inputs and reference described above.
