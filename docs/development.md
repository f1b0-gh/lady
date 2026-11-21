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
proof that a deployment works. Ignored tests for LadybugDB, images, OpenShell,
Jujutsu and VMs have separate commands in the relevant guides. Build outputs,
state, exports and credentials stay outside published sources.

## Known dependency findings

The 2026-11-21 OSV query covers all 291 crates.io package versions in `Cargo.lock`,
without platform, feature or dependency-kind filtering. The
[review record](../sources/dependency-review.json) binds the exact lock, query,
response and advisory dates.

`rustix 1.1.6` fixes the reported extended-attribute soundness issue. Upgrading
Parquet to `59.3.3` removes the affected `thrift 0.17.0` dependency and unmaintained
`paste 1.0.15`. The remaining finding is
[`chrono 0.4.45` being unmaintained](https://osv.dev/vulnerability/RUSTSEC-2026-0543),
still required by Parquet. It remains maintenance work, not an approved exception.

The workspace has 298 packages and 14 multiversion families; extracting the local
`ladybom-graph` crate adds no registry packages or versions. The security update
introduces a reviewed `num-bigint 0.4.8`/`0.5.1` split while removing two other
splits; the record names its parents, maintenance owner and review date. Reduced
counts do not establish non-regression. Native closures, local packages and
future advisories are outside the Cargo query; recheck before release.

The maintained-manifest `graph alignment --check` still exits 2: version ranges,
path overrides and multiple versions remain. Inventory and version projection
are complete for the selected manifests; platform and feature activation remain
unknown. No verified baseline or alignment-policy exception is established by
this review.

## Continuous integration

[GitHub Actions](../.github/workflows/ci.yml) runs the checks above on pushes to
`main`, pull requests and manual dispatches. It uses Ubuntu 22.04 and the pinned
`nix#ci` development shell, prepares both Nickel evaluators, then runs Cargo
offline after explicit dependency acquisition. It also runs the Python suites
above. Actions are pinned to full commits;
repository permissions are read-only and checkout credentials are not retained.
The job bounds build/test concurrency and keeps build output in Lady's `target/`.

To enter the same tool environment locally:

```sh
nix --extra-experimental-features 'nix-command flakes' develop path:./nix#ci
```

CI does not disable isolation or run ignored tests requiring live OpenShell,
providers, native images or VMs. A green source check is not bootc lifecycle,
private GitHub policy or deployment qualification. Dependency advisories and
alignment remain the separate, incomplete review described above; CI does not
silently waive them or renew a reference. Required branch protection is a
separate repository setting.
