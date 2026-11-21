# Build and development

## Prerequisites

Lady targets Linux, including Ladybom's use of `/proc/self/fd`. Building the
workspace requires stable Rust and a C compiler. Nix recipes currently select
`x86_64-linux`; this is not a claim of other-platform qualification.

Cargo uses `target/` in Lady. If your shell sets a target directory for another
project, unset it or set `CARGO_TARGET_DIR="$PWD/target"` from the repository root.
The workspace includes all project source dependencies; no sibling repository
is needed. Package downloads during a build are separate from Ladybom scanning.

## Rust consumers

Nickeling owns the shared `nickel-util =0.1.0` helper. Its unchanged source and
Apache license are included in `vendor/nickel-util`. The URL, full published
commit and file hashes are recorded in [the source lock](../sources/nickeling.json).
With Python 3.11 or later:

```sh
python3 scripts/check_sources.py
cargo build --workspace --locked
```

The checker verifies the complete bundle and workspace declaration offline;
Git commit provenance is recorded, not authenticated by hashes alone. To update,
review a published Nickeling commit, replace the bundle with its exact crate
files and repository license, update the source lock and Cargo lock together,
and follow the [dependency policy](dependencies.md#dependency-maintenance). Do not
edit bundled source locally or follow a floating branch during builds.

This bundle is a temporary bridge to a published `nickel-util` crate. Once that
release is available and reviewed, use the registry dependency and its Cargo
lock checksum, update Nix/runtime packaging to supply the same locked source,
and remove the bundle and its special source checker. A registry declaration
alone does not replace the runtime's source-verification requirements.

The Nix runtime copies the bundle into its source snapshot. Ladyshell hashes
the runtime sources before preparation; building it does not use a host binary.

## Required checks

```sh
python3 scripts/check_sources.py
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
python3 tests/check_boundaries.py --bootc crates/ladyboot
```

Set `CARGO_BUILD_JOBS=2` when limiting build concurrency. Library checks preserve
CLI independence; Ladyboot is checked with default features disabled by the
boundary checker.

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

The 2026-11-21 OSV query of all 295 crates.io package versions in `Cargo.lock`
reported the following existing findings, without platform or feature filtering.
The [review record](../sources/dependency-review.json) binds the lock digest,
query parameters, response digest and advisory modification dates:

| Package | Finding | Advisory |
| --- | --- | --- |
| `chrono 0.4.45` | Unmaintained | [RUSTSEC-2026-0543](https://osv.dev/vulnerability/RUSTSEC-2026-0543) |
| `paste 1.0.15` | Unmaintained | [RUSTSEC-2024-0436](https://osv.dev/vulnerability/RUSTSEC-2024-0436) |
| `rustix 1.1.5` | Uninitialized bytes in xattr functions | [RUSTSEC-2026-0486](https://osv.dev/vulnerability/RUSTSEC-2026-0486) |
| `thrift 0.17.0` | Unbounded allocation in binary protocol | [RUSTSEC-2026-0435](https://osv.dev/vulnerability/RUSTSEC-2026-0435), [GHSA-2f9f-gq7v-9h6m](https://osv.dev/vulnerability/GHSA-2f9f-gq7v-9h6m) |

These are dependency findings, not confirmed exploitability in Lady. They remain
maintenance work, not approved exceptions. The source bundle update adds seven
package versions and five multiversion families; none of those additions matched
an OSV advisory in that query. This is a portability update, not a reduction.
Local packages, native closures and future advisories are outside that result.
Recheck current sources before a dependency update or release.

The maintained-manifest `graph alignment --check` also exits 2: version ranges
and multiple versions remain, and static coverage of the excluded helper's
resolution context is incomplete. No verified baseline or non-regression gate
is established by this publication; the review record retains the exact scope.

## Continuous integration

[GitHub Actions](../.github/workflows/ci.yml) runs the checks above on pushes to
`main`, pull requests and manual dispatches. It uses Ubuntu 22.04 and the pinned
`nix#ci` development shell, prepares both Nickel evaluators, then runs Cargo
offline after explicit dependency acquisition. Actions are pinned to full commits;
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
