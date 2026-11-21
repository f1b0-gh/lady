# ladybom CLI

The inventory command for [Ladybom](../ladybom/README.md). The Cargo package is
`ladybom-cli`; its binary is `ladybom`. From the repository root:

```sh
cargo build -p ladybom-cli --locked
./target/debug/ladybom scan --project /absolute/project --json
./target/debug/ladybom scan --project /absolute/project --cyclonedx
```

Examples below assume the binary is on `PATH`; otherwise use
`./target/debug/ladybom`. Run `ladybom COMMAND --help` for all options. Keep outputs
outside scanned sources. Native JSON is the input to `ladyshell --ladybom`;
CycloneDX is an exchange format and does not replace that report.

## Commands and exit status

| Group | Purpose |
| --- | --- |
| `scan` | Static inventory, optionally restricted by source selection |
| `graph` | Snapshots, traversal, version alignment and baseline policy |
| `prune` | Usage evidence, removal simulation and validation plans |
| `vuln` | Local OSV import, assessment, policy and VEX |
| `interop` | Exchanges partitioned by independent lockfile |
| `vxdf` | Experimental untrusted import and explicitly reviewed export |
| `artifact` | Explicit Nix/Go collection and offline SBOM export |

Code **0** means the requested operation completed or its policy passed;
**2** means refused input, incomplete analysis or failed policy; **1** means an
operational failure. Complete `scan`, `alignment` or `vuln assess` results may
still contain findings. Use the corresponding checks for policy decisions.
File outputs refuse replacement. A published partial report is not approval.

## Source inventory

```sh
ladybom scan --project /absolute/project --sources /absolute/sources.json --json
ladybom scan --project /absolute/project --cyclonedx > /outside-project/bom.cdx.json
```

`--sources` accepts a strict JSON object such as
`{"include":["src","Cargo.toml","Cargo.lock"],"exclude":["src/runtime"]}`.
Paths are relative and normalized, without `..`; protected exclusions remain
active. Selected symlinks are refused and excluded paths are not traversed.
The selection file is limited to 1 MiB, with no symlink in its path. Use the
same scope as the Ladyshell mission, which independently verifies the report.

`--cyclonedx` and `--json` are exclusive. The default CycloneDX 1.5 profile is
`public`; `--export-profile private-detailed` includes native details that may
contain secrets. Unresolved constraints do not become component versions.
Composition stays `unknown` or `incomplete`; `ladybom:complete` describes parsing.
A partial SBOM is written with exit code 2. Native JSON reports are version 2;
graph snapshots remain version 1 with a version 2 inventory.

## Version analysis

```sh
ladybom graph export --project /absolute/project --output /absolute/new-snapshot
ladybom graph inspect --snapshot /absolute/new-snapshot
ladybom graph alignment --snapshot /absolute/new-snapshot --check
ladybom graph alignment-plan --snapshot /absolute/new-snapshot --markdown > /outside-project/plan.md
```

`graph export` also accepts `--sources`. Static alignment preserves identity,
source and independent lockfile contexts; nested npm installations share their
lockfile's comparison domain. Cargo `1.2.3` is a range; `=1.2.3` is an exact pin.
Without `--check`, complete analysis returns 0 even with duplicate versions.
With it, `aligned`, `pins_compliant` and `pin_lock_consistent` must all pass.
Exact pins require distinct resolved targets, preserving aliases. This does not
replace lockfile freshness checks with the native package manager.

`alignment-plan` produces JSON v1 by default or escaped Markdown. It retains the
snapshot digest, known parents, contexts, direct pins and coverage gaps. Complete
analysis returns 0 even with duplicates; incomplete coverage returns 2 and keeps
the diagnostic plan. `remediation_approved` is always false. No candidate is
selected or declared compatible/security-fixed; both outputs are capped at
128 MiB. Keep the snapshot with the plan.

### Alignment policy

```sh
ladybom graph alignment-policy --snapshot /state/current --baseline /state/reference \
  --policy /project/alignment-policy.json --as-of 2026-11-05T12:00:00Z
```

The versioned policy binds the reviewed reference's `graph_digest`, also stored
as `logical_sha256` in its snapshot manifest:

```json
{"schema_version":1,"baseline_graph_digest":"<reviewed SHA-256>","exceptions":[]}
```

An unchanged complete baseline can pass non-regression while divergent families
remain `review=backlog` and `reviewed_alignment_pass=false`. New divergent
families or new versions in still-divergent families require review even when
counts are unchanged. `--require-reviewed` requires active exceptions for every
remaining divergence. Each exception has this form:

```json
{
  "finding_id":"<family id>", "versions":["1.0.0","2.0.0"],
  "owner":"responsible team", "reason":"scope, evidence, maintenance cost and migration deadline",
  "issued_at":"2026-11-05T12:00:00Z", "expires_at":"2026-12-05T12:00:00Z"
}
```

Copy the exact finding ID and `after` version set. Maximum lifetime is 365 days;
expiry is exclusive. Future, duplicate, stale, out-of-scope or mismatched
exceptions are refused; expired exceptions block unchanged debt too. Policies
are limited to 4 MiB and reject unknown/duplicate fields.

Incomplete version coverage, changed manifests/domains or a changed supplier for
an existing package block a favorable conclusion. The scope is all locked
versions, including optional, build/dev and all platforms; it does not prove
activation. Verify scope independently, retain the immutable reference and its
digest, then compare new snapshots. Never regenerate baselines or exceptions to
make a check pass. Explicitly advancing a reviewed baseline after a reduction
prevents reintroductions; the tool does not remember reductions automatically.
[Maintenance rules](../../docs/dependencies.md#dependency-maintenance) also require
separate pin, advisory and consumer checks.

## Native and exchange operations

`graph query`, `graph impact` and `prune simulate` require an absolute trusted
LadybugDB 0.17.1 path through `--engine`. Alignment can optionally explain parents
with `--engine ... --package pkg:cargo/openssl`: defaults are 8 queries, 4,096
results, depth 16 and 60 seconds; maxima are 16, 4,096, 64 and 300. Truncation is
explicit and returns 2. Paths show potential dependants, not exploitability.

[Graphs](../../docs/dependency-graphs.md) documents usage evidence and removal
plans; only Ladyshell executes their checks. [Vulnerabilities](../../docs/vulnerabilities.md)
documents mandatory `--as-of`, coverage and expiring decisions. [Interoperability](../../docs/ladybom-interop.md)
covers public bundles, VEX profiles and reviewed VXDF export.
[Artifact SBOMs](../../docs/artifact-sbom.md) describes explicit collectors.
None of these reports authorizes installation, network access or project execution.

Clap belongs to this CLI crate. `ladybom_cli::{Cli, run}` supports composing
interfaces; the business library does not depend on it.
