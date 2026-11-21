# Ladybom

A Rust library for dependency inventories and static analysis. Ladybom reads
Cargo, Python, npm and Go source metadata, retaining source fingerprints,
package identities, constraints and coverage gaps. Scanning runs no package
manager, project code, Nickel or OpenShell and performs no network access.

```rust,no_run
use ladybom::scan_project;
use std::path::Path;

let report = scan_project(Path::new("/absolute/project"))?;
assert_eq!(report.schema_version, 2);
# Ok::<(), ladybom::error::Error>(())
```

The library has no Clap dependency. [ladybom-cli](../ladybom-cli/README.md)
provides the `ladybom` command. Ladyshell reuses the analyzer without the optional
`graph` feature and independently verifies its inputs before any preparation.
An inventory grants no permission to install, connect to a network or execute.

## Inventory contract

`deps` and its root reexports expose the same API. `Report` uses JSON schema
version 2. Components from a shared lockfile are stored once; member projects
reference their owner through `components_from`. Use
`Report::components_for(project)` to resolve these references. Regenerate old
version 1 reports and snapshots explicitly rather than adopting them silently.

`complete` describes parser coverage, not reproducibility, dependency activation
or absence of vulnerabilities. Missing locks, unresolved declarations,
unsupported formats and ambiguous identities remain visible. The normal source
snapshot is bounded to 5,000 files and 256 MiB, with 8 MiB per manifest/lockfile;
selected symlinks are refused and protected paths remain excluded.

Supported inventory details and preparation restrictions are documented in
[dependencies](../../docs/dependencies.md). Go module/workspace directives, checksums and vendor inventories are read
without running Go. Local `use`/`replace` references require matching manifests
already in the selected snapshot. Requirements are minimum versions; checksums
never become components or locks. Vendored modules are observations, with local
replacements kept distinct. Go projects remain unlocked and unresolved build
selection is explicit. Artifact collection remains a separate operation.

## SBOM and advisory APIs

`cyclonedx::from_report(&report)` returns a validated CycloneDX 1.5 `Bom`;
`cyclonedx::write_json(&report, writer)` serializes it. Neither reads sources nor
uses the network. Both are available without `graph`, including under `deps`.
The default public projection retains accepted identities, static relationships,
explicit licenses and coverage summaries; opaque native data is omitted.
`from_report_with_profile` and `write_json_with_profile` accept
`ExportProfile::PrivateDetailed`, which can expose sensitive native details.

Static relationships describe potential dependencies, not an activated build.
CycloneDX composition remains `unknown` or `incomplete`, even if parsing succeeds.
Document identities depend on the actual exported content. `interop::bundle`
partitions independent lockfiles into public artifacts and private native reports
with deterministic identities and a hash manifest; decisions never transfer
implicitly between reports. See [interoperability](../../docs/ladybom-interop.md).

`vuln` evaluates native reports against separately supplied OSV snapshots,
checks policy and exports CycloneDX VEX without `graph`, Clap or execution.
Matches retain advisory evidence and candidate fixes; they do not establish
exploitability. Private registries, Git sources and ambiguous identities remain
unknown. Decisions and exceptions expire and bind exact report/snapshot digests.
For external JSON, use `vuln::parse_json` before `serde_json::from_value` so that
duplicate keys in nested OSV extensions are also refused.
See [vulnerabilities](../../docs/vulnerabilities.md) for inputs and policy.

## Optional graphs and removal analysis

The `graph` feature, disabled by default, adds Parquet snapshots, version
alignment, lexical usage analysis and removal simulations. Snapshot export,
inspection and alignment are static. Native traversal and simulation require an
explicit absolute path to trusted LadybugDB **0.17.1**, with bounded time,
memory and output. See [graphs](../../docs/dependency-graphs.md).

`deps::graph::analyze_alignment` groups versions by identity, source and lockfile
and separately audits direct pins and coverage. `AlignmentAnalysis::policy_pass`
is stricter than analysis completeness. `Ladybug::explain_alignment` adds bounded
reverse paths; Cargo features and target conditions remain unevaluated.

Qualified local components use graph identities `pkg:generic/cargo-local/...`,
`npm-local/...` or `python-local/...`; these are not public registry packages.
Selected manifests must justify local npm and uv identities. Missing, conflicting,
external or ambiguous evidence remains incomplete. Different directories retain
distinct source identities. Old reports without manifest evidence need a new scan.
Local identity does not establish public advisory coverage or installability.

`deps::graph::plan_alignment(&graph)` returns JSON v1 `AlignmentPlan`, bound to
`graph_digest`; `to_markdown()` provides an exportable rendering. Actions start
with coverage gaps, then resolution and parent migration reviews. They preserve
contexts, parents and indices into alignment groups/source variants. Full
transitive constraints remain unknown. `analysis_complete` is coverage only;
`remediation_approved` is always false. JSON and Markdown are limited to 128 MiB.
No version, exception or baseline is chosen or updated by this API.

`deps::graph::check_alignment_policy` compares verified snapshots against an
`AlignmentPolicy` with a versioned baseline digest and temporary exceptions.
Inherited backlog is not approval. Pins and current advisories need separate
checks; see the [CLI](../ladybom-cli/README.md#alignment-policy).

`deps::prune_validation` exposes plan types and inventory verification without
optional features; constructing a plan requires `graph`. `NodeRef`, `Root` and
`IdentifiedRoot` live in `deps::declarations`, with compatible graph reexports.
`inventory` supplies shared bounded readers. `deps::constraints` matches Rust,
Python and npm versions; preparation permissions belong to Ladyshell. Ladyshell
also owns check execution and receipts. Removal candidates remain hypotheses.

## Retained inputs

The workspace pins `nickel-util =0.1.0` from crates.io. No sibling checkout or
Nickel evaluator is required for a Ladybom scan.

Fixtures in `tests/fixtures/` retain original Erwin names and digests to test
compatibility. Native tests require explicit `LADYBOM_LADYBUG_BIN` selection.
[Nix/Go artifact SBOMs](../../docs/artifact-sbom.md) use a separate explicit
collector; offline export does not expand the static scanner's coverage.
