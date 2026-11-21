# Offline vulnerability assessment

Ladybom compares native inventories with local OSV advisories without network
access, installation, project execution, Ladybug, Nickel or OpenShell. Acquire
advisories separately, retaining source URL, revision/hash, collection time and
actual coverage. A match is evidence about a package/version, not exploitability.

## Sources and coverage

| Ecosystem | Advisory sources | Local support |
| --- | --- | --- |
| Rust / crates.io | [RustSec OSV](https://github.com/rustsec/advisory-db/tree/osv), GitHub advisories | OSV import and Cargo comparison |
| JavaScript/TypeScript / npm | [GitHub Advisory Database](https://github.com/github/advisory-database), OSV npm | OSV import and npm comparison |
| Python / PyPI | [PyPA Advisory Database](https://github.com/pypa/advisory-database), GitHub, OSV PyPI | OSV import and PEP 440 comparison |
| Go | [Go Vulnerability Database](https://vuln.go.dev/) | Unsupported by this inventory/advisory matcher |
| Other ecosystems | Their maintained databases or [OSV sources](https://google.github.io/osv.dev/data/) | Unknown until an adapter and version semantics are qualified |

Choose by registry/ecosystem, not project language. A PURL alone does not confer
coverage. Private registries, Git packages, ambiguous identities and local
components are not automatically mapped to public releases. Cargo Git PURLs
retain declared provenance but do not prove equivalence with crates.io.

Cross-check the modified component's maintainer advisories: fresh aggregate
databases can omit upstream reports. Preserve disagreements, missing responses
and limitations. Check wrappers, bindings and embedded native libraries separately;
archive hashes, ELF imports and licenses alone do not identify static library
versions. External tools such as `cargo audit` and `govulncheck` run separately.

Before dependency changes, assess candidates and then final lockfiles across all
maintained contexts, including transitive, optional, build/test and all-platform
packages. Existing findings remain visible. Version alignment and advisory policy
are separate controls. See [maintenance rules](dependencies.md#dependency-maintenance).

## Prepare inputs

Build [the CLI](../crates/ladybom-cli/README.md); examples assume `ladybom` on PATH.
Keep outputs outside the project and use unchanged source selection for both scans.

```sh
ladybom scan --project /absolute/project --json > /outside-project/report.json
ladybom scan --project /absolute/project --cyclonedx > /outside-project/bom.cdx.json
ladybom vuln import --input /advisories/npm.json --input /advisories/cargo.json \
  --source 'Reviewed mirror' --fetched-at 2026-11-04T12:00:00Z \
  --ecosystem npm --ecosystem crates.io --complete --output /outside-project/osv.json
ladybom vuln assess --report /outside-project/report.json --snapshot /outside-project/osv.json \
  --as-of 2026-11-04T13:00:00Z --output /outside-project/assessment.json
ladybom vuln check --report /outside-project/report.json --snapshot /outside-project/osv.json \
  --as-of 2026-11-04T13:00:00Z
ladybom vuln vex --report /outside-project/report.json --snapshot /outside-project/osv.json \
  --as-of 2026-11-04T13:00:00Z --output /outside-project/vex.cdx.json
```

Each `--input` contains one OSV object or an array. The command neither downloads
nor decompresses archives. `--source`, `--fetched-at`, at least one `--ecosystem`
(`crates.io`, `npm`, `PyPI`) and `--output` are required. `--complete` defaults to
false and asserts ecosystem-wide coverage; selected advisories or successful
per-version API requests do not justify it. Empty or incomplete paginated
responses never establish absence. Collection time is declared, not authenticated.

Inputs use native report schema 2 and OSV snapshot schema 1. A snapshot contains
`source`, `fetched_at`, `complete`, `ecosystems` and `advisories`, for example:

```json
{
  "schema_version":1, "source":"Synthetic example", "fetched_at":"2026-11-04T12:00:00Z",
  "complete":false, "ecosystems":["npm"], "advisories":[{
    "schema_version":"1.6.0", "id":"SYNTHETIC-001", "modified":"2026-11-04T12:00:00Z",
    "affected":[{"package":{"ecosystem":"npm","name":"example-package"},
      "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.1"}]}]}]
  }]
}
```

Imports allow 64 MiB total and 100,000 advisories; report and snapshot each allow
64 MiB; policy, decisions and signals each allow 4 MiB. Outputs are capped at
64 MiB and refuse replacement. Paths with traversal or symlinks, including
ancestors, are refused. All external JSON rejects duplicate keys even inside
OSV extensions; duplicate advisory IDs are refused. URL-shaped paths do not
trigger network access.

## Assessment semantics

Assessment schema 1 retains `report_digest`, `snapshot_digest`, `sbom_serial`,
`as_of`, source/time, `max_age_seconds`, coverage and findings. Findings preserve
component/context identity, advisory IDs/aliases, OSV evidence, candidate fixed
versions and limitations. `related` is not an identity alias. Withdrawn advisories
remain retained but do not create matches. Active advisories without package
metadata make coverage incomplete even if no finding can be constructed.

Explicit affected versions and SEMVER/ECOSYSTEM ranges support `introduced`,
`fixed`, `last_affected` and `limit`; Python uses PEP 440. Mixed registry/Git/path
Python sources remain unknown. Digests hash serialized models rather than raw
input bytes: JSON whitespace and object key order do not affect them. Digests
bind content, not supplier authenticity. `sbom_serial` must match the actual SBOM.

`--as-of` is mandatory. `assess` and `vex` accept `--max-age-seconds` (default
604800, seven days); `check` takes it from policy. Future or stale snapshots
cannot pass. OSV publication/withdrawal times need not precede modification time,
but none can follow snapshot collection. Missing coverage blocks favorable results.

## Decisions and exceptions

`check --decisions FILE` and `vex --decisions FILE` accept schema 1 bound to the
recomputed report and snapshot digests. Replace placeholders with exact values:

```json
{
  "schema_version":1, "report_digest":"<digest>", "snapshot_digest":"<digest>",
  "decisions":[{"finding_id":"<id>", "state":"not_affected",
    "justification":"code_not_reachable", "detail":"Reviewed affected call paths.",
    "author":"reviewer", "evidence":["review:ticket-123"],
    "issued_at":"2026-11-04T12:00:00Z", "expires_at":"2026-11-06T12:00:00Z"}]
}
```

Initial state is `in_triage`. `not_affected` requires a VEX justification;
both it and `false_positive` require author, detail and evidence. `exploitable`,
`in_triage` and `resolved` cannot hide a persisting affected match. A fix requires
a new scan/check. Every decision expires; changed inputs require new decisions.

Default policy rejects unqualified findings and stale/incomplete coverage.
`check --policy FILE` accepts temporary risk exceptions:

```json
{
  "schema_version":1, "max_age_seconds":604800, "exceptions":[{
    "finding_id":"<id>", "report_digest":"<digest>", "snapshot_digest":"<digest>",
    "author":"risk-owner", "reason":"Temporary acceptance pending tested upgrade",
    "evidence":["approval:ticket-456"], "issued_at":"2026-11-04T12:00:00Z",
    "expires_at":"2026-11-06T12:00:00Z"}]
}
```

Exceptions accept risk, never change VEX state or repair missing coverage.
Policy results expose `allowed`, `complete`, reasons and each finding's state,
priority, `accepted_risk` and `blocking`. `check --signals FILE` accepts
`{"schema_version":1,"source":"Reviewed feed","fetched_at":"2026-11-04T12:00:00Z","entries":[{"id":"CVE-2026-0001","known_exploited":true,"epss":0.8}]}`.
Signals older than 24 hours or in the future block the check. EPSS uses a fixed
heuristic threshold of 0.1; neither EPSS nor KEV grants an exemption.

## VEX and status

`check` and `vex` recompute from native report and snapshot; an assessment file
cannot substitute for either. Default VEX uses CycloneDX 1.5 BOM-Link references
to the exact SBOM serial. `--profile local-components` embeds affected components
and refuses ambiguous identities. `--export-profile` must match the target SBOM:
`public` omits free sensitive fields; `private-detailed` can contain secrets.
[Interoperability](ladybom-interop.md) covers publication and consumer limitations.

Fixed versions are candidates, not compatibility guarantees or automatic upgrade
instructions. Recheck modified sources and lockfiles after authorized consumer
tests. These assessments do not inventory system packages or prove a Ladyboot
image secure. No report authorizes network, installation or execution.

Without `--output`, assessment/check/VEX JSON goes to stdout. Code 0 means valid
import, complete analysis/export or allowed policy; 2 means refused/incomplete
input or failed policy; 1 means operational failure. A complete assessment can
return 0 with findings: use `check` for the policy decision.
