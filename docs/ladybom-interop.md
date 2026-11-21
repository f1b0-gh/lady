# SBOM, VEX and experimental VXDF exchange

Local exports use no server, network or project execution. Sending artifacts to
Dependency-Track is separate. Schema validity, data preservation and applied
VEX decisions require different checks. Use [the CLI](../crates/ladybom-cli/README.md)
from PATH or invoke `./target/debug/ladybom` after building it.

## Public artifacts and identity

`scan --cyclonedx` emits CycloneDX **1.5**. The synthetic `ladybom-inventory`
application root represents inventoried sources, not a built application or
activated target. Its version is not inferred from a host path. Static edges
are potential: Cargo conditions, npm options and Python markers remain
unevaluated. Missing relationships remain unknown; parsing success never changes
composition to `complete`. `ladybom:complete` describes native parser coverage.

The default `public` profile allows accepted package identities, opaque references,
relationships, explicit licenses and coverage summaries. Native sources, artifact
URLs, paths, diagnostics and free metadata are omitted; hashes support private
correlation. Package names are not anonymized. `--export-profile private-detailed`
can contain secrets and is only for controlled exchange. It projects accepted
HTTP(S) distribution URLs with explicit hashes of that artifact, never inferred
licenses or package hashes from manifests. Referenced URLs are not downloaded.

Component references preserve contexts/shared locks. UUIDv8 serials bind exported
content and profile (excluding their own `serialNumber`); retain full hashes too.

```sh
ladybom interop bundle --report report.json --repository repository-id \
  --revision REVISION --target-profile static-all-platforms --output new-bundle
```

Bundles partition independent locks. Project identity binds repository, lock and
declared profile; version binds revision/report digest. Labels remain private in
`private/scope.json`; profiles do not prove activation. `manifest.json`, published
last, lists hashes, project/version and public/private paths. Directories/files
are 0700/0600; existing destinations and symlink paths are refused. Publish only
listed public artifacts, never the whole directory.

Shared-lock manifests stay together. Duplicate PURL or package/version occurrences
within a partition are refused because consumers can merge contexts. No artificial
PURL is invented. Global gaps survive in partitioned private reports. Recompute
advisories and decisions per partition; global VEX decisions never transfer.

## VEX scope and consumer checks

```sh
ladybom vuln vex --report report.json --snapshot osv-snapshot.json \
  --as-of 2026-11-05T12:00:00Z --profile local-components \
  --decisions decisions.json --output vex.cdx.json
```

Default profile `bom-link` targets the exact SBOM serial. `local-components`
embeds affected components and uses local references, refusing collisions across
sources/contexts, forks without PURLs and ambiguous advisory mappings. Select the
same `--export-profile` as the SBOM. Public output retains decision state and
hashes without sensitive free fields; private output may retain them.

Expired/inapplicable decisions remain provenance but are inactive. Risk acceptance
never becomes `not_affected`; `resolved` is refused for an affected match. An
expiry property does not force server revocation: read back applied decisions
and handle expiry explicitly. The CVE namespace does not imply NVD acquisition.

The [pinned synthetic Dependency-Track recipe](../qualification/dependency-track/README.md)
provides reproducible tests, not a blanket fidelity guarantee. Verify project,
version, serial, findings and applied decisions after asynchronous processing.
Consumers can lose global coverage/composition, merge identities, ignore aliases
or accept old VEX in a different project with matching packages. HTTP success or
an accepted import token alone proves none of these checks. Preserve versions,
image digests, exports, hashes and API results without credentials. Test missing
findings, multiple components, reimports, expiry, contradictions and new versions.

## VXDF 0.0.1

```sh
ladybom vxdf import --input evidence.vxdf.json --output retained-vxdf.json
ladybom vxdf review-template --input evidence.vxdf.json --report report.json --snapshot osv-snapshot.json \
  --revision REVISION --target-profile TARGET --as-of 2026-11-05T12:00:00Z --output review.json
# Complete and review the template; compute its exact SHA-256 before export.
ladybom vxdf export --input evidence.vxdf.json --report report.json --snapshot osv-snapshot.json \
  --revision REVISION --target-profile TARGET --as-of 2026-11-05T12:00:00Z \
  --review review.json --review-sha256 REVIEW_SHA256 --reviewer AUTHOR --output reviewed.vxdf.json
```

Import retains original UTF-8 and SHA-256 privately without following URLs,
paths or payloads. Limits are 4 MiB, depth 32, 20,000 nodes, 1 MiB strings,
256 findings and 256 evidence items per finding. Duplicate keys/IDs, invalid
dates and dangling local evidence references are refused. Rust validates the
pinned Draft 2020-12 schema and formats without HTTP/file resolvers. Imports and
correlations remain `trust: untrusted`, `qualified: false`; code 0 is not proof
of a vulnerability. The website schema differs from inspected repository
revisions; [the fixture manifest](../tests/fixtures/interop/manifest.json)
retains exact hashes, provenance and accompanying licenses.

`vxdf correlate` accepts the same input/scope arguments as `review-template`.
Each flow's `x-ladybom` must contain exact `report_digest`, `snapshot_digest`,
`finding_id`, `component_ref`, `purl`, native `source`, `manifest`, `lockfile`,
`context`, `revision` and `target_profile`. One exact `affectedComponents`
identity is accepted. Evidence needs UUIDs and timestamps satisfying
`timestamp <= validatedAt <= generatedAt <= as_of`; snapshot and evidence ages
are separately bounded to seven days by default. Operator expectations for
revision/profile are not independent execution attestations.

Templates start `unreviewed` with `public_content_approved=false`. Review each
finding as `validated_exploitable`, supplying author, dates, reproducible scenario,
observed result, tool/version, environment, limits and approved publication text.
Review must follow the document and remain unexpired; changed inputs require
new correlation/review. Check semantic agreement between evidence type and data
as well as schema validity. Export includes approved text, identities and hashes,
not opaque payloads. `human_review_assertion` and
`cryptographically_verified:false` state the limit: hashes bind a review without
authenticating its author or proving exploitability. Reimport grants no trust.
VXDF states never automatically alter VEX; no native Dependency-Track VXDF import
is assumed. Retain evidence and reviews in access-controlled storage.

## Offline validation and import comparison

Pinned schemas live in `tests/fixtures/interop`; Python validation dependencies
are separate from runtime dependencies. From the repository root:

```sh
uv venv --python /usr/bin/python3 /tmp/ladybom-interop-venv
uv pip sync --python /tmp/ladybom-interop-venv/bin/python --require-hashes --no-build --default-index https://pypi.org/simple tests/requirements-interop.txt
. /tmp/ladybom-interop-venv/bin/activate
python3 tests/check_ladybom_interop.py sbom.cdx.json vex.cdx.json
python3 tests/check_ladybom_interop.py --schema vxdf evidence.vxdf.json
python3 tests/check_ladybom_interop.py sbom.cdx.json --compare downloaded.cdx.json
python3 -m unittest discover -s tests -p test_ladybom_interop.py
```

Environment setup is explicit acquisition; validation stays offline, checks
schema hashes and refuses missing format validators or external resolution.
Choose a new environment unless intentionally resuming the same work. Comparison
checks roots, nested components, versions, relationships, metadata and coverage
across changed references; collisions block and losses remain visible. It does
not certify server execution or VEX decisions. Start with the
[synthetic fixture recipe](../tests/fixtures/interop/README.md).
