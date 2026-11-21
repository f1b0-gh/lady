# Offline qualification resources

`manifest.json` records SHA-256 hashes, URLs and revisions consulted on
2026-11-05. Licenses accompany the schemas. The VXDF schema from the website
differs from the one in the inspected repository; no revision equivalence
is claimed.

The files in `qualification/project` describe a fully synthetic npm dependency
diamond. Its `preinstall` script must never run. The advisory in
`qualification/osv.json` is fictional and does not establish a real vulnerability.

This reproducible example writes output outside the project. First prepare the
[pinned Python environment](../../../docs/ladybom-interop.md#offline-validation-and-import-comparison).

```sh
cargo build -p ladybom-cli --locked
mkdir -p /tmp/ladybom-interop-example
target/debug/ladybom scan --project tests/fixtures/interop/qualification/project --json > /tmp/ladybom-interop-example/report.json
target/debug/ladybom scan --project tests/fixtures/interop/qualification/project --cyclonedx > /tmp/ladybom-interop-example/sbom.cdx.json
target/debug/ladybom vuln import --input tests/fixtures/interop/qualification/osv.json --source synthetic-local --fetched-at 2026-11-05T12:00:00Z --ecosystem npm --complete --output /tmp/ladybom-interop-example/snapshot.json
target/debug/ladybom vuln vex --report /tmp/ladybom-interop-example/report.json --snapshot /tmp/ladybom-interop-example/snapshot.json --as-of 2026-11-05T12:00:00Z --profile local-components --output /tmp/ladybom-interop-example/vex.cdx.json
python3 tests/check_ladybom_interop.py /tmp/ladybom-interop-example/sbom.cdx.json /tmp/ladybom-interop-example/vex.cdx.json
```

Commands using `--output` refuse to overwrite files; choose another directory
to repeat the example. None of these checks contacts Dependency-Track.
The comparator can separately accept an SBOM read back after server processing
through `--compare` and report losses. Applying VEX decisions requires a
separate check.
