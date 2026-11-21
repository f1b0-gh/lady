# Nix/Go artifact SBOMs

Ladybom separates explicit artifact collection from static source scanning.
`scan` executes no project tool. `artifact collect` runs three trusted
executables selected by the caller; `artifact export` runs no process and needs
neither the original rootfs nor a Nix daemon.

Build [the CLI](../crates/ladybom-cli/README.md), then invoke it from PATH or use
`./target/debug/ladybom` from the repository root:

```sh
ladybom artifact collect --rootfs ROOTFS --manifest usr/share/ladyboot/inventory.json \
  --archive IMAGE.tar.gz --store-relative usr/lib/nix/store \
  --nix /absolute/nix --go-reader /absolute/go-buildinfo \
  --archive-checker /absolute/archive-check --output new-collection
ladybom artifact export --evidence new-collection/evidence.json --output new-sbom
```

## Collector prerequisites

Input paths and their ancestors must not be symlinks. Tools must be explicit
regular executable files. Collection never executes a binary from the rootfs
and performs no downloads. Supported inputs are Ladyboot manifest v1, Nix
path-info JSON v1 and derivation JSON v4. The Go reader emits `debug.BuildInfo`
fields as JSON. The archive checker receives exactly `(archive, manifest)` and
must reject any content difference.

Ladyboot's Nix package `bootc-podman-sbom-tools` supplies the Go reader and archive
checker. Resolve package symlinks to their real executables before collection.
Delivered rootfs symlinks are verified as inventory entries, never followed.

Collection verifies the file inventory and archive, compares copied outputs'
NAR hashes with native metadata, checks that derivations declare those outputs,
and binds Go metadata to delivered binary hashes. Inputs and tools are checked
again after execution. Supplied tools are part of the trust boundary; this
protocol does not confine them as hostile project code.

## Outputs and status

Each operation creates a new private directory (0700), with files mode 0600.
Collection writes `evidence.json` and `coverage.json`; export writes
`bom.cdx.json` and `coverage.json`. `manifest.json`, published last, lists hashes
and marks completion. Existing directories are refused. Publication failure
can leave an incomplete directory without a final manifest.

Exit code 0 means the declared scope was covered; 2 means partial results or
refused input; 1 means an operational failure. Inspect the final manifest and
coverage to distinguish a completed partial artifact from a failed publication.

`evidence.json` is private: it can contain local Go replacements and opaque
metadata. Public CycloneDX 1.5 is deterministic and omits host paths and opaque
fields. References distinguish Nix outputs with identical names/versions and
Go modules by binary. Export checks evidence consistency but does not
authenticate its producer or reread original artifacts.

Public Nix versions must start with a digit, `v` plus a digit or `unstable-`
plus a digit, using only letters, digits and `._+~-`. Opaque versions are
refused before publication. A missing Go main module stays missing with an
explicit gap; omitted empty fields from Go's native JSON are accepted.

## Coverage and limits

Coverage distinguishes delivered entries, resolved Nix outputs, ELF/Go metadata
and gaps. `(devel)` versions, local replacements, unqualified ELF formats and
unavailable Nix metadata remain unknown. Compressed archive contents and
non-Go static libraries are not enumerated. A file hash is not package identity.
Global OS composition is never declared complete; licenses, security advisories
and exploitability are not assessed by these commands.

Limits: 200,000 entries, depth 64, 32 GiB content, 64 MiB inventory/evidence,
10,000 Nix outputs, 1 MiB Go metadata per binary / 64 MiB cumulative,
200,000 modules and cumulative Nix references, 200,000 diagnostics / 16 MiB,
200,000 components and 128 MiB CycloneDX. Inspection allows 300 seconds per
phase; native collection 1,800 seconds total, with 60 seconds per Nix call,
30 seconds per Go reader and 300 seconds for archive checking.
