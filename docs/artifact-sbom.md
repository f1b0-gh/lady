# Nix/Go artifact SBOMs

Ladybom separates explicit artifact collection from static source scanning.
`scan` executes no project tool. `artifact collect` runs three trusted
executables selected by the caller; `artifact export` runs no process and needs
neither the original rootfs nor a Nix daemon.

## Why Go and Nix use different evidence

Ladybom distinguishes declared requirements, recorded dependency resolution and
delivered files. The available evidence differs by format:

| Ecosystem | Source evidence and what Ladybom can read statically |
| --- | --- |
| Cargo | [`Cargo.lock`](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html) records selected versions, sources and dependency relationships. Ladybom reads this resolution alongside the manifests without running Cargo. |
| npm | [`package-lock.json`](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/) records resolved package versions and installation locations. Ladybom can reconstruct the recorded dependency graph without running npm. |
| Python / PyPI | [`uv.lock`](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile) records resolved versions across supported environments. `pyproject.toml` declares requirements; flat requirements exports have less evidence and retain explicit coverage gaps. PyPI is the package registry, not a lockfile format. |
| Go | `go.mod` declares minimum module requirements; `go.work` changes the workspace context. `go.sum` and `go.work.sum` hold integrity hashes, while `vendor/modules.txt` records vendored observations. These are not interchangeable with a resolved dependency graph. |
| Nix | [`flake.lock`](https://nix.dev/manual/nix/2.36/command-ref/new-cli/nix3-flake.html#lock-files) pins flake inputs, such as a nixpkgs source revision. It does not enumerate the packages selected and built for a particular system configuration. |

Go checksum files **are parsed**, but their entries do not become resolved SBOM
components. A [`go.sum` file](https://go.dev/ref/mod#go-sum-files) may retain
multiple versions, hashes of `go.mod` files alone, and versions no longer needed.
Go selects a build list from module requirements using
[minimal version selection](https://go.dev/ref/mod#minimal-version-selection).
Ladybom does not run that resolver or fetch missing module metadata during
`scan`. Its [Go source inventory](dependencies.md#go-source-inventory) therefore
remains unlocked, with resolution and advisory coverage gaps explicit.

For Nix, the selected outputs depend on evaluation, configuration and target
system. The [closure of an output](https://nix.dev/manual/nix/2.35/glossary.html#gloss-closure)
describes its store references; a derivation's closure instead describes build
dependencies. Ladybom uses explicit native metadata and the delivered file
inventory rather than treating pinned flake inputs as installed packages.

The collector combines these two views for Ladyboot-built systems: it verifies
delivered Nix outputs and reads [Go build metadata](https://pkg.go.dev/debug/buildinfo#ReadFile)
from binaries without executing them, binding the observations to file hashes.
This is useful when an existing Go service is shipped in a container: source
requirements and the binary actually delivered answer different questions.
The current workflow requires a Ladyboot inventory and matching archive; it is
not a general scanner for arbitrary OCI images or live Kubernetes clusters.

Cargo, npm and Python locks likewise do not prove what was built, installed or
deployed. The distinction is the evidence and collector coverage available
today, not a guarantee that those ecosystems need only source analysis.

## Collect and export

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
