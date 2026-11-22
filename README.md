# Lady

Lady is a set of Linux tools for understanding a software project, running work
in a controlled environment, building its operating-system image, and publishing
reviewed changes.

## Why it exists

A dependency inventory answers what a project declares. It does not tell you
what an agent may download or execute, whether its sandbox enforces that policy,
or which changes are ready to publish. Lady keeps those decisions explicit and
connects them through checked inputs, locks and retained results.

Use the tools independently, or combine them for a workflow in which source
analysis, execution, system construction and host credentials have separate
owners.

| Tool | Use it to | Guide |
| --- | --- | --- |
| **Ladybom** | Inventory Cargo, Python, npm and Go source metadata; export SBOMs; inspect dependency graphs and supplied security advisories | [CLI](crates/ladybom-cli/README.md) · [Rust API](crates/ladybom/README.md) |
| **Ladyshell** | Prepare authorized OpenShell environments, run tasks and retain their state and exports | [Usage](docs/usage.md) |
| **Ladyboot** | Describe system needs in Nickel and build bootc OS images with Nix | [Profiles and images](crates/ladyboot/README.md) |
| **Ladyhost** | Keep GitHub credentials and signing keys on the host; publish and integrate reviewed Jujutsu commits | [Host workflow](crates/ladyhost/README.md) |

## Start with an inventory

You need Linux, stable Rust, a C compiler and Git. This path does not require
Nickel, Nix, OpenShell or a model provider. Cargo's first build may download
packages; scanning itself does not access the network or execute project code.

```sh
cargo install ladybom-cli --version 0.1.0 --locked
ladybom scan --project /absolute/path/to/project --json
```

For the minimal build or a local Cargo installation, see the
[CLI build choices](crates/ladybom-cli/README.md#build-and-install-choices).

For a CycloneDX SBOM, write outside the scanned project:

```sh
ladybom scan --project /absolute/path/to/project \
  --cyclonedx > /absolute/path/outside-project/bom.cdx.json
```

Read the report's coverage and diagnostics. Unsupported inputs and unresolved
identities remain gaps; a successful scan is not a security clearance.
Nix/Go artifacts use a separate,
[explicit collection workflow](docs/artifact-sbom.md).

## How it works

1. **Observe.** Ladybom reads bounded source snapshots and produces an inventory.
   Graph and advisory analysis use those recorded identities and their limits.
2. **Authorize and run.** Ladyshell checks the inventory against an independently
   selected source scope. An explicit configuration controls tools, permissions
   and checks. `lock → plan → apply` prepares the environment; execution requires
   verified identity, effective confinement and any required provider.
3. **Retain and review.** Results and exports remain available for inspection.
   Ladyhost performs forge and signing operations on the host, then verifies the
   selected commits and review policy before integration.

Ladyboot is a separate system-build path: Nickel validates needs, Nix selects
pinned packages and assembles the image, and Rust locks inputs and verifies
artifact receipts. Invoke `ladyboot` directly for this workflow; the retired
`ladyshell artifact` command only provides migration guidance. Ladyshell has no
Cargo dependency on Ladyboot. A report never grants installation or network
permission.

## Build and contribute

```sh
git clone https://github.com/f1b0-gh/lady.git
cd lady
cargo build --workspace --locked
```

This builds the tools as separate executables. For a first sandbox, follow the
[Ladyshell starting path](docs/usage.md#first-run).

Cargo uses the published `nickel-util =0.1.0` release pinned in `Cargo.lock`.
No sibling checkout is required. See the [build guide](docs/development.md)
for test prerequisites, required checks and known dependency findings.

See the component guides for usage and validation details.

[Documentation](docs/README.md) · [Contributor rules](AGENTS.md)

## License

[Apache-2.0](LICENSE). The bundled audit validator retains its
[MIT notice](crates/ladyshell/src/audit/validator/LICENSE-MIT).
