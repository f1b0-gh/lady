# Documentation

Start with the [project overview](../README.md) and [build guide](development.md).

| Task | Guide |
| --- | --- |
| Inventory a project or use the Rust API | [Ladybom CLI](../crates/ladybom-cli/README.md) · [Library](../crates/ladybom/README.md) |
| Inspect dependency relationships and removal candidates | [Graphs](dependency-graphs.md) |
| Supply security advisories and assess their coverage | [Vulnerabilities](vulnerabilities.md) |
| Exchange SBOMs and VEX | [Interoperability](ladybom-interop.md) |
| Collect Nix/Go artifact evidence | [Artifact SBOMs](artifact-sbom.md) |
| Configure and run an OpenShell task | [Ladyshell](usage.md) · [Dependencies](dependencies.md) |
| Run and verify native security audits | [Auditing](audits/usage.md) · [Run contract](audits/run-format.md) |
| Build bootc operating-system images | [Ladyboot](../crates/ladyboot/README.md) |
| Publish and integrate reviewed commits from the host | [Ladyhost](../crates/ladyhost/README.md) |

The component guides link to maintained qualification drivers and native
package provenance. Historical experiment outputs are not part of this source
distribution. Fixtures, schemas, source notices and build locks are retained.
