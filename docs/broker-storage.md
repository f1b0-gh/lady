# Bounded broker storage

A fixed WASI broker needs separate capacity for incoming components, immutable
installed packages and retained execution records. Filling the package area must
not consume the space reserved for dispatch barriers or results. Reclaiming space
must never make an uncertain dispatch eligible to run again.

The `ladyshell::storage` API provides fixed Docker local tmpfs intents, per-volume
creation/deletion journals, original identity checks, and correlation of fresh
mount and filesystem observations. This is an optional capability. Ordinary
`app::lock_broker`, `app::make_broker_plan` and `app::apply_broker` accept an
explicit `BrokerDesired` with independently selected worker and Ladyshell runtime
ELFs. Native provisioning supports the closed `openshell-wasi` profile on the
qualified local OpenShell 0.1.4 Docker backend. Ordinary destruction/export and
the governed retained-receiver bridge are still being integrated; this is not
yet a complete task lifecycle API. Native `destroy` refuses broker state,
including `--discard-work`, until the broker export/deletion path is available.

## Configuration and lifecycle

The optional Nickel `storage` block selects byte and inode ceilings:

```nickel
storage = {
  control = { bytes = 65536, inodes = 32 },
  artifacts = { bytes = 262144, inodes = 64 },
  incoming = { bytes = 262144, inodes = 64 },
}
```

These small limits are useful for qualification, not a sizing recommendation.
Each byte limit must be page aligned, between 4 KiB and 16 GiB. Inode limits are
between 16 and 1,048,576. The resolved values participate in the original desired
input digest; recovery refuses changes. Without this block, existing serialized
configurations and driver behavior remain unchanged.

The three fixed mount targets are `/var/lib/ladyshell/broker/control`,
`/var/lib/ladyshell/broker/artifacts` and `/var/lib/ladyshell/broker/incoming`.
Call `storage::prepare` only within an independently admitted provisioning
operation. It records all original intents before creating anything and retains
each observed volume before proceeding. A lost acknowledgement can be reconciled;
a missing previously retained volume is refused, never recreated silently.

Before use, verify original volume receipts against the pinned Docker daemon,
then use `verify_mounts` to correlate the actual mount sources and fresh filesystem
measurements. It rejects replacement sources, bind-mount fallbacks, overlapping
nested mounts, different caps, duplicate scopes and shared filesystems. These
observations must come from a separately authenticated runtime and trusted probe.
A JSON record alone grants no authority and proves no containment.

`Filesystem::warning()` reports observed usage of at least 80% of either bytes or
inodes. This is a sampled warning that an orchestrator can pass to its agent. It
cannot reserve remaining space or replace kernel enforcement.

Before `storage::remove`, establish the original sandbox's absence and retain
required work and recovery exports. The Docker driver refuses attached volumes
and removes only the original identities without force. Partial deletion resumes
from the retained journal. Keep the journal after cleanup; deleting storage is
not proof that a task or managed Promise may retire.

## Fixed image and publication

Select `image = { backend = "nix", profile = "openshell-wasi",
platform = "x86_64-linux" }` and the storage block. Omit the provider; the broker
profile rejects native tools, mission checks, dependency preparation, audit and
extra permissions. The existing native profile still requires its provider.
`BrokerDesired` names both `worker` (the LO `lo-executor-worker` ELF) and `runtime`
(the Ladyshell CLI ELF); an embedding application is never substituted for either.

The environment lock hashes both artifacts and the five fixed Nix recipes.
Image construction authenticates copied inputs, freezes the recipes and records
the archive/image identity before loading. It reads image metadata without
spawning temporary probe containers. The operation-owned OpenShell sandbox runs
UID, binary-path, runtime and broker protocol checks before publication.

OpenShell 0.1.4 [validates the working directory before launching the workload](https://github.com/NVIDIA/OpenShell/blob/v0.1.4/crates/openshell-sandbox/src/delegated.rs)
and [requires a temporary write there](https://github.com/NVIDIA/OpenShell/blob/v0.1.4/crates/openshell-sandbox/src/process.rs).
The image therefore gives UID 10001 POSIX write access to the project directory;
Landlock permits only reads there when the workload runs. Source files remain
read-only. Publication must verify that writes to both the project and `/tmp`
are denied; an image permission check alone cannot establish this boundary.

Provisioning retains the local Docker endpoint and daemon identity before volume
effects. Resource commands use that explicit endpoint and recheck the daemon.
Publication correlates the actual sandbox/image/owner, container start identity,
volume fingerprints, fixed mounts, effective policy and in-sandbox filesystem
measurements. It retains the runtime and filesystem identities for recovery;
changed runtime or mount identity requires a separate deployment. The initial
carrier requests one CPU and 512 MiB; disk evidence does not certify every native
resource or process-scope guarantee.

The ignored `broker_image_native` test can build and provision from explicit ELF
inputs using `LADYSHELL_BROKER_IMAGE_EVIDENCE`, `LADYSHELL_BROKER_WORKER` and
`LADYSHELL_STORAGE_TEST_GATEWAY`. Select
`qualified_broker_provisions_with_original_mounted_caps` with `--ignored`.
It retains source/lock/build/operation journals and removes its original sandbox,
volumes and image tag. Its fixture cleanup is not the ordinary destruction API.

## Durability and policy limits

Docker local tmpfs is volatile. Its contents can survive broker process exit
while the mount remains alive, but not unmount, runtime reconstruction or host
reboot. A changed container start identity must invalidate the old receiver
incarnation. Requests requiring reboot persistence need a separately qualified
persistent quota profile. Host task/lifecycle journals must remain outside these
volatile volumes.

`policy::broker_policy()` requires Landlock, permits no network rules, and allows
writes only to the three roots and `/dev/null`. It grants no ambient filesystem
capabilities to WASI components. The effective-policy verifier accepts the
omitted empty map used by OpenShell 0.1.4; it refuses nonempty rules and null.
OpenShell's [schema](https://github.com/NVIDIA/OpenShell/blob/v0.1.4/crates/openshell-policy-schema/src/lib.rs)
omits empty maps, and its [network policy](https://github.com/NVIDIA/OpenShell/blob/v0.1.4/crates/openshell-supervisor-network/data/sandbox-policy.rego)
defaults to denial.

Disk caps do not bound the broker compiler's memory, CPU, process count or elapsed
time. Qualify and enforce those limits independently before admitting work.
Neither a completed computation nor a process reply establishes effect application
or complete process-scope closure.

## Reproduce the mounted-cap qualification

The explicitly ignored `storage_openshell` test creates an owned sandbox and three
owned volumes through the selected local Docker/OpenShell gateway. Supply a
reviewed image already available to that daemon, with user/group `sandbox` (10001),
`/bin/python3`, `/bin/sleep` and standard runtime support. The test resolves its
immutable image ID; it does not download or build an image.

```sh
mkdir -p /absolute/path/to/evidence
LADYSHELL_STORAGE_TEST_ROOT=/absolute/path/to/evidence \
LADYSHELL_STORAGE_TEST_GATEWAY=openshell \
LADYSHELL_STORAGE_TEST_IMAGE=sha256:YOUR_REVIEWED_IMAGE_ID \
cargo test --locked -p ladyshell --test storage_openshell -- --ignored --nocapture
```

The synthetic Python probe writes until byte exhaustion and creates empty files
until inode exhaustion in each area, requiring actual `ENOSPC`. It removes its
files and checks that available capacity returns. The host verifies policy,
original volumes, mounted caps and runtime identity before accepting the result.
The harness then deletes the owned sandbox and detached volumes, including on a
qualification error. `qualification.json`, effective policy and per-volume
journals remain in the selected evidence directory. If the controller itself is
killed, inspect those original records before resuming owned cleanup; never
remove a same-name replacement.

This qualification exercises real mount enforcement. It does not execute the LO
broker, qualify LO policy admission, or replace the remaining ordinary lifecycle
and retained-receiver integration tests. Python is a test probe, not an SDK or
production controller.
