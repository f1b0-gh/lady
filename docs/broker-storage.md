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
qualified local OpenShell 0.1.4 Docker backend. Ordinary `destroy` seals the broker,
retains a verified storage archive and removes the original sandbox and volumes.
`--discard-work` refuses broker state. `destroy::cancel_broker` handles interrupted
provisioning against the original operation. The governed retained-receiver bridge
is still being integrated; this is not yet a complete task lifecycle API.

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

## Sealed storage exports

`storage::export::worker` streams a bounded tar archive from the three fixed
broker mounts. The hidden `ladyshell broker-export` entry reads a strict JSON
`storage::export::Request` from stdin (at most 16,384 bytes) and emits only binary
archive bytes on stdout. The request includes format 1, a 64-character lowercase
hexadecimal correlation token, and the original storage profile. The worker
rechecks the measured tmpfs caps and the denial of writes outside those mounts.

The host must first fence retained receivers and incoming uploads, then seal the
LO broker generation. The exporter requires the sealed `.lifecycle` directory
and absence of its `open` directory. It takes an independent exclusive lock on the
original control directory for the entire snapshot. An active broker writer,
missing lifecycle metadata or a substituted marker refuses export. This requires
a worker image with the LO Initialize/Seal protocol; old images cannot provide
this capability.

Exports preserve empty directories, incomplete dispatch files, installed packages
and incoming bytes. Reads are descriptor-relative and refuse symlinks, hard-linked
files, special files and different filesystem devices. Per-scope inode and logical
byte budgets are checked during traversal; sparse files cannot expand beyond the
configured byte budget. Paths use printable ASCII components of at most 100 bytes,
with at most 32 components and 255 bytes overall. Unsupported names refuse the
export instead of silently dropping recovery evidence.

`storage::export::verify` consumes the complete archive without extracting it.
It checks the original request, canonical ustar headers, parent directories,
component-wise lexical order, separate scope budgets and both end blocks. It
rejects trailing bytes, including extra zero padding. Its receipt hashes all wire
bytes and records the entry count. `Request::max_bytes` bounds capture space;
host disk admission and transport deadlines remain separate requirements.

A successful worker exit and valid archive are both required. The host must
verify the original runtime before and after export, fsync and publish the host
copy outside the deletion scope, then retain its receipt before any deletion.
`storage::export::capture` streams a trusted host command into a fresh private
file, requires successful client exit, verifies the complete archive and fsyncs
the bytes. It bounds stderr and stdout independently and refuses incomplete pipes
held by client descendants. Partial output remains on failure. Local filesystem
I/O is still subject to host scheduling. The caller must authenticate and recheck
the runtime, publish the copy and receipt durably, and retain the lifecycle lease.
The ordinary destruction path below performs that publication and retains its
journal before deletion. Calling the export primitives alone does not. No export
receipt grants lifecycle authority, establishes LO task retirement or permits a
sealed generation to resume execution.

Ordinary fixed-broker provisioning now initializes the LO lifecycle only after
verifying the original runtime, mandatory policy and all mounted caps. The host
retains `protocol.json` alongside `binding.json` and `mounts.json` before publishing
the deployment. Unsupported workers, mismatched replies and sealed generations
refuse publication; recovery never reopens a sealed generation. Later verification
requires the original capability record. This is a record of initial capability,
not a fresh assertion that a subsequently sealed broker still accepts mutations.

The ignored `qualified_broker_provisions_with_original_mounted_caps` test builds
from locked explicit artifacts, exercises ordinary provisioning and empty-plan
revalidation, then fills the 64 KiB / 32-inode control filesystem until both
available counters are zero. It requires ENOSPC for both attempts, seals at full
capacity and retains a verified host archive before stop/start. It then requires
refusal of the old runtime binding and removes its original sandbox, volumes and
image tag. This qualifies storage/export and runtime recovery, not LO admission
or ordinary broker destroy. Assertions are caught so fixture cleanup also runs
after a test panic; abrupt test-process death retains journals for explicit cleanup:

```sh
LADYSHELL_BROKER_CLEANUP_EVIDENCE=/absolute/retained/image-fixture \
  cargo test --locked -p ladyshell-cli --test broker_image_native \
  cleanup_retained_broker_qualification -- --ignored --nocapture
```

That cleanup helper accepts only the original retained fixture identities. Keep
its source, locks, compact evidence and exports; generated executable copies can
be reclaimed after the fixture and every consumer have settled.


## Journalled broker destruction

`ladyshell destroy --state /absolute/path/to/state` acquires the original state
lock and exclusive session lease. It verifies the original daemon, gateway,
sandbox, running incarnation, policy, mounted ceilings and volume receipts,
then records `broker-destroy.json`. All managed execution and reapply entry points
refuse this persistent fence. Recovery uses the same command and state directory;
a completed deletion never makes that state eligible for reprovisioning.

The journal advances through intent, sealed, captured, exported, deleting,
sandbox-deleted and complete. Sealing closes the broker generation permanently.
A bounded streaming export is verified and fsynced before its receipt is retained;
`broker-recovery/export.partial` is renamed without replacement to `export.tar`,
and the containing directory is fsynced before recording the deletion intent.
The archive and journal remain outside the sandbox and volume deletion scopes.

An interrupted, unacknowledged transport copy may be regenerated only while the
original runtime and sealed source are verified available. The attempt count and
discarded staging size are recorded before truncation. Captured or published
archives are never overwritten. Symlinks, hardlinks, unexpected file permissions,
a missing source identity or insufficient sampled host capacity refuse capture.
The preflight capacity observation is not a reservation or a host disk hard cap.

Deletion is retried only against the original sandbox identity. Missing sandboxes
are accepted as cleanup recovery only after the deletion intent was retained;
otherwise their disappearance is a loss. After API deletion, the pinned Docker
daemon must also report no original runtime. Each volume is then removed through
its own original receipt journal, with non-forced removal and attachment refusal.
`storage::remove_original` checks the complete deployment receipt set before any
volume deletion intent or effect. Lost replies and partial volume cleanup retain
the same journal for retry. Every retry revalidates the complete retained archive,
even when the sandbox is already absent.

These records do not close LO task scopes or release Promise occupancy. Host
lifecycle policy admission belongs to the embedding orchestrator. A changed or
lost original runtime is not silently readmitted for export. Incomplete apply
operations use the separate cancellation path below.

The explicit native qualification exercises ordinary provisioning, simultaneous
byte and inode exhaustion, ordinary destroy, archive verification after deletion,
original-volume absence and idempotent retry:

```sh
LADYSHELL_BROKER_IMAGE_EVIDENCE=/absolute/path/to/evidence \
LADYSHELL_BROKER_WORKER=/absolute/path/to/lo-executor-worker \
LADYSHELL_STORAGE_TEST_GATEWAY=openshell \
cargo test --locked -p ladyshell-cli --test broker_image_native \
  qualified_broker_destroy -- --ignored --nocapture
```

The test retains `full-storage.json`, `ordinary-destroy.json`, lifecycle and
volume journals, the verified tar and its receipt. The fixture removes only its
owned image tag after the lifecycle assertions; test panics still run the
fixture's separately bounded cleanup.


## Interrupted provisioning

Use `ladyshell cancel-broker --state /absolute/path/to/state`, or
`destroy::cancel_broker(&Existing)`, for an incomplete broker apply operation.
The original desired inputs are retained in the apply journal before effects.
Cancellation checks their digest, owner, name, phase and the unchanged predecessor
or partially published state. It does not reload source files, configuration or
runtime artifacts that may have changed since provisioning. Legacy operations
without retained inputs require resuming their original apply, then using ordinary
`destroy` on the completed state.

A persistent `broker-cancel.json` fence prevents provisioning and managed
execution from resuming while cancellation is pending or complete. The original
operation and state files remain intact. Cancellation of a pending replacement
targets only that operation's new resources; predecessor resources remain intact,
and the state remains fenced. Images and host build inputs remain available for
inspection or separately scoped reclamation.

Before runtime validation, cancellation records the observed original sandbox
identity, confirms deletion on the original backend, then removes partially
created volumes against their exact planned owner, workspace and limits.
`storage::remove_planned` checks those intents before adopting any lost creation
acknowledgement. Retained receipts still require the same volume identities.
Missing or substituted resources never cause the controller to create replacements.

Runtime validation has its own retained intent. A missing binding after that
intent is a recovery gap, not evidence that no generation existed. Once the
original binding or publication result exists, cancellation uses the same sealed,
verified export-before-delete path as ordinary destruction. If initialization was
interrupted, it may finish only against the original qualified runtime, without
publishing it for tasks. An already sealed generation may acquire a cleanup-only
initialization receipt: ordinary execution verification rejects that receipt,
while export and deletion can proceed. The generation is never reopened.
A failed qualification, lost generation or failed export
never falls back to deleting unpublished resources. Reconcile the original binding
from retained evidence before retrying cancellation; keep its data meanwhile.
A cancellation fence does not permit resuming apply or admitting new work.

The explicit native cancellation qualifications interrupt real native provisioning
immediately after sandbox creation, immediately after runtime validation, and
with a sealed generation missing its initialization receipt. They exercise cancellation, archive retention for the bound generation, original
volume absence, refusal to resume apply, unchanged operation evidence and
idempotent retry. Run them with the same evidence, worker and gateway variables:

```sh
cargo test --locked -p ladyshell-cli --test broker_image_native \
  qualified_broker_cancellation -- --ignored --nocapture --test-threads=1
```

## Bounded component intake

`execution::upload(&environment, &component_sha256, &bytes, timeout_seconds)`
transfers one component to the original environment's incoming volume. The host
selects the retained `EnvironmentPin` independently of task input. The method
verifies that environment, its current runtime and fixed broker profile, then
holds its original session lease through the bounded transport. It accepts
nonempty input of at most 2 MiB whose SHA-256 matches the supplied lowercase hex
digest; timeouts range from 1 to 86,400 seconds.

The command is fixed: `lo-executor-worker broker-upload` with the three broker
roots and component digest. Binary bytes travel through stdin. A successful
`UploadedComponent` requires a successful exit, bounded untruncated output and
an exact digest/length receipt. No task field can select paths or native argv.
This requires an LO worker implementing `broker-upload`; the initial
Initialize/Seal capability check alone does not establish intake support. Lock
and qualify matching worker, Ladyshell library and runtime versions together.

The broker uses create-only files and the same mutation/seal lock as Stage and
Execute. Disk exhaustion can leave an occupied partial incoming file. A repeat
upload refuses that name even if space later becomes available; it never replaces
or repairs partial or complete bytes automatically. Timeout, lost output or a
bad receipt remains unresolved. Preserve the original intent and environment
for observation and sealed export before deletion.

This blocking host primitive grants no policy authority and performs no Stage,
activation or task admission. Initiate the owning lifecycle operation under the
orchestrator's live policy guard, then perform blocking transport outside that
guard. A serialized pin or successful upload is not evidence of task retirement.

The ignored `native_component_upload_staging_execution_and_full_intake_export`
qualification uses the same evidence/worker/gateway variables as the native
destroy test, plus `LADYSHELL_BROKER_TEST_PACKAGE` naming an explicit maintained
LO summary package directory (`artifact.json` and `components/<digest>.wasm`).
It uploads and stages through the ordinary retained receiver, executes the
summary component, exhausts the incoming byte cap and refuses a partial retry,
then exports before ordinary deletion. Its host admissions are synthetic; it
does not qualify LO policy or Promise integration.
