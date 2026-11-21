# Retained OpenShell execution

Use `ladyshell execution` to submit a host-approved task, disconnect, and
retrieve its original record and output. The receiver reserves each invocation
before launch and keeps its history if the client or supervisor is interrupted.
It runs fixed catalogue entries inside an existing verified native environment.

## Install and admit

Run these commands as the trusted host operator in an environment prepared
with `lock → plan → apply`. Keep the receiver in an absolute private path
with a host-owned parent outside the project and environment state. Keep the
installation files and pinned receiver ID under host control. See the
[native prerequisites](usage.md#prerequisites).

Write a JSON array of approved task definitions to `tasks.json`:

```json
[
  {
    "id": "python-check",
    "argv": ["python", "-m", "compileall", "src"],
    "timeout_seconds": 60,
    "output_limit_bytes": 16384
  }
]
```

```sh
RECEIVER=/absolute/private/receiver
ladyshell execution install --state "$STATE_DIR" --receiver "$RECEIVER" \
  --tasks /absolute/private/tasks.json
```

Installation prints `binding` and `definitions` keyed by catalogue task ID.
Pin the returned `binding.receiver_id` as `RECEIVER_ID`. Each definition digest
binds its argv, execution budget and original environment, including the source
inventory and runtime generation. The supervisor rechecks the environment,
provider and effective policy before dispatch.

Write an invocation file with these fields. Replace the example digest with
`definitions["python-check"]` from the trusted installation.

```json
{
  "scope": "project-checks",
  "id": "check-001",
  "task": "python-check",
  "definition_sha256": "INSTALLED_DEFINITION_SHA256",
  "intent": {"purpose": "check the reviewed Python sources"}
}
```

Bind the scope and advance its claim explicitly. The claim in a submission must
equal the current positive claim. The host supplies a reference and a short,
exclusive admission deadline in Unix seconds.

```sh
ladyshell execution fence bind --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --standalone
ladyshell execution fence advance --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --standalone --claim 1

ADMIT_BEFORE=$(($(date +%s) + 30))
ladyshell execution submit --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --invocation /absolute/private/invocation.json --reference host-check-001 \
  --admit-before "$ADMIT_BEFORE" --standalone --claim 1
```

Use exactly one of `--standalone` and `--owner FILE` on these commands. The
owner file contains `task` and `deployment` as 64-character lowercase hex,
`epoch` as an integer, and `incarnation` as 32-character lowercase hex.
Owner and claim are separate fences. Ownership advancement preserves history
and resets the claim to zero for explicit initialization. Dispatch requires a
positive claim. `fence` is host administration. Authentication depends on trusted
local access to the private state and receiver.

Submit returns JSON with `is_new` and the original `record`. Only first
acceptance starts a detached supervisor. The same scope, ID and complete
invocation return the original record, even after the original owner file is
removed. Changed intent under the same scope and ID conflicts. Pass admission
metadata separately. The first acceptance fixes the retained deadline, and the
catalogue supplies the complete argv. The supervisor needs kernel support for
`close_range` with `CLOSE_RANGE_CLOEXEC`. If startup or acknowledgement fails
after acceptance, inspect the original key.

The CLI accepts strict JSON regular files and refuses duplicate keys. Task
definitions, invocation and owner files are bounded to 3 MiB, 32 KiB and
4 KiB respectively. The catalogue has up to 64 tasks, each with a runtime
timeout of 1–86,400 seconds and a limit of 1–1,048,576 bytes per stream. Intent
is bounded to 16 KiB of encoded JSON, with up to 256 bytes each for scope and
invocation ID. Receiver retention is capacity-limited. Preserve the original
receiver for lookup. A separate installation has a new identity and applies
only to newly admitted work.

## Inspect, reconnect and recover

```sh
ladyshell execution status --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --id check-001
ladyshell execution output --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --id check-001 --stream stdout --offset 0 --length 16384
```

Status returns the retained `record` and a point-in-time `worker_observed`
sample. Status and output work with the environment offline. Output returns
raw bytes from `stdout` or `stderr`, with offset zero by default and a maximum
length of 1 MiB. It verifies the original capture hashes. Treat the private
receiver, intent and output as sensitive host data.

The admission deadline bounds starting work. The installed runtime timeout
bounds the OpenShell client and its capture. A client wait timeout or
disconnect leaves original work in place. `completed` records an
`openshell_client` exit of zero with complete captures. It establishes client
completion only. Nonzero exit, signals, timeout, overflow and interrupted
dispatch leave uncertain effects. The managed state fence excludes other Lady
sessions. Unmanaged writers and background sandbox processes remain outside
that guarantee.

If an `accepted` or `dispatching` record has no observed supervisor, inspect
it and explicitly recover the original invocation. Recovery consumes an
orphan as `uncertain` and can repair an interrupted fence clear for a
verified completed receipt. It starts no work.

```sh
ladyshell execution recover --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --id check-001
```

For an uncertain dispatch with a retained state fence, independently stop
the exact original runtime through authorized host controls. Record the reason
and the receiver checks the stopped generation before retaining evidence and
clearing the fence. Reconciliation preserves the original uncertainty. Runtime
lifecycle actions stay under independent operator control.

```sh
ladyshell execution reconcile --receiver "$RECEIVER" --receiver-id "$RECEIVER_ID" \
  --scope project-checks --id check-001 --reason "Original workload stopped by operator"
```

Use `ladyshell help execution COMMAND` for details. Help runs without
configuration, credentials or state.

## External lo-tasks provider

An external `lo_tasks::domain_task::Provider` can use the native host API or
run the CLI under the same trusted local boundary. Pin its reviewed adapter
revision, expected target, receiver identity and capability profile in
`Binding`. Map the original `(target, task)` to a stable scope and retain
the original intent ID separately from the installed catalogue task. Serialize
the complete typed original `Invocation` as `intent`, including any composition
and the full context in `arguments`. LO serialization may omit absent composition
and empty dependencies. Forbid a changed binding on reconnect.

`validate_task` and effect-free `preflight_dispatch` check the installed
operation and argument mapping. The adapter selects the exact catalogue task
and definition digest and rejects unsupported parameters. The initial mapping
uses the installed argv as-is. Use `DispatchMode::Inline` for local admission
and reject unadmitted dispatch calls. In `dispatch_admitted`, take authority
from the borrowed `DispatchPermit`, reject nonzero artificial delay and require
its exclusive deadline on the shared Unix-second timebase. Use a fresh trusted
clock at receiver admission and reject regressed time. Implement `bind_owner` and
`advance_fence_admitted` as authenticated host administration. Pass the
permit's original owner generation and exact claim epoch independently at
dispatch. Hex-encode LO's typed task and deployment byte arrays and incarnation
bytes to the neutral Lady owner fields, retaining its epoch. The wire formats
differ. A zero claim acknowledges initialization only.

`observe` compares the complete original invocation in retained history.
Return `Pending` for accepted or dispatching work with affirmative supervisor
presence. Map a verified completed record to `Confirmed(Box<Receipt>)` when
the reviewed operation promises OpenShell client completion. An operation
that promises a business postcondition requires separate evidence before
confirmation. Preserve the full original invocation, `version: None` and
compact `detail` with provenance, result, receiver identity, definition and
invocation digests, and stream references with lengths and hashes. Respect
the configured receipt capacity and keep raw logs in the receiver.
`version()` returns `None`, with no expected version or dependency versions
for this profile.
Map missing, unreadable, refused or uncertain history and lost replies to
`Unknown` or an error. `NotApplied` requires a permanent exclusion guarantee
outside this profile.

Advertise durable receipt lookup, asynchronous completion and serialized
isolation. Keep conditional mutation, cancellation and non-application
unsupported and leave advertised idempotency unset for the initial profile.
Use `RejectStale` fencing only with implemented native owner and claim checks
and authenticated advancement. Set `max_retries = 0` and configure one to
eight observation polls with backoff. The journal limits managed dispatch to
one launch of an invocation. OpenShell effects happen outside the journal
transaction, so business CAS and exactly-once effects are outside its guarantee.
Keep OpenShell I/O outside the LO `effects::Store` handler.

This mapping was reviewed against the actual `lo-tasks` Provider source.
The neutral receiver tests use synthetic native subprocess fixtures. A compiled
LO adapter and live deployment still require independent qualification.
