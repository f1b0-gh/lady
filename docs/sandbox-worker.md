# Sandbox worker contract, version 1

The `openshell-worker-v1` profile runs an explicitly selected native worker in a
fixed OpenShell environment. Ladyshell has no dependency on an application
framework, task schema, WASI engine or scheduler. The worker may implement these;
the embedding host owns application policy and validates application results.

## Selection and authority

`BrokerDesired.worker` selects an ELF whose digest is retained in the environment
lock under `worker`. The image installs it at `/usr/local/bin/sandbox-worker`.
The selected resources, source snapshot, image, effective policy, runtime identity
and mounted caps remain part of the ordinary Ladyshell checks. Requests cannot
select executable paths, change mounts, add permissions or substitute a worker.

A host must independently admit provisioning, execution, observation and cleanup.
Neither a successful transport nor a matching reply is authorization. Workers
receive no host credentials, Docker socket or Nix daemon. Network is disabled;
Landlock and the original capped storage mounts remain mandatory.

## Fixed entries

Every entry receives three fixed root arguments, in order:
`/var/lib/ladyshell/broker/control`, `/var/lib/ladyshell/broker/artifacts`, and
`/var/lib/ladyshell/broker/incoming`. No request supplies these paths.

| Entry | Standard input | Standard output |
| --- | --- | --- |
| `sandbox-control` | Control JSON below, at most 16 KiB | Exact control reply, at most 16 KiB |
| `sandbox-upload` | Raw bytes, 1 byte to 2 MiB; one additional argv is their lowercase SHA-256 | `{"Ok":{"component":"<sha256>","bytes":123}}` |
| `sandbox-execute` | Opaque application JSON, at most 16 KiB | Opaque application reply, at most 16 KiB |
| `sandbox-observe` | The original retained application JSON, at most 16 KiB | Opaque historical evidence, at most 16 KiB |

Nonzero exit, timeout, truncated streams or invalid control/upload correlation
leave the operation unresolved. There is no automatic retry or alternate entry.
Upload creates `incoming/<sha256>.wasm` once, without replacing existing complete
or partial bytes. The suffix is a storage convention, not format validation;
application admission and installation are separate operations.

Control messages are independent of application messages:

```json
{"format":1,"action":"probe"}
{"format":1,"action":"initialize","token":"<64 lowercase hex characters>"}
{"format":1,"action":"seal","token":"<64 lowercase hex characters>"}
```

The exact probe reply is `{"format":1,"protocol":"ladyshell-worker-v1"}`.
Initialization and sealing reply with exactly `format`, the original `token`, and
`accepting`: true for an initialized open generation, false for a sealed one.
Unknown fields, versions and actions must be refused. A token correlates an
operation; it is not a permission or proof of application termination.

## Storage and sealing obligations

The approved worker must take a shared, nonblocking `flock` on a newly opened
control-directory descriptor for the entire duration of every mutation. It must
check that `control/.lifecycle/open` is a directory while holding that lock.
Initialization and sealing take the exclusive lock. A busy seal fails; it must
not acknowledge success while writers remain.

Initialization requires an empty control root before creating `.lifecycle` and
its `open` subdirectory. An existing `.lifecycle` without `open` is permanently
sealed, including after interrupted initialization. Never recreate the marker.
Seal removes the empty `open` directory and synchronizes `.lifecycle` and control;
removal requires no new data blocks or inodes. Repeated seal can finish an
interrupted durability acknowledgement. Initialization of a sealed generation
reports `accepting:false` and cannot authorize new execution.

The exporter independently takes the exclusive control lock, checks that the
open marker is absent, and verifies the bounded archive. Original runtime,
source, policy, volume and journal checks remain required before deletion.

These are obligations of an approved worker, not enforcement against a malicious
worker. `flock` is advisory; Landlock and filesystem quotas enforce different
boundaries. A protocol reply alone cannot prove permanent quiescence. Stronger
claims require separate host-enforced stopping or read-only storage. The contract
does not grant generic task termination, refund or retirement guarantees.

## Recovery

`execution::observe_broker(store, key)` is available only for the original
uncertain receiver and matching execution fence. Its original task must use the
fixed `sandbox-execute` argv and bounded intent channel. The task identifier and
application JSON have no special meaning to Ladyshell.

Ladyshell forwards that exact retained intent to `sandbox-observe`; the caller
cannot supply a new query, digest or command. The approved adapter must derive
its read-only lookup from the original message and refuse unsupported operation
kinds. It must never run the original execution as a fallback. The host validates
returned application evidence under its current policy. Receiver uncertainty,
the original fence and application accounting remain unchanged.

## Implementations and compatibility

`examples/sandbox_worker.rs` is an independent fixture that echoes JSON and
retains its result. It implements no task framework or WASI engine. Build with
`cargo build --example sandbox_worker`; select the resulting ELF explicitly in
the native qualification commands in [bounded storage](broker-storage.md).
Production workers require their own review and qualification against this
contract, including failed/partial writes and read-only recovery.

The previous experimental `openshell-wasi` profile used an application-specific
protocol. It is not silently migrated. Keep its original binary and resources
for recovery; deploy version 1 into a new environment with a new lock and approval.
Native Codex profiles retain their separate existing behavior.
