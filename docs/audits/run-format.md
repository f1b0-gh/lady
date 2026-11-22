# Native audit run contract v1

The executable contract is in
[`model.rs`](../../crates/ladyshell/src/audit/model.rs) and
[`verify.rs`](../../crates/ladyshell/src/audit/verify.rs).
[`run-contract-v1.json`](../../crates/ladyshell/resources/audit/run-contract-v1.json) describes
metadata; Rust also checks file contents and cross-document relationships.

## Required files

| File | Contents |
| --- | --- |
| `run-metadata.json` | Identity, profile, status, scope, conditions, budget, invocations and links |
| `findings.json` | Upstream-validator findings array |
| `coverage-ledger.json` | Upstream-validator coverage array |
| `source-manifest.json` | `{schema_version: 1, files: [{path, size, sha256}]}` |
| `evidence-manifest.json` | `{schema_version: 1, artifacts: [{id, path, size, sha256, producer, command}]}` |

Metadata records a SHA-256 digest for each of the four other documents.
Source paths are normalized, relative and unique. The inventory binds their
contents without necessarily including those contents. Finding `trace[].file`
and `evidence[].file` references identify source files, not generated artifacts.

Artifacts reside under `agents/<producer>/artifacts/`; `producer` identifies a
declared invocation. `command` is an argument array, never an instruction to
execute during verification/export. Verification checks retained sizes/hashes.
Limits: 1,024 artifacts, 16 MiB per artifact, 64 MiB per loaded run, and 5 MiB
per document. Native parsing also bounds depth/cardinality and rejects duplicate
JSON keys. The runtime may impose tighter production/transport limits.

## Metadata

Required fields:

- `schema_version: 1`, `document_schema: "upstream-v1"`, and a safe `run_id`.
- `status`: planned, running, interrupted, blocked, failed, partial or complete.
- `profile`: quick or targeted; nonempty `scope_paths`.
- `config_sha256`, `toolchain_sha256`, `method_sha256`.
- `documents`: the four document names and their hashes.
- `budget: {invocations, seconds}` and `elapsed_seconds`.
- `invocations`: `{id, role, status}`, with role recon/hunter/verifier/critic
  and status finished/failed/interrupted.
- `links`: `{fingerprint, coverage_ids, artifact_ids, hunter_id, verifier_id}`.
- `open_obligations`, `environment_verified`, `cleanup_verified`.

Exceeded duration is publishable only for a non-complete state with open
obligations. Method provenance is retained in
[`provenance.json`](../../crates/ladyshell/resources/audit/provenance.json). The native controller
sets `method_sha256` to the selected bundle; external runs need not use the
locally installed bundle.

## Relationships and trust

Every finding has exactly one link. Its coverage units reference it in the
current attempt or retained attempts. Every candidate, including an archived
one, needs a disposition or explicit blockage.

Hunter and verifier identities are distinct, finished and have the expected
roles. A confirmation references verifier evidence. Local checks reference an
existing artifact owned by their producer. Hashes cannot establish that an
invocation actually occurred or that a third party's receipts are authentic.

`complete` requires coverage units, no open obligation/validation, finished
invocations, a final critic, and declared environment/cleanup verification.
Terminal `not_applicable` or `out_of_scope` explanations are not blockages.
Complete means the run's obligations ended; it does not mean exhaustive coverage
or absence of vulnerabilities.

Verification exposes `authenticity_verified: false` and `coverage_complete: false`.
Identities, conditions and commands remain declarations without independently
established execution trust. Never synthesize metadata to convert an old report
into proof of execution. See [usage](usage.md) for runtime and recovery limits.
