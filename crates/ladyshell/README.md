# Ladyshell library

Ladyshell prepares authorized OpenShell environments, verifies source and runtime
identity, and retains execution state and audit evidence. Imported Ladybom reports
grant no permissions. Authorization, provider checks and mandatory confinement
remain separate from inventory and document validation.

```toml
[dependencies]
ladyshell = "=0.2.0"
```

For the `ladyshell` and `audit-validator` executables, install `ladyshell-cli`.
Native execution requires Linux, the explicitly prepared native tools and a
trusted Lady resource tree selected with `--resources`. The crate includes its
compile-time audit assets; it does not install or download a complete runtime
workspace, Nix recipes, provider configuration or credentials.

See the [usage guide](https://github.com/f1b0-gh/lady/blob/main/docs/usage.md),
[audit guide](https://github.com/f1b0-gh/lady/blob/main/docs/audits/usage.md) and
[development guide](https://github.com/f1b0-gh/lady/blob/main/docs/development.md).

For the optional bounded broker storage primitives and their current integration
limits, see [bounded storage](https://github.com/f1b0-gh/lady/blob/main/docs/broker-storage.md).

Embedding hosts can retain `state::Selection` before obtaining policy approval.
It binds the original state directory's device/inode and a record digest; it
grants no permission. `app::select_plan` selects a saved plan for
`app::apply_expected` or `app::apply_broker_expected`. The expected plan is checked
under the ordinary lifecycle locks before effects and retained in the operation
journal. Recovery cannot substitute another plan or attach an approval to an
older, unbound journal. Reopening the same completed approved operation verifies
its original result and runtime; it does not create another sandbox.

`state::select_generation` selects an existing environment for
`execution::install_pinned` or `destroy::run_pinned`. It binds every state field
except `last_sync`, which records export progress. A new sandbox, policy, source
configuration, storage binding, continuous session or replacement directory is
refused. `destroy::select_cancellation` and `destroy::cancel_broker_pinned` bind
cancellation to the exact original incomplete broker provisioning record.
These checks supplement fresh runtime verification and the embedding host's
policy admission. Native and broker deployments use the same selection type.

An orphaned fixed-broker invocation can retain an execution fence while its
result survives remotely. After explicit `execution::recover`, the separately
admitted `execution::observe_broker` retrieves opaque observation bytes for the embedding host
to verify. `destroy::run_recovering` seals and exports before deleting the exact
fenced generation, including interrupted nonexecution invocations. Both preserve
the original uncertainty and fence; neither grants worker execution or application
retirement. See the bounded-storage guide for the caller's policy obligations.

Lady's own code uses [Apache-2.0](LICENSE). The imported
[audit validator](src/audit/validator/LICENSE-MIT) and
[audit methods](resources/audit/security-audit/LICENSE) retain their MIT notices.
[Provenance](resources/audit/provenance.json) records their sources and adaptations.

The optional sandbox profile uses the provider-neutral [worker contract](https://github.com/f1b0-gh/lady/blob/main/docs/sandbox-worker.md). Application adapters live outside Ladyshell; no application-specific executable or task schema is required.
