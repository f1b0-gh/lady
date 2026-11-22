# Ladyshell library

Ladyshell prepares authorized OpenShell environments, verifies source and runtime
identity, and retains execution state and audit evidence. Imported Ladybom reports
grant no permissions. Authorization, provider checks and mandatory confinement
remain separate from inventory and document validation.

```toml
[dependencies]
ladyshell = "=0.1.0"
```

For the `ladyshell` and `audit-validator` executables, install `ladyshell-cli`.
Native execution requires Linux, the explicitly prepared native tools and a
trusted Lady resource tree selected with `--resources`. The crate includes its
compile-time audit assets; it does not install or download a complete runtime
workspace, Nix recipes, provider configuration or credentials.

See the [usage guide](https://github.com/f1b0-gh/lady/blob/main/docs/usage.md),
[audit guide](https://github.com/f1b0-gh/lady/blob/main/docs/audits/usage.md) and
[development guide](https://github.com/f1b0-gh/lady/blob/main/docs/development.md).

Lady's own code uses [Apache-2.0](LICENSE). The imported
[audit validator](src/audit/validator/LICENSE-MIT) and
[audit methods](resources/audit/security-audit/LICENSE) retain their MIT notices.
[Provenance](resources/audit/provenance.json) records their sources and adaptations.
