# Audit document validation

This internal module implements `ladyshell::audit::validator`. It validates
JSON findings and coverage documents with bounded input handling. It is part
of Ladyshell and has no separate Cargo package or release.

Use the main CLI:

```sh
cargo run -p ladyshell-cli --locked -- audit validate findings /path/to/findings.json
cargo run -p ladyshell-cli --locked -- audit validate coverage /path/to/coverage.json
```

The `audit-validator` compatibility binary is also built by `ladyshell-cli`.
It preserves the original output and exit codes:

```sh
cargo run -p ladyshell-cli --bin audit-validator --locked -- findings /path/to/findings.json
```

Acceptance checks document structure and consistency. It does not establish
that an audit is authentic, a finding is exploitable or reported checks ran.

## Imported code and license

The imported validator source, schema and fixture corpus retain the
[MIT license](LICENSE-MIT), copyright Cloudflare, Inc. The imported CLI at
`src/bin/audit-validator.rs` and its relocated tests carry explicit MIT headers
and use this same notice. This exception does not relicense Ladyshell or Lady;
the project's own code remains Apache-2.0.

[Provenance](../../../../../resources/audit/provenance.json) records original
source hashes, current paths and local adaptations. The standalone Cargo
manifest is recorded as retired; the validator's dependency requirements now
belong to Ladyshell. Existing parsing, limits and validation rules are retained.

[Audit workflow](../../../../../docs/audits/usage.md)
