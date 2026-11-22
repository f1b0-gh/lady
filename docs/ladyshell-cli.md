# Ladyshell CLI

Prepare explicitly authorized OpenShell environments, run tasks, and retain
their state and evidence. A dependency report grants no execution or network
permissions. Execution requires verified identity and effective confinement.

```sh
cargo install ladyshell-cli --version 0.1.0 --locked
ladyshell --help
audit-validator --version
```

This installs `ladyshell` and `audit-validator`. Native tools, provider setup,
and trusted Nickel/Nix resources are separate prerequisites. Acquire resources
from the matching
[`ladyshell-v0.1.0` source](https://github.com/f1b0-gh/lady/tree/ladyshell-v0.1.0)
and supply the resource directory explicitly; installation does not initialize
credentials or launch a sandbox.

Follow the [first-run guide](https://github.com/f1b0-gh/lady/blob/ladyshell-v0.1.0/docs/usage.md#first-run)
and [command reference](https://github.com/f1b0-gh/lady/blob/ladyshell-v0.1.0/docs/usage.md).
The Rust API is provided by the separate `ladyshell` crate.

The complete CLI integration suite uses the versioned repository's recipes and
workspace sources. The archive gate separately builds both installed binaries
and tests the portable validator interface outside the checkout.

Lady code is Apache-2.0 licensed. The bundled audit validator and imported audit
materials retain their MIT license and copyright notices.
