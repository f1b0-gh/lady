# Ladyboot rules

Follow the root [contributor rules](../../AGENTS.md) and read [README.md](README.md)
before changing profiles or recipes.

- Own bootable bootc OS artifacts only: no instance orchestration, deployment
  adapters or application-container profiles.
- Nickel defines needs; Nix pins and assembles packages; Rust validates, explains
  and verifies artifacts. Keep Clap optional and nickel-util the only shared
  project dependency.
- Preserve nixpkgs `1c89083e451e891152365b799595cf7790a43325` and Nickel 1.18.0
  unless an explicit dependency review authorizes changing them.
- Never silently add services, package roots, network permissions or command
  replacements. Explain provenance. Inventory delivered files, kernel, initramfs,
  modules and generated units, not just Nix store references.
- Build from the workspace; keep outputs outside this crate's flake source.
  Bound native build concurrency and verify Nickel/Nix behavior when available.
- Record artifact layout, direct-kernel boot and bootc installation/update/rollback
  qualification separately. Do not claim unrun lifecycle tests passed.
