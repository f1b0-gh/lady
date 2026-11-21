# Ladyboot

Build and inspect bootable bootc operating-system images from explicit profiles.
Nickel describes needs; Nix selects pinned packages and assembles the system;
Rust validates inputs, explains selections and verifies artifact receipts.
Ladyboot does not deploy instances or manage OpenShell sandboxes.

It is a library and optional CLI in the Lady workspace. Use
`default-features = false` to consume it without Clap. The shared
`nickel-util =0.1.0` source is bundled under `vendor/nickel-util`; no sibling
checkout is required. See [development](../../docs/development.md).

## Profiles and needs

| Profile | Purpose |
| --- | --- |
| `profiles/base.ncl` | Hardware-independent bootc baseline |
| `profiles/virtio.ncl` | Baseline with supported virtual-machine devices |
| `profiles/network-vm.ncl` | DHCP VM, guest agent and diagnostics |
| `profiles/podman-vm.ncl` | Rootless Podman and explicit runtime-network policy |
| `profiles/podman-debug.ncl` | Same identity/policy with additional runtimes and diagnostics |

| Need | Selection |
| --- | --- |
| `bootc-base` | Required kernel, initramfs, bootc, OSTree, systemd, shell, modules and CA trust |
| `virtio-vm` | Virtio disk, network, console, entropy and balloon modules |
| `qemu-agent` | Explicit guest management channel; requires `virtio-vm` |
| `network-dhcp` | DHCPv4 on `en*`, default-deny firewall; no DNS/time/registry destinations |
| `diagnostics` | iproute2 and ethtool; no service or network grant |
| `offline` | Rejects composition with either network need |
| `podman-rootless` | Podman, crun, pasta, user sessions and persistent storage; explicit `podman` contract |
| `network-runtime` | Explicit IPv4 interface, DNS/NTS and ingress/egress; explicit `network` contract |
| `podman-debug` | Optional CRIU/libkrun/runc support; requires `podman-rootless` |

Unknown/duplicate needs, unsupported fields and conflicts fail. Arbitrary package
overrides are unsupported. Command collisions require an explicit catalogue
winner and reason. Recipes remain pinned to nixpkgs
`1c89083e451e891152365b799595cf7790a43325` and Nickel 1.18.0.
The Podman role selects GNU `cp` from already-delivered coreutils so bootupd can
copy OSTree-deduplicated EFI files onto FAT. Other BusyBox commands are unchanged.

Example endpoints are synthetic documentation addresses. Select real endpoints,
server identities and trust explicitly before deployment. Profiles do not create
SSH access, credentials, signing state, workloads or automatic updates. Compiled
service code or a permitted destination does not prove a service is active.

## Build and inspect

First follow the root build prerequisites, then from the Lady root:

```sh
python3 scripts/check_sources.py
cargo build -p ladyboot --locked
cargo run -p ladyboot --locked -- explain \
  --config "$PWD/crates/ladyboot/profiles/base.ncl" \
  --resources "$PWD/crates/ladyboot"
```

Native evaluation requires Nix and the confined Nickel evaluator. Resource
recipes are explicitly trusted inputs. Keep build outputs and receipts outside
the recipe source. From `crates/ladyboot`:

```sh
RECIPES="$PWD"
ARTIFACTS=$(mktemp -d)
cargo run -p ladyboot --locked -- diff \
  --config "$RECIPES/profiles/base.ncl" \
  --other "$RECIPES/profiles/network-vm.ncl" --resources "$RECIPES"
cargo run -p ladyboot --locked -- lock \
  --config "$RECIPES/profiles/virtio.ncl" --resources "$RECIPES" \
  --output "$ARTIFACTS/profile.lock.json"
cargo run -p ladyboot --locked -- plan \
  --config "$RECIPES/profiles/virtio.ncl" --resources "$RECIPES" \
  --lock "$ARTIFACTS/profile.lock.json"
cargo run -p ladyboot --locked -- build \
  --config "$RECIPES/profiles/virtio.ncl" --resources "$RECIPES" \
  --lock "$ARTIFACTS/profile.lock.json" --receipt "$ARTIFACTS/image.receipt.json"
cargo run -p ladyboot --locked -- inspect --receipt "$ARTIFACTS/image.receipt.json"
```

`check`, `render`, `lock`, `plan`, `explain` and `diff` do not build an OS image.
Nix explanation forbids import-from-derivation; Nickel evaluation is bounded and
network-isolated. `build --target` accepts `bootc-image`, `rootfs`, `kernel`,
`initrd`, `boot-test-rootfs` and `checks`. `test` realizes artifact checks.
Existing locks/receipts require explicit `--replace`; stale inputs fail.
None of these operations installs an OS.

Explanation separates requested needs, planned native versions/store identities,
services/network/persistence, and observed files. `explain --rootfs PATH` verifies
the complete rootfs inventory and agreement with the selected plan before reporting
observations. It does not invent PURLs, a complete SBOM or future compressed sizes.
Regular-file byte totals are distinct from OCI size and complete Nix closure size.

The rootfs stores runtime objects under `/usr/lib/nix/store`, reached through
`/nix`. Its assembly manifest covers regular files, directories, symlinks, kernel,
initramfs, modules and generated configuration. Only the manifest excludes itself;
its digest is in the receipt. The archive check compares final layer entries
against this inventory. Rust checks hashes with count/byte/time limits and rejects
unexpected paths. A store-reference graph alone is not a delivered-file inventory.

Receipts retain rootfs NAR and inventory digests. `inspect` checks local Nix
identities and all recorded rootfs bytes; it does not authenticate an external
author or rehash an OCI archive's NAR. A receipt is not a signed attestation or
proof of boot, installation, update or rollback.

## Direct Nix outputs and checks

From this crate directory:

```sh
nix --extra-experimental-features 'nix-command flakes' build \
  path:.#bootc-podman path:.#bootc-podman-debug --no-link \
  --no-update-lock-file --no-write-lock-file --max-jobs 1 --cores 2 --print-out-paths
nix --extra-experimental-features 'nix-command flakes' build \
  path:.#checks.x86_64-linux.podman-rootfs \
  path:.#checks.x86_64-linux.podman-debug-rootfs \
  path:.#checks.x86_64-linux.podman-image \
  path:.#checks.x86_64-linux.podman-debug-image \
  path:.#checks.x86_64-linux.profile --no-link \
  --no-update-lock-file --no-write-lock-file --max-jobs 1 --cores 2
cargo fmt --check -p ladyboot
cargo clippy -p ladyboot --all-targets --all-features --locked -- -D warnings
cargo test -p ladyboot --all-features --locked
```

The default flake consumes `profiles/base.json`; Podman outputs consume
`podman-vm.json` and `podman-debug.json`. Checks compare all three with Nickel.
After an intentional profile change, update JSON using `render --output PATH`
(and `--replace` for an existing file). The CLI instead uses freshly evaluated,
locked JSON. Cargo outputs stay in Lady's `target/`, outside the flake source.

Images are Docker-format archives. Rootfs outputs end in `-rootfs`; disposable
qualification overlays end in `-test-rootfs` and add test-only Python/smoke images.
Do not count those overlays as production OS size. `tests/boot.py`,
`tests/podman_vm.py`, `tests/network_vm.py` and `tests/bootc_lifecycle.py` retain
explicit qualification drivers; use their `--help` and new owned output folders.
They do not grant access to unrelated disks, deployment credentials or state.

## Runtime and network boundaries

Minimal Podman disables crun CRIU/libkrun support and extra Podman runtimes,
removing CRIU/Python, libkrun/libkrunfw and runc branches. Debug retains these
optional capabilities. Seccomp, capabilities, namespaces and systemd cgroups
remain. This uses upstream build options, not a source fork or post-build deletion.
Both variants share accounts, subordinate IDs, persistent paths and network policy.

Rootless pasta opens host sockets; host input/output policy governs its traffic.
The [network matrix](network-flows.md) documents actual flow grants and current
qualification limits. Firewall updates replace only the `inet ladyboot` table
atomically. Existing established/related sessions can outlive grant revocation;
new-connection checks are separate. Networkd requires firewall loading first.
Network readiness uses a bounded interface wait; Quadlet ordering is not a strict
prohibition on starting workloads while networking or time synchronization fails.

The production image enables no application Quadlet. The NIC-less test explicitly
opts out of its network dependency and uses a service drop-in for cleanup by
container ID. Its collision-preservation result does not qualify unmodified
upstream name-based cleanup. Stable generator aliases under
`/etc/systemd/{system,user}-generators` target `/usr/lib`; local overrides across
bootc updates still need lifecycle qualification.

## Authenticated time

`network-runtime` requires `nts = [{ server = "nts.test", address = "192.0.2.1" }]`;
the old `ntp` field is rejected. Sources have unique explicit DNS identities and
IPv4 addresses. Hosts entries bind those identities. ntpd-rs uses NTS only, with
SRV discovery disabled, normal TLS validation and an explicit CA bundle.
`SSL_CERT_DIR` is unset. The native client pins each negotiated endpoint to its
expected IP:123; the firewall permits TCP/4460 and UDP/123 only for declared NTS
addresses. Generic egress cannot reopen these pairs elsewhere.

One authenticated source suffices. Corrections are bounded to 1,800 seconds;
initial certificate validation requires a sufficiently accurate RTC. Threshold
failure needs administrator intervention, not a restart loop. Workload startup
is not gated on synchronized time. Valid cookies may support authenticated time
during a key-exchange outage; they are not an unauthenticated fallback.

The dynamic service user has only CAP_SYS_TIME and a private observation socket.
No time-server or metrics service is activated. Timesyncd is compiled out/masked.
Bootc preserves local `/etc`: explicitly reconcile old units, drop-ins and time
configuration before an upgrade. No historical state is silently adopted/deleted.

## Qualification and provenance

The [dated network matrix](network-flows.md) records isolated NTS and both Podman
variant qualifications. These are historical observations, not a rerun by this
source publication. Full bootc installation, UEFI lifecycle/update/rollback,
Secure Boot and Proxmox qualification remain separate pending work. Unsigned
shim and pinned GRUB are not a Secure Boot claim.

Retained native source selections, locks, advisory scope and maintenance duties:

- [Container runtime corrections](nix/container-security.md)
- [bootupd build provenance](nix/bootupd-dependencies.md)
- [ntpd-rs lock and endpoint policy](nix/ntpd-rs-dependencies.md)
- [Public synthetic TLS fixtures](tests/fixtures/network/README.md)

Historical raw results/PDFs referenced there are not bundled release evidence.
Source/fixture checks do not establish a fresh whole-image security clearance.
[Development rules](AGENTS.md) preserve the component and confinement boundaries.
