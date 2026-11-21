# Public OS data only. Package resolution belongs to the pinned Nix catalogue.
let between = fun low high => std.contract.from_predicate (fun n =>
  std.is_number n && n >= low && n <= high && std.number.floor n == n
) in
let bounded_unique = fun items =>
  std.array.length items <= 64 && std.array.all (fun item =>
    std.array.length (std.array.filter (fun other => other == item) items) == 1
  ) items
in
let Unicast = std.contract.from_predicate (fun address =>
  std.is_string address
  && std.string.is_match "^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$" address
  && (let parts = std.array.map std.string.to_number (std.string.split "." address) in
    std.array.all (fun n => n <= 255) parts
    && std.array.first parts > 0 && std.array.first parts < 224
    && std.array.first parts != 127)
) in
let Addresses = Array Unicast in
let ServerName = std.contract.from_predicate (fun name =>
  std.is_string name && std.string.length name <= 253
  && std.string.is_match "^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$" name
) in
let NtsSource = { server | ServerName, address | Unicast } in
let Flow = fun minimum => {
  address | Unicast,
  protocol | std.string.Matches "^(tcp|udp)$",
  port | between minimum 65535,
} in
let Shape = {
  schema_version | std.contract.Equal 1,
  architecture | std.contract.Equal "x86_64-linux",
  os_id | std.string.Matches "^[a-z][a-z0-9-]{0,31}$",
  revision | std.string.Matches "^[0-9]{1,12}$",
  needs | Array (std.string.Matches "^(bootc-base|virtio-vm|qemu-agent|network-dhcp|diagnostics|offline|podman-rootless|podman-debug|network-runtime)$"),
  podman | optional | {
    user | std.string.Matches "^[a-z][a-z0-9_-]{0,31}$",
    uid | between 1000 60000,
    gid | between 1000 60000,
    subuid_start | between 65536 4294967295,
    subgid_start | between 65536 4294967295,
    range_size | between 1 65536,
  },
  network | optional | {
    interface | std.string.Matches "^[A-Za-z][A-Za-z0-9_.-]{0,14}$",
    dns | Addresses,
    nts | Array NtsSource,
    egress | Array (Flow 1),
    ingress | Array (Flow 1024),
  },
} in
std.contract.custom (fun label input =>
  let value = std.contract.apply Shape label input in
  std.deep_seq value (
    let has = fun need => std.array.elem need value.needs in
    let valid =
      std.array.length value.needs <= 16 && bounded_unique value.needs
      && has "bootc-base"
      && (!(has "qemu-agent") || has "virtio-vm")
      && !(has "offline" && (has "network-dhcp" || has "network-runtime"))
      && !(has "network-dhcp" && has "network-runtime")
      && (!(has "podman-debug") || has "podman-rootless")
      && (has "podman-rootless" == std.record.has_field "podman" value)
      && (has "network-runtime" == std.record.has_field "network" value)
      && (if has "podman-rootless" then
        value.podman.user != "root"
        && (!(has "network-runtime") || value.podman.user != "ntpd-rs")
        && value.podman.subuid_start + value.podman.range_size <= 4294967295
        && value.podman.subgid_start + value.podman.range_size <= 4294967295
        else true)
      && (if has "network-runtime" then
        value.network.interface != "lo"
        && std.array.length value.network.dns > 0
        && std.array.length value.network.nts > 0
        && std.array.all bounded_unique [value.network.dns, value.network.nts,
          value.network.egress, value.network.ingress]
        && bounded_unique (std.array.map (fun source => source.server) value.network.nts)
        && bounded_unique (std.array.map (fun source => source.address) value.network.nts)
        && std.array.all (fun flow =>
          !((flow.protocol == "udp" && flow.port == 123) || (flow.protocol == "tcp" && flow.port == 4460))
          || std.array.elem flow.address (std.array.map (fun source => source.address) value.network.nts)
        ) value.network.egress
        else true)
    in if valid then 'Ok value
    else 'Error { message = "Invalid bootc needs, rootless identity or explicit network policy" }
  )
)
