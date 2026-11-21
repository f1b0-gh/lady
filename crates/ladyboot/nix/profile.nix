# Independently validate direct Nix callers before package selection or assembly.
{ lib, profile }:
let
  exact = value: names: builtins.isAttrs value
    && builtins.attrNames value == lib.sort builtins.lessThan names;
  integer = low: high: value: builtins.isInt value && value >= low && value <= high;
  matches = regex: value: builtins.isString value && builtins.match regex value != null;
  unique = values: builtins.isList values && builtins.length values <= 64
    && builtins.length (lib.unique values) == builtins.length values;
  unicast = value:
    matches "(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}" value
    && (let parts = map builtins.fromJSON (lib.splitString "." value);
        first = builtins.head parts;
      in lib.all (n: n <= 255) parts && first > 0 && first < 224 && first != 127);
  addresses = values: unique values && values != [] && lib.all unicast values;
  serverName = value: builtins.isString value && builtins.stringLength value <= 253
    && matches "([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?" value;
  ntsSources = values: unique values && values != []
    && lib.all (s: exact s [ "server" "address" ] && serverName s.server && unicast s.address) values
    && unique (map (s: s.server) values) && unique (map (s: s.address) values);
  flow = minimum: value: exact value [ "address" "protocol" "port" ]
    && unicast value.address && builtins.elem value.protocol [ "tcp" "udp" ]
    && integer minimum 65535 value.port;
  flows = minimum: values: unique values && lib.all (flow minimum) values;
  podman = p: exact p [ "user" "uid" "gid" "subuid_start" "subgid_start" "range_size" ]
    && matches "[a-z][a-z0-9_-]{0,31}" p.user && p.user != "root"
    && integer 1000 60000 p.uid && integer 1000 60000 p.gid
    && integer 1 65536 p.range_size
    && integer 65536 (4294967295 - p.range_size) p.subuid_start
    && integer 65536 (4294967295 - p.range_size) p.subgid_start;
  network = n: exact n [ "interface" "dns" "nts" "egress" "ingress" ]
    && matches "[A-Za-z][A-Za-z0-9_.-]{0,14}" n.interface && n.interface != "lo"
    && addresses n.dns && ntsSources n.nts && flows 1 n.egress && flows 1024 n.ingress
    && lib.all (f: !((f.protocol == "udp" && f.port == 123) || (f.protocol == "tcp" && f.port == 4460))
      || builtins.elem f.address (map (s: s.address) n.nts)) n.egress;
  known = [ "bootc-base" "virtio-vm" "qemu-agent" "network-dhcp" "diagnostics"
    "offline" "podman-rootless" "podman-debug" "network-runtime" ];
  has = need: builtins.elem need profile.needs;
  valid = exact profile ([ "architecture" "needs" "os_id" "revision" "schema_version" ]
      ++ lib.optional (profile ? podman) "podman" ++ lib.optional (profile ? network) "network")
    && profile.schema_version == 1 && profile.architecture == "x86_64-linux"
    && matches "[a-z][a-z0-9-]{0,31}" profile.os_id && matches "[0-9]{1,12}" profile.revision
    && unique profile.needs && builtins.length profile.needs <= 16
    && lib.all (need: builtins.elem need known) profile.needs
    && has "bootc-base" && (!(has "qemu-agent") || has "virtio-vm")
    && !(has "offline" && (has "network-dhcp" || has "network-runtime"))
    && !(has "network-dhcp" && has "network-runtime")
    && (!(has "podman-debug") || has "podman-rootless")
    && (has "podman-rootless" == (profile ? podman))
    && (has "network-runtime" == (profile ? network))
    && (!(has "podman-rootless") || podman profile.podman)
    && (!(has "network-runtime") || network profile.network)
    && (!(has "network-runtime" && has "podman-rootless") || profile.podman.user != "ntpd-rs");
in assert lib.assertMsg valid "Invalid bootc needs, rootless identity or explicit network policy";
profile
