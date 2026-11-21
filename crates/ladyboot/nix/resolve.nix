# Public needs are resolved only against this pinned nixpkgs catalogue.
{ pkgs, profile }:
let
  inherit (pkgs) lib;
  checked = import ./profile.nix { inherit lib profile; };
  has = need: builtins.elem need checked.needs;
  podman = has "podman-rootless";
  runtime = import ./runtime.nix { inherit pkgs; debug = has "podman-debug"; };
  runtimeNetwork = has "network-runtime";
  # Reuse a single pinned systemd output; daemon activation is strictly optional.
  # Its compiled network capabilities are reported separately from enabled services.
  systemd = pkgs.systemdMinimal.override {
    withNetworkd = true; withResolved = runtimeNetwork; withTimesyncd = false;
    withPam = podman; withLogind = podman;
    withSysusers = true; withAcl = true; withAudit = true; withLibseccomp = true;
  };
  hostInit = pkgs.runCommand "ladyboot-podman-init-1" {
    nativeBuildInputs = [ pkgs.rustc pkgs.stdenv.cc ];
  } ''
    rustc --edition 2021 --test ${./host-init.rs} -o tests
    ./tests
    mkdir -p "$out/bin"
    rustc --edition 2021 -C opt-level=s -C strip=symbols ${./host-init.rs} -o "$out/bin/ladyboot-podman-init"
  '';
  security = import ./container-security.nix { inherit pkgs; };
  catalog = {
    inherit (security) skopeo criu;
    ntpd-rs = import ./ntpd-rs.nix { inherit pkgs; };
    bootc = pkgs.bootc; inherit systemd; busybox = pkgs.busybox;
    ostree = pkgs.ostree; kmod = pkgs.kmod; ca-certificates = pkgs.cacert;
    nftables = pkgs.nftables; iproute2 = pkgs.iproute2; ethtool = pkgs.ethtool;
    qemu-agent = pkgs.qemu_kvm.ga;
    inherit (runtime) podman crun;
    inherit (pkgs) conmon passt dbus shadow;
    util-linux = pkgs.util-linux;
    podman-init = hostInit;
    bootupd = import ./bootupd.nix { inherit pkgs; };
    uefi-assets = import ./uefi.nix { inherit pkgs; };
    grub = pkgs.grub2_efi;
    e2fsprogs = pkgs.e2fsprogs;
    inherit (pkgs) dosfstools efibootmgr coreutils;
  };
  roles = {
    bootc-base = { packages = [ "bootc" "skopeo" "systemd" "busybox" "ostree" "kmod" "ca-certificates" ]; reason = "Bootable system, immutable deployments, module loading and TLS trust"; };
    virtio-vm = { packages = []; reason = "Virtio storage, console, network and entropy hardware support"; };
    qemu-agent = { packages = [ "qemu-agent" ]; reason = "Explicit hypervisor management channel"; };
    network-dhcp = { packages = [ "nftables" ]; reason = "DHCPv4 addressing with a default-deny packet policy"; };
    diagnostics = { packages = [ "iproute2" "ethtool" ]; reason = "Local network inspection commands; no services or network permissions"; };
    podman-rootless = { packages = [ "podman" "crun" "conmon" "passt" "dbus" "shadow" "util-linux" "podman-init" "bootupd" "uefi-assets" "grub" "e2fsprogs" "dosfstools" "efibootmgr" "coreutils" ]; reason = "Rootless runtime, user identity and UEFI bootc disk installation tools"; };
    network-runtime = { packages = [ "nftables" "ntpd-rs" ]; reason = "Explicit IPv4 site policy, DNS and authenticated NTS time"; };
    podman-debug = { packages = [ "criu" ]; reason = "Explicit checkpoint/restore tooling; debug runtime retains upstream optional capabilities"; };
    offline = { packages = []; reason = "Require absence of network activation roles"; };
  };
  names = lib.unique (lib.concatMap (need: roles.${need}.packages) profile.needs);
  origins = name: map (need: { origin = need; reason = roles.${need}.reason; })
    (builtins.filter (need: builtins.elem name roles.${need}.packages) profile.needs);
  package = name: let p = catalog.${name}; in {
    selection = name; nix_name = lib.getName p; version = lib.getVersion p;
    store_path = toString p; origins = origins name;
  } // lib.optionalAttrs (name == "coreutils") { commands = [ "cp" ]; }
    // lib.optionalAttrs (name == "ntpd-rs") { commands = [ "ntp-daemon" "ntp-ctl" ]; }
    // lib.optionalAttrs (name == "shadow") { commands = [ "newuidmap" "newgidmap" ]; }
    // lib.optionalAttrs (name == "util-linux") {
      commands = [ "agetty" "mount" "umount" "findmnt" "lsblk" "blkid" "setpriv" "findfs" "sfdisk" "swapon" "swapoff" "fstrim" "losetup" "wipefs" "nsenter" "fsfreeze" ];
  } // lib.optionalAttrs (name == "grub") { commands = [ "grub-editenv" ]; }
    // lib.optionalAttrs (name == "e2fsprogs") { commands = [ "mkfs.ext4" "fsck.ext4" "chattr" "lsattr" ]; }
    // lib.optionalAttrs (name == "dosfstools") { commands = [ "mkfs.fat" "fsck.fat" ]; };
  kernel = pkgs.linuxPackages_6_12.kernel;
  kernelModules = [ "ext4" "overlay" "erofs" "autofs4" "binfmt_misc" "configfs" "fuse" ]
    ++ lib.optionals (has "virtio-vm") [ "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "virtio_net" "virtio_balloon" "virtio_console" "virtio_rng" ]
    ++ lib.optionals podman [ "tun" "vfat" "nls_cp437" "nls_iso8859-1" "efivarfs" ]
    ++ lib.optionals (has "network-dhcp" || runtimeNetwork) [ "af_packet" "nf_tables" "nf_conntrack" "nft_ct" ];
  service = name: origin: reason: { inherit name origin reason; };
  vendorLinks = import ./systemd-units.nix ++ lib.optionals podman [
    "multi-user.target.wants/systemd-logind.service"
    "multi-user.target.wants/systemd-user-sessions.service"
    "sockets.target.wants/systemd-logind-varlink.socket"
  ];
  vendorServices = map (link: {
    name = builtins.baseNameOf link;
    enabled_by = builtins.head (lib.splitString ".wants/" link);
    origin = "bootc-base";
    source = "systemd-vendor";
    reason = "Pinned systemd core unit link; activation depends on the owning target and unit conditions";
  }) (builtins.filter (lib.hasSuffix ".service") vendorLinks);
  services = [ (service "ostree-remount.service" "bootc-base" "Prepare deployment writable state") ]
    ++ lib.optionals (has "network-dhcp") [
      (service "ladyboot-firewall.service" "network-dhcp" "Load deny policy before interface activation")
      (service "systemd-networkd.service" "network-dhcp" "Explicit DHCPv4 link configuration")
    ] ++ lib.optionals runtimeNetwork [
      (service "ladyboot-firewall.service" "network-runtime" "Apply explicit site policy before network activation")
      (service "systemd-networkd.service" "network-runtime" "Activate selected DHCPv4 link")
      (service "systemd-resolved.service" "network-runtime" "Explicit resolvers without fallback")
      (service "ntpd-rs.service" "network-runtime" "Authenticated NTS sources without fallback")
      (service "ladyboot-network-online.service" "network-runtime" "Bounded IPv4 readiness required by network-online.target")
    ] ++ lib.optionals podman [
      (service "ladyboot-podman-init.service" "podman-rootless" "Verify identity without adopting state")
      (service "systemd-logind.service" "podman-rootless" "Maintain rootless user sessions")
      (service "user@${toString profile.podman.uid}.service" "podman-rootless" "Persistent service user manager without interactive login")
    ] ++ lib.optionals (has "qemu-agent") [(service "qemu-guest-agent.service" "qemu-agent" "Serve the explicitly selected virtio guest channel")];
  override = winner: reason: { inherit winner reason; origin = "bootc-base"; };
  commandOverrides = lib.genAttrs [ "depmod" "insmod" "lsmod" "modinfo" "modprobe" "rmmod" ]
    (_: override "kmod" "Use the module loader matched to the module assembly")
    // lib.genAttrs [ "init" "halt" "poweroff" "reboot" "systemctl" "loginctl" "hostnamectl" "journalctl" ]
    (_: override "systemd" "Use systemd PID1 management semantics")
    // lib.optionalAttrs (has "diagnostics") (lib.genAttrs [ "ip" "tc" ]
      (_: { winner = "iproute2"; reason = "Explicit diagnostics role requests the full iproute2 implementation"; origin = "diagnostics"; }));
  podmanOverrides = lib.genAttrs [ "mount" "umount" "findmnt" "lsblk" "blkid" "setpriv" "findfs" "sfdisk" "swapon" "swapoff" "fstrim" "losetup" "wipefs" "nsenter" "fsfreeze" ]
    (_: { winner = "util-linux"; reason = "Explicit runtime and bootc mount/block-device semantics"; origin = "podman-rootless"; });
  filesystemOverrides = lib.genAttrs [ "chattr" "lsattr" ]
    (_: { winner = "e2fsprogs"; reason = "bootc requires ext4 attributes support"; origin = "podman-rootless"; });
  plan = {
    schema_version = 1;
    requested = profile;
    source = { nixpkgs_revision = "1c89083e451e891152365b799595cf7790a43325"; nickel_version = "1.18.0"; };
    runtime_packages = map package names;
    kernel = { nix_name = lib.getName kernel; version = kernel.version; store_path = toString kernel; origin = "bootc-base"; reason = "Pinned LTS boot kernel"; };
    kernel_modules = map (name: { inherit name; origin = if builtins.elem name [ "af_packet" "nf_tables" "nf_conntrack" "nft_ct" ] then (if runtimeNetwork then "network-runtime" else "network-dhcp") else if builtins.elem name [ "tun" "vfat" "nls_cp437" "nls_iso8859-1" "efivarfs" ] then "podman-rootless" else if lib.hasPrefix "virtio" name || name == "sd_mod" then "virtio-vm" else "bootc-base"; }) kernelModules;
    enabled_services = vendorServices ++ services;
    enabled_targets = lib.optionals podman [ {
      name = "network-online.target"; origin = "podman-rootless";
      reason = "System readiness target observed by the pinned Quadlet user wait unit";
    } ];
    vendor_unit_links = map (link: {
      path = "usr/lib/systemd/system/" + link;
      origin = "bootc-base";
      reason = "Pinned systemd vendor enablement; verified against delivered links";
    }) vendorLinks;
    generator_aliases = [ {
      path = "etc/systemd/system-generators/ostree-system-generator";
      target = "/usr/lib/systemd/system-generators/ostree-system-generator";
      origin = "bootc-base";
      reason = "Reach the delivered OSTree generator through pinned systemd search paths";
    } ] ++ lib.optionals podman [ {
      path = "etc/systemd/user-generators/podman-user-generator";
      target = "/usr/lib/systemd/user-generators/podman-user-generator";
      origin = "podman-rootless";
      reason = "Reach the selected Quadlet generator without persisting its store hash in /etc";
    } ];
    service_observation = "Static enablement and installed unit files; running services require a boot observation";
    network = if runtimeNetwork then profile.network // {
      mode = "dhcp4"; policy = "default deny; explicit site IPv4 flows only";
      registry_endpoints = []; dns_fallback = []; nts_fallback = [];
    } else { mode = if has "network-dhcp" then "dhcp4" else "unconfigured";
      interface = if has "network-dhcp" then "en*" else null;
      allowed_ports = lib.optionals (has "network-dhcp") [{ protocol = "udp"; local = 68; remote = 67; origin = "network-dhcp"; reason = "DHCPv4 discovery and lease renewal only"; }];
      dns = []; nts = []; registry_endpoints = [];
      policy = if has "network-dhcp" then "drop input/output/forward except loopback and DHCPv4" else "no network activation configured; no firewall claim";
    };
    persistence = [ { path = "/etc"; origin = "bootc-base"; reason = "bootc managed configuration"; } { path = "/var"; origin = "bootc-base"; reason = "Persistent operating-system state"; } ];
    command_overrides = commandOverrides // lib.optionalAttrs podman (podmanOverrides // filesystemOverrides // {
      cp = { winner = "coreutils"; origin = "podman-rootless";
        reason = "bootupd -rp must copy OSTree-deduplicated EFI files without preserving hardlinks on FAT"; };
    });
    build_tools = let tool = p: phase: reason: {
      nix_name = lib.getName p; version = lib.getVersion p; inherit phase reason;
    }; in [
      (tool pkgs.nickel "configuration" "Evaluate the public needs contract")
      (tool pkgs.python3Minimal "assembly" "Check command ownership and record/verify delivered filesystem files")
      (tool pkgs.python3 "artifact-verification" "Read and verify compressed image archives; compression modules required")
      (tool pkgs.zstd "initramfs" "Compress the initramfs")
      (tool pkgs.cpio "initramfs" "Package the initramfs archive")
    ];
    host_requirements = [ "Host-supplied Nix executable with flakes; its version is not the nixpkgs Nix package version" "Rust CLI built from the Lady workspace" ];
    expected_outputs = [ "rootfs" "bootc-image" "kernel" "initramfs" "module-tree" "delivered-file-manifest" ];
    measurements = { status = "unrealized"; image_bytes = null; closure_bytes = null; };
    observations = null;
    runtime_variant = if podman then (if has "podman-debug" then "debug" else "minimal") else null;
    capabilities = { systemd_networkd_compiled = true; networkd_enabled = has "network-dhcp" || runtimeNetwork; rootless_podman = podman; boot_install_update_rollback_qualified = false; };
  };
in builtins.seq checked
{ inherit plan kernel kernelModules systemd catalog has; selected = map (name: catalog.${name}) names; }
