{ pkgs, profile }:
let
  inherit (pkgs) lib;
  resolved = import ./resolve.nix { inherit pkgs profile; };
  inherit (resolved) kernel kernelModules systemd selected has plan;
  modules = pkgs.makeModulesClosure {
    kernel = lib.getOutput "modules" kernel;
    rootModules = kernelModules;
    firmware = pkgs.runCommand "ladyboot-empty-firmware" {} "mkdir -p $out/lib/firmware";
    allowMissing = false;
  };
  closure = pkgs.closureInfo { rootPaths = selected; };
  init = pkgs.writeScript "ladyboot-init" ''
    #!${pkgs.busybox}/bin/sh
    export PATH=${pkgs.busybox}/bin:${pkgs.kmod}/bin
    mkdir -p /proc /sys /dev /run /sysroot
    mount -t proc proc /proc
    mount -t sysfs sysfs /sys
    mount -t devtmpfs devtmpfs /dev
    mount -t tmpfs tmpfs /run
    fail() { echo "LADYBOOT_INIT_FAILED: $*" >/dev/console; exec sh; }
    for module in ${lib.escapeShellArgs kernelModules}; do
      ${pkgs.kmod}/bin/modprobe -d /modules "$module" || fail "module $module"
    done
    rootdev=
    ostree_boot=
    for arg in $(cat /proc/cmdline); do
      case "$arg" in
        root=*) rootdev="''${arg#root=}" ;;
        ostree=*) ostree_boot=1 ;;
      esac
    done
    [ -n "$rootdev" ] || fail "missing root device"
    for attempt in $(seq 1 100); do
      resolved=$(findfs "$rootdev" 2>/dev/null || true)
      [ -n "$resolved" ] || resolved="$rootdev"
      [ -b "$resolved" ] && break
      sleep 0.1
    done
    mount -o rw "$resolved" /sysroot || fail "mount $rootdev"
    if [ -n "$ostree_boot" ]; then
      ${pkgs.ostree}/lib/ostree/ostree-prepare-root /sysroot || fail "prepare ostree root"
    fi
    mkdir -p /sysroot/proc /sysroot/sys /sysroot/dev /sysroot/run
    ln -s /usr/lib/ladyboot /run/current-system
    mount --move /proc /sysroot/proc
    mount --move /sys /sysroot/sys
    mount --move /dev /sysroot/dev
    mount --move /run /sysroot/run
    exec switch_root /sysroot /usr/lib/systemd/systemd
  '';
  initrd = pkgs.makeInitrdNG {
    name = "ladyboot-initrd";
    contents = [
      { source = init; target = "/init"; }
      { source = pkgs.busybox + "/bin"; }
      { source = pkgs.kmod + "/bin"; }
      { source = modules; target = "/modules"; }
      { source = pkgs.ostree + "/lib/ostree/ostree-prepare-root"; }
      { source = pkgs.writeText "prepare-root.conf" "[composefs]\nenabled=true\n"; target = "/usr/lib/ostree/prepare-root.conf"; }
    ];
    compressor = "zstd";
  };
  planJSON = pkgs.writeText "ladyboot-resolved-plan.json" (builtins.toJSON plan);
  rootfs = pkgs.runCommand "ladyboot-rootfs-${profile.revision}" {
    passthru = { inherit systemd; timeClient = if has "network-runtime" then resolved.catalog.ntpd-rs else null; };
    __structuredAttrs = true;
    nativeBuildInputs = [ pkgs.python3Minimal ];
    unsafeDiscardReferences.out = true;
    outputChecks.out.allowedReferences = [];
  } ''
    mkdir -p "$out"/{boot,dev,proc,sys,run,tmp,var,sysroot,etc,usr/bin,usr/lib,usr/share/ladyboot}
    mkdir -p "$out/usr/lib/nix/store" "$out/usr/lib/modules/${kernel.modDirVersion}"
    ln -s usr/lib/nix "$out/nix"
    ln -s usr/bin "$out/bin"
    ln -s usr/bin "$out/sbin"
    ln -s usr/lib "$out/lib"
    ln -s sysroot/ostree "$out/ostree"
    while read -r path; do cp -a "$path" "$out/usr/lib/nix/store/"; done < ${closure}/store-paths
    python3 ${./inventory.py} link "$out" ${planJSON}
    cp -a ${systemd}/lib/systemd "$out/usr/lib/systemd"
    cp -a ${systemd}/lib/udev "$out/usr/lib/udev"
    chmod u+w "$out/usr/lib/systemd"
    cp -a ${systemd}/example/systemd/system "$out/usr/lib/systemd/system"
    chmod -R u+w "$out/usr/lib/systemd"
    mkdir -p "$out/usr/lib/systemd/system/service.d"
    cat > "$out/usr/lib/systemd/system/service.d/10-command-path.conf" <<'UNIT'
    [Service]
    Environment=PATH=/usr/bin
    ExecSearchPath=/usr/bin
    UNIT
    mkdir -p "$out/usr/lib/ostree" "$out/usr/lib/sysusers.d" "$out/usr/lib/tmpfiles.d" "$out/usr/lib/ladyboot"
    ln -s ${systemd} "$out/usr/lib/ladyboot/systemd"
    ln -s /usr "$out/usr/lib/ladyboot/sw"
    cp -a ${systemd}/example/tmpfiles.d/. "$out/usr/lib/tmpfiles.d/"
    cp -a ${systemd}/example/sysusers.d/. "$out/usr/lib/sysusers.d/"
    chmod -R u+w "$out/usr/lib/tmpfiles.d" "$out/usr/lib/sysusers.d"
    ln -s ${pkgs.ostree}/lib/ostree/ostree-remount "$out/usr/lib/ostree/ostree-remount"
    cp ${pkgs.ostree}/lib/systemd/system/ostree-*.service "$out/usr/lib/systemd/system/"
    cp ${pkgs.ostree}/lib/systemd/system-generators/ostree-system-generator "$out/usr/lib/systemd/system-generators/"
    mkdir -p "$out/etc/systemd/system-generators"
    ln -s /usr/lib/systemd/system-generators/ostree-system-generator "$out/etc/systemd/system-generators/ostree-system-generator"
    cp ${kernel}/bzImage "$out/usr/lib/modules/${kernel.modDirVersion}/vmlinuz"
    cp ${initrd}/initrd "$out/usr/lib/modules/${kernel.modDirVersion}/initramfs.img"
    cp -aL ${modules}/lib/modules/${kernel.modDirVersion}/. "$out/usr/lib/modules/${kernel.modDirVersion}/"
    cp ${planJSON} "$out/usr/share/ladyboot/plan.json"
    cat > "$out/usr/lib/os-release" <<'RELEASE'
    ID=${profile.os_id}
    NAME="ladyboot OS"
    VERSION_ID=${profile.revision}
    PRETTY_NAME="ladyboot OS ${profile.revision}"
    RELEASE
    ln -s ../usr/lib/os-release "$out/etc/os-release"
    printf '[composefs]\nenabled=true\n' > "$out/usr/lib/ostree/prepare-root.conf"
    printf 'root:x:0:0:root:/root:/bin/sh\n' > "$out/etc/passwd"
    printf 'root:x:0:\n' > "$out/etc/group"
    printf 'u root 0 "Root" /root /bin/sh\n' > "$out/usr/lib/sysusers.d/root.conf"
    printf 'd /var/log 0755 root root -\nd /var/lib 0755 root root -\nL /var/run - - - - ../run\n' > "$out/usr/lib/tmpfiles.d/state.conf"
    touch "$out/etc/machine-id"
    mkdir -p "$out/etc/systemd/system/multi-user.target.wants" "$out/etc/systemd/system/local-fs.target.wants"
    ln -s /usr/lib/systemd/system/multi-user.target "$out/etc/systemd/system/default.target"
    ln -s /usr/lib/systemd/system/ostree-remount.service "$out/etc/systemd/system/local-fs.target.wants/"
    ${lib.optionalString (has "network-dhcp") ''
      mkdir -p "$out/etc/systemd/network" "$out/etc/systemd/system/systemd-networkd.service.d" "$out/usr/lib/sysctl.d"
      cat > "$out/etc/systemd/network/10-ladyboot.network" <<'NETWORK'
      [Match]
      Name=en*
      [Network]
      DHCP=ipv4
      IPv6AcceptRA=no
      LinkLocalAddressing=no
      LLDP=no
      EmitLLDP=no
      [DHCPv4]
      UseDNS=no
      UseNTP=no
      UseHostname=no
      NETWORK
      cat > "$out/etc/nftables.conf" <<'FIREWALL'
      destroy table inet ladyboot
      table inet ladyboot {
        chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; iifname "en*" udp sport 67 udp dport 68 accept; }
        chain output { type filter hook output priority 0; policy drop; oifname "lo" accept; oifname "en*" udp sport 68 udp dport 67 accept; }
        chain forward { type filter hook forward priority 0; policy drop; }
      }
      FIREWALL
      cat > "$out/usr/lib/systemd/system/ladyboot-firewall.service" <<'UNIT'
      [Unit]
      Description=Selected DHCP-only default-deny firewall
      DefaultDependencies=no
      After=local-fs.target systemd-sysctl.service
      Before=network-pre.target
      Wants=network-pre.target
      [Service]
      Type=oneshot
      ExecStart=/usr/bin/nft -f /etc/nftables.conf
      RemainAfterExit=yes
      UNIT
      cat > "$out/etc/systemd/system/systemd-networkd.service.d/10-firewall.conf" <<'UNIT'
      [Unit]
      Requires=ladyboot-firewall.service
      After=ladyboot-firewall.service
      UNIT
      printf 'net.ipv4.ip_forward=0\nnet.ipv6.conf.all.forwarding=0\n' > "$out/usr/lib/sysctl.d/50-ladyboot.conf"
      ln -s /usr/lib/systemd/system/ladyboot-firewall.service "$out/etc/systemd/system/multi-user.target.wants/"
      ln -s /usr/lib/systemd/system/systemd-networkd.service "$out/etc/systemd/system/multi-user.target.wants/"
    ''}
    ${lib.optionalString (has "qemu-agent") ''
      cat > "$out/usr/lib/systemd/system/qemu-guest-agent.service" <<'UNIT'
      [Unit]
      Description=Explicit QEMU guest channel
      ConditionPathExists=/dev/virtio-ports/org.qemu.guest_agent.0
      [Service]
      ExecStart=/usr/bin/qemu-ga --statedir /run/qemu-ga
      RuntimeDirectory=qemu-ga
      Restart=on-failure
      RestartSec=5
      UNIT
      ln -s /usr/lib/systemd/system/qemu-guest-agent.service "$out/etc/systemd/system/multi-user.target.wants/"
    ''}
    printf '127.0.0.1 localhost\n::1 localhost\n' > "$out/etc/hosts"
    printf 'hosts: files\npasswd: files\ngroup: files\n' > "$out/etc/nsswitch.conf"
    mkdir -p "$out/etc/ssl/certs"
    ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt "$out/etc/ssl/certs/ca-certificates.crt"
    ${lib.optionalString (has "podman-rootless") (import ./podman.nix { inherit pkgs profile resolved; })}
    ${lib.optionalString (has "network-runtime") (import ./network.nix { inherit pkgs profile resolved; })}
    chmod 1777 "$out/tmp"
    # Nix canonicalizes store modes after the builder; inventory the delivered modes.
    find "$out" -type f -perm /111 -exec chmod 0555 {} +
    find "$out" -type f ! -perm /111 -exec chmod 0444 {} +
    find "$out" -type d -exec chmod 0555 {} +
    chmod u+w "$out/usr/share/ladyboot"
    touch "$out/usr/share/ladyboot/inventory.json"
    chmod 0555 "$out/usr/share/ladyboot"
    python3 ${./inventory.py} manifest "$out" ${planJSON}
    chmod 0444 "$out/usr/share/ladyboot/inventory.json"
    chmod 0555 "$out/usr/share/ladyboot"
  '';
  image = pkgs.dockerTools.buildLayeredImage {
    name = if has "podman-debug" then "bootc-podman-debug" else if has "podman-rootless" then "bootc-podman" else "ladyboot"; tag = profile.revision;
    includeStorePaths = false;
    extraCommands = "cp -a ${rootfs}/. .";
    config = { Labels."containers.bootc" = "1"; Cmd = [ "/usr/lib/systemd/systemd" ]; };
  };
  bootTestRootfs = import ./boot-test.nix { inherit pkgs rootfs; };
in { inherit rootfs image initrd kernel bootTestRootfs; }
