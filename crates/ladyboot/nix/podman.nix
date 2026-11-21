# OS integration only. Application Quadlets and secrets are provisioned separately.
{ pkgs, profile, resolved }:
let
  inherit (pkgs) lib;
  inherit (resolved) systemd;
  p = profile.podman;
  id = toString p.uid;
  init = resolved.catalog.podman-init;
  policy = builtins.toJSON {
    default = [{ type = "reject"; }];
    transports = lib.genAttrs [ "containers-storage" "docker-archive" "oci-archive" ]
      (_: { "" = [{ type = "insecureAcceptAnything"; }]; });
  };
in ''
  cp -a ${resolved.catalog.uefi-assets}/usr/lib/. "$out/usr/lib/"
  # cp -a preserves the store directory modes; reopen only assembly parents.
  chmod u+w "$out/usr/lib" "$out/usr/lib/bootupd"
  cp -a ${resolved.catalog.bootupd}/lib/bootupd/grub2-static "$out/usr/lib/bootupd/"
  chmod -R u+w "$out/usr/lib/bootupd"
  ln -s ${pkgs.grub2_efi}/bin/grub-editenv "$out/usr/bin/grub2-editenv"
  cat > "$out/usr/lib/bootupd/grub2-static/configs.d/00-ladyboot-console.cfg" <<'GRUB'
  serial --unit=0 --speed=115200
  terminal_input serial console
  terminal_output serial console
  GRUB
  mkdir -p "$out/usr/libexec" "$out/usr/lib/ladyboot/helpers" "$out/usr/lib/systemd/user-generators"
  mkdir -p "$out/usr/lib/systemd/user" "$out/etc/pam.d" "$out/etc/containers"
  ln -s ${init}/bin/ladyboot-podman-init "$out/usr/libexec/ladyboot-podman-init"
  cp ${pkgs.shadow}/bin/newuidmap ${pkgs.shadow}/bin/newgidmap "$out/usr/lib/ladyboot/helpers/"
  for helper in newuidmap newgidmap; do
    rm "$out/usr/bin/$helper"
    ln -s /run/ladyboot-helpers/$helper "$out/usr/bin/$helper"
  done
  printf '${p.user}:x:${id}:${toString p.gid}:Containers:/var/home/${p.user}:/bin/sh\n' >> "$out/etc/passwd"
  printf '${p.user}:x:${toString p.gid}:\n' >> "$out/etc/group"
  printf 'root:!:::::::\n${p.user}:!:::::::\n' > "$out/etc/shadow"
  printf '${p.user}:${toString p.subuid_start}:${toString p.range_size}\n' > "$out/etc/subuid"
  printf '${p.user}:${toString p.subgid_start}:${toString p.range_size}\n' > "$out/etc/subgid"
  cp -a ${systemd}/example/systemd/user/. "$out/usr/lib/systemd/user/"
  chmod -R u+w "$out/usr/lib/systemd/user"
  cp ${pkgs.dbus}/etc/systemd/user/dbus.{socket,service} "$out/usr/lib/systemd/user/"
  substituteInPlace "$out/usr/lib/systemd/user/dbus.service" \
    --replace-fail '--session --address' '--config-file=${pkgs.dbus}/share/dbus-1/session.conf --address'
  mkdir -p "$out/usr/lib/systemd/user/sockets.target.wants"
  ln -s ../dbus.socket "$out/usr/lib/systemd/user/sockets.target.wants/dbus.socket"
  ln -s ${resolved.catalog.podman}/libexec/podman/quadlet "$out/usr/lib/systemd/user-generators/podman-user-generator"
  mkdir -p "$out/etc/systemd/user-generators"
  ln -s /usr/lib/systemd/user-generators/podman-user-generator "$out/etc/systemd/user-generators/podman-user-generator"
  cp ${resolved.catalog.podman}/share/systemd/user/podman-user-wait-network-online.service "$out/usr/lib/systemd/user/"
  ln -s /usr/lib/systemd/system/network-online.target "$out/etc/systemd/system/multi-user.target.wants/network-online.target"
  printf 'u messagebus - "D-Bus system bus" /run/dbus\n' > "$out/usr/lib/sysusers.d/messagebus.conf"
  cp ${pkgs.dbus}/etc/systemd/system/dbus.{socket,service} "$out/usr/lib/systemd/system/"
  substituteInPlace "$out/usr/lib/systemd/system/dbus.service" \
    --replace-fail '--system --address' '--config-file=${pkgs.dbus}/share/dbus-1/system.conf --address'
  mkdir -p "$out/etc/dbus-1/system.d" "$out/etc/systemd/system/sockets.target.wants"
  cp ${systemd}/share/dbus-1/system.d/*.conf "$out/etc/dbus-1/system.d/"
  ln -s /usr/lib/systemd/system/dbus.socket "$out/etc/systemd/system/sockets.target.wants/dbus.socket"
  ln -s /usr/lib/systemd/system/systemd-logind.service "$out/etc/systemd/system/dbus-org.freedesktop.login1.service"
  cat > "$out/etc/pam.d/systemd-user" <<'PAM'
  account required ${pkgs.pam}/lib/security/pam_permit.so
  session required ${systemd}/lib/security/pam_systemd.so class=manager
  PAM
  cat > "$out/etc/systemd/user.conf" <<'USER'
  [Manager]
  DefaultEnvironment=PATH=/usr/bin
  USER
  cat > "$out/usr/lib/systemd/system/run-ladyboot\x2dhelpers.mount" <<'MOUNT'
  [Unit]
  Description=Private mapping helpers with explicit setuid support
  Before=ladyboot-podman-init.service
  [Mount]
  What=tmpfs
  Where=/run/ladyboot-helpers
  Type=tmpfs
  Options=mode=0755,nodev,size=8M
  MOUNT
  cat > "$out/usr/lib/systemd/system/ladyboot-podman-init.service" <<'UNIT'
  [Unit]
  Description=Verify rootless identity and prepare private runtime
  Requires=run-ladyboot\x2dhelpers.mount
  After=local-fs.target systemd-sysusers.service run-ladyboot\x2dhelpers.mount
  Before=systemd-logind.service user@${id}.service
  [Service]
  Type=oneshot
  TimeoutStartSec=30s
  ExecStart=/usr/libexec/ladyboot-podman-init ${p.user} ${id} ${toString p.gid} ${toString p.subuid_start} ${toString p.subgid_start} ${toString p.range_size}
  RemainAfterExit=yes
  UNIT
  for unit in systemd-logind.service user@${id}.service; do
    mkdir -p "$out/etc/systemd/system/$unit.d"
    cat > "$out/etc/systemd/system/$unit.d/10-rootless-identity.conf" <<'UNIT'
  [Unit]
  Requires=ladyboot-podman-init.service
  After=ladyboot-podman-init.service
  UNIT
  done
  ln -s /usr/lib/systemd/system/user@.service "$out/etc/systemd/system/multi-user.target.wants/user@${id}.service"
  for unit in ladyboot-podman-init systemd-logind; do
    ln -s /usr/lib/systemd/system/$unit.service "$out/etc/systemd/system/multi-user.target.wants/$unit.service"
  done
  cat > "$out/etc/containers/containers.conf" <<'CONTAINERS'
  [containers]
  default_capabilities=[]
  log_driver="journald"
  [engine]
  cgroup_manager="systemd"
  runtime="crun"
  events_logger="journald"
  [engine.runtimes]
  crun=["/usr/bin/crun"]
  [network]
  default_rootless_network_cmd="pasta"
  CONTAINERS
  cat > "$out/etc/containers/storage.conf" <<'STORAGE'
  [storage]
  driver="overlay"
  runroot="/run/containers/storage"
  graphroot="/var/lib/containers/storage"
  [storage.options.overlay]
  mountopt="nodev"
  STORAGE
  mkdir -p "$out/etc/containers/storage.rootless.conf.d"
  cat > "$out/etc/containers/storage.rootless.conf.d/10-ladyboot.conf" <<'STORAGE'
  [storage]
  graphroot="/var/home/${p.user}/.local/share/containers/storage"
  runroot="/run/user/${id}/containers"
  STORAGE
  printf '%s\n' '${policy}' > "$out/etc/containers/policy.json"
  printf 'unqualified-search-registries=[]\nshort-name-mode="enforcing"\n' > "$out/etc/containers/registries.conf"
  mkdir -p "$out/usr/lib/systemd/journald.conf.d"
  printf '[Journal]\nSystemMaxUse=64M\nRuntimeMaxUse=32M\n' > "$out/usr/lib/systemd/journald.conf.d/10-limits.conf"
''
