# Test-only fixtures and Python overlay; minimal production excludes Python.
{ pkgs, rootfs }:
let
  smoke = pkgs.dockerTools.buildLayeredImage {
    name = "ladyboot-smoke"; tag = "1";
    contents = [ pkgs.busybox ];
    config.Cmd = [ "/bin/sh" ];
  };
  closure = pkgs.closureInfo { rootPaths = [ pkgs.python3 ]; };
in pkgs.runCommand "ladyboot-podman-test-rootfs" {
  __structuredAttrs = true;
  unsafeDiscardReferences.out = true;
  outputChecks.out.allowedReferences = [];
} ''
  cp -a ${rootfs} "$out"
  chmod -R u+w "$out"
  while read -r path; do
    if [ ! -e "$out/usr/lib/nix/store/$(basename "$path")" ]; then
      cp -a "$path" "$out/usr/lib/nix/store/"
    fi
  done < ${closure}/store-paths
  mkdir -p "$out/opt/qualification"
  cp ${smoke} "$out/opt/qualification/smoke.tar.gz"
  cp ${../tests/podman_guest.py} "$out/opt/qualification/podman_guest.py"
  cat > "$out/etc/systemd/system/ladyboot-podman-test.service" <<'UNIT'
  [Unit]
  Description=Disposable rootless runtime qualification
  After=multi-user.target
  [Service]
  Type=oneshot
  Environment=PATH=/usr/bin
  ExecStart=${pkgs.python3}/bin/python3 /opt/qualification/podman_guest.py
  StandardOutput=journal+console
  StandardError=journal+console
  TimeoutStartSec=900
  UNIT
  cat > "$out/etc/systemd/system/ladyboot-podman-test.target" <<'UNIT'
  [Unit]
  Requires=multi-user.target ladyboot-podman-test.service
  After=multi-user.target
  UNIT
  rm "$out/etc/systemd/system/default.target"
  ln -s ladyboot-podman-test.target "$out/etc/systemd/system/default.target"
''
