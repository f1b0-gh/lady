# Disposable fixtures only: production images never include these services or CA.
{ pkgs, rootfs, role }:
assert builtins.elem role [ "dut" "peer" "legacy" ];
let
  smoke = pkgs.dockerTools.buildLayeredImage {
    name = "ladyboot-network"; tag = "1";
    contents = [ pkgs.curl pkgs.busybox ];
    config.Entrypoint = [ "/bin/curl" ];
  };
  closure = pkgs.closureInfo { rootPaths = [ pkgs.python3 ] ++ pkgs.lib.optional (role == "dut") pkgs.systemd ++ pkgs.lib.optional (role == "peer") pkgs.chrony; };
in pkgs.runCommand "ladyboot-network-${role}-rootfs" {
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
  mkdir -p "$out/opt/qualification" "$out/opt/qualification/http"
  printf 'Ladyboot isolated network fixture\n' > "$out/opt/qualification/http/index.html"
  cp ${../tests/nts_peer.py} "$out/opt/qualification/nts_peer.py"
  cp ${../tests/nts_guest.py} "$out/opt/qualification/nts_guest.py"
  mkdir -p "$out/opt/qualification/nts"
  cp ${../tests/fixtures/network/nts/ca.pem} "$out/opt/qualification/nts/ca.pem"
  cp ${../tests/network_probe.py} "$out/opt/qualification/network_probe.py"
  cp ${../tests/fixtures/network/net-cert.pem} "$out/opt/qualification/net-cert.pem"
  ${if role == "dut" then ''
    cp ${smoke} "$out/opt/qualification/network-smoke.tar.gz"
    cp ${../tests/test_firewall_reload.py} "$out/opt/qualification/test_firewall_reload.py"
    cp ${../tests/network_guest.py} "$out/opt/qualification/guest.py"
  '' else if role == "legacy" then ''
    cp ${../tests/legacy_network_guest.py} "$out/opt/qualification/guest.py"
  '' else ''
    cp ${../tests/fixtures/network/nts}/{expired,future,server-key,valid,wrong-name}.pem "$out/opt/qualification/nts/"
    cp ${../tests/fixtures/network/net-key.pem} "$out/opt/qualification/net-key.pem"
    cp ${../tests/network_fixture.py} "$out/opt/qualification/guest.py"
    for service in ladyboot-firewall systemd-networkd systemd-resolved ntpd-rs ladyboot-network-online; do
      ln -s /dev/null "$out/etc/systemd/system/$service.service"
    done
  ''}
  cat > "$out/etc/systemd/system/ladyboot-network-test.service" <<'UNIT'
  [Unit]
  Description=Disposable isolated network qualification (${role})
  After=multi-user.target
  [Service]
  Type=oneshot
  Environment=PATH=/usr/bin
  ${pkgs.lib.optionalString (role == "peer") "Environment=CHRONYD=${pkgs.chrony}/bin/chronyd"}
  # systemd 262 verify creates /run/systemd even with --root; run in the guest.
  ${pkgs.lib.optionalString (role == "dut") "ExecStartPre=${pkgs.systemd}/bin/systemd-analyze --man=no --generators=no verify ntpd-rs.service"}
  ExecStart=${pkgs.python3}/bin/python3 /opt/qualification/guest.py
  StandardOutput=journal+console
  StandardError=journal+console
  TimeoutStartSec=${if role == "dut" then "1100" else "1800"}
  UNIT
  cat > "$out/etc/systemd/system/ladyboot-network-test.target" <<'UNIT'
  [Unit]
  Requires=multi-user.target ladyboot-network-test.service
  After=multi-user.target
  UNIT
  rm "$out/etc/systemd/system/default.target"
  ln -s ladyboot-network-test.target "$out/etc/systemd/system/default.target"
''
