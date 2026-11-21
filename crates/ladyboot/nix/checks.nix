{ pkgs, rootfs, image }:
{
  vm-drivers = pkgs.runCommand "ladyboot-vm-driver-checks" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    cp ${../tests/network_vm.py} network_vm.py
    cp ${../tests/podman_vm.py} podman_vm.py
    cp ${../tests/bootc_lifecycle.py} bootc_lifecycle.py
    cp ${../tests/lifecycle_install.py} lifecycle_install.py
    cp ${../tests/test_vm_drivers.py} test_vm_drivers.py
    cp ${../tests/test_nts_observation.py} test_nts_observation.py
    cp ${../tests/nts_guest.py} nts_guest.py
    cp ${../tests/nts_peer.py} nts_peer.py
    cp ${../tests/test_nts_scenarios.py} test_nts_scenarios.py
    cp ${../tests/network_probe.py} network_probe.py
    PYTHONDONTWRITEBYTECODE=1 python3 test_nts_observation.py
    PYTHONDONTWRITEBYTECODE=1 python3 test_nts_scenarios.py
    PYTHONDONTWRITEBYTECODE=1 python3 test_vm_drivers.py
    touch "$out"
  '';
  unit = pkgs.runCommand "ladyboot-unit-checks" { nativeBuildInputs = [ pkgs.python3Minimal ]; } ''
    mkdir -p workspace/{nix,tests}
    cp ${./inventory.py} workspace/nix/inventory.py
    cp ${./archive_inventory.py} workspace/nix/archive_inventory.py
    cp ${../tests/test_assembly.py} workspace/tests/test_assembly.py
    cd workspace
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
    touch "$out"
  '';
  image = pkgs.runCommand "ladyboot-image-checks" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 ${./archive_inventory.py} ${image} ${rootfs}/usr/share/ladyboot/inventory.json
    touch "$out"
  '';
  rootfs = pkgs.runCommand "ladyboot-rootfs-checks" { nativeBuildInputs = [ pkgs.python3Minimal rootfs.systemd ] ++ pkgs.lib.optional (rootfs.timeClient != null) rootfs.timeClient; } ''
    python3 ${./inventory.py} verify ${rootfs} ${rootfs}/usr/share/ladyboot/plan.json
    python3 ${../tests/test_rootfs.py} ${rootfs}
    python3 ${../tests/test_generator_paths.py} ${rootfs}
    if [ -e ${rootfs}/etc/containers/containers.conf ]; then
      python3 ${../tests/test_podman_rootfs.py} ${rootfs}
      GOCACHE="$TMPDIR/go-cache" GOMAXPROCS=2 GOTOOLCHAIN=local GOPROXY=off \
        ${(import ./container-security.nix { inherit pkgs; }).go}/bin/go build -o go-buildinfo ${../tests/go-buildinfo.go}
      python3 ${../tests/test_go_runtime.py} ${rootfs} ./go-buildinfo ${(import ./container-security.nix { inherit pkgs; }).go}/bin/go
      python3 ${../tests/test_quadlet_rootfs.py} ${rootfs}
      python3 ${../tests/test_uefi_rootfs.py} ${rootfs}
    fi
    if ${pkgs.lib.boolToString (rootfs.timeClient != null)}; then
      python3 ${../tests/test_nts_rootfs.py} ${rootfs}
      python3 ${../tests/test_nts_config.py} ${rootfs} "$(command -v ntp-ctl)" ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt
      python3 ${../tests/check_nts_endpoint_contract.py} "$(command -v ntp-ctl)"
    fi
    ${pkgs.bootc}/bin/bootc container lint --rootfs ${rootfs}
    touch "$out"
  '';
}
