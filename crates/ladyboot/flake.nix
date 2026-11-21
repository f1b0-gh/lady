{
  description = "ladyboot: explicit bootable OS needs, pinned assembly and observed inventories";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/1c89083e451e891152365b799595cf7790a43325";
  outputs = { nixpkgs, ... }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
      profile = builtins.fromJSON (builtins.readFile ./profiles/base.json);
      artifacts = import ./nix/image.nix { inherit pkgs profile; };
      podmanProfile = builtins.fromJSON (builtins.readFile ./profiles/podman-vm.json);
      podmanArtifacts = import ./nix/image.nix { inherit pkgs; profile = podmanProfile; };
      legacyNetworkArtifacts = import ./nix/image.nix {
        inherit pkgs;
        profile = (builtins.removeAttrs podmanProfile [ "podman" "network" ]) // {
          needs = [ "bootc-base" "virtio-vm" "network-dhcp" ];
        };
      };
      revision2Artifacts = import ./nix/image.nix { inherit pkgs; profile = podmanProfile // { revision = "2"; }; };
      debugProfile = builtins.fromJSON (builtins.readFile ./profiles/podman-debug.json);
      debugArtifacts = import ./nix/image.nix { inherit pkgs; profile = debugProfile; };
      dev = pkgs.mkShell { packages = [ pkgs.nickel pkgs.nls pkgs.python3Minimal ]; };
    in {
      packages.x86_64-linux = {
        default = artifacts.image;
        rootfs = artifacts.rootfs;
        bootc-image = artifacts.image;
        boot-test-rootfs = artifacts.bootTestRootfs;
        inherit (artifacts) initrd kernel;
        nickel = pkgs.nickel;
        bootc-podman = podmanArtifacts.image;
        bootc-podman-sbom-tools = import ./nix/sbom-tools.nix { inherit pkgs; };
        bootc-podman-rootfs = podmanArtifacts.rootfs;
        bootc-podman-test-rootfs = import ./nix/podman-test.nix { inherit pkgs; rootfs = podmanArtifacts.rootfs; };
        bootc-podman-network-legacy-rootfs = import ./nix/network-test.nix { inherit pkgs; rootfs = legacyNetworkArtifacts.rootfs; role = "legacy"; };
        bootc-podman-network-test-rootfs = import ./nix/network-test.nix { inherit pkgs; rootfs = podmanArtifacts.rootfs; role = "dut"; };
        bootc-podman-network-peer-rootfs = import ./nix/network-test.nix { inherit pkgs; rootfs = podmanArtifacts.rootfs; role = "peer"; };
        bootc-podman-revision2 = revision2Artifacts.image;
        bootc-podman-lifecycle-installer = import ./nix/lifecycle.nix {
          inherit pkgs; rootfs = podmanArtifacts.rootfs;
          imageV1 = podmanArtifacts.image; imageV2 = revision2Artifacts.image;
        };
        bootc-podman-debug = debugArtifacts.image;
        bootc-podman-debug-rootfs = debugArtifacts.rootfs;
        bootc-podman-debug-test-rootfs = import ./nix/podman-test.nix { inherit pkgs; rootfs = debugArtifacts.rootfs; };
        qemu = pkgs.qemu_kvm;
        mkfs = pkgs.e2fsprogs;
        firmware = pkgs.OVMF.fd;
        bootupd = import ./nix/bootupd.nix { inherit pkgs; };
        grub-efi = pkgs.grub2_efi;
        shim = pkgs.shim-unsigned;
      };
      devShells.x86_64-linux = { default = dev; inherit dev; build = dev; };
      checks.x86_64-linux = (import ./nix/checks.nix { inherit pkgs; inherit (artifacts) rootfs image; }) // {
        podman-rootfs = (import ./nix/checks.nix { inherit pkgs; rootfs = podmanArtifacts.rootfs; image = podmanArtifacts.image; }).rootfs;
        podman-image = (import ./nix/checks.nix { inherit pkgs; rootfs = podmanArtifacts.rootfs; image = podmanArtifacts.image; }).image;
        podman-debug-rootfs = (import ./nix/checks.nix { inherit pkgs; rootfs = debugArtifacts.rootfs; image = debugArtifacts.image; }).rootfs;
        podman-debug-image = (import ./nix/checks.nix { inherit pkgs; rootfs = debugArtifacts.rootfs; image = debugArtifacts.image; }).image;
        podman-revision2-image = (import ./nix/checks.nix { inherit pkgs; rootfs = revision2Artifacts.rootfs; image = revision2Artifacts.image; }).image;
        profile = pkgs.runCommand "ladyboot-profile-check" { nativeBuildInputs = [ pkgs.nickel pkgs.python3Minimal ]; } ''
          cp -r ${./profiles} profiles
          for profile in base podman-vm podman-debug; do
            nickel export --format json --apply-contract profiles/schema.ncl "profiles/$profile.ncl" > "$profile.evaluated.json"
          done
          python3 - <<'PY'
          import json
          from pathlib import Path
          for profile in ["base", "podman-vm", "podman-debug"]:
              if json.loads(Path(f"{profile}.evaluated.json").read_text()) != json.loads(Path(f"profiles/{profile}.json").read_text()):
                  raise SystemExit(f"Stale JSON: render {profile} explicitly")
          PY
          touch "$out"
        '';
      };
    };
}
