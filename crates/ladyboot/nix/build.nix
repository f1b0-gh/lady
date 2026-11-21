{ flakePath, configPath, output ? "image" }:
let
  flake = builtins.getFlake ("path:" + flakePath);
  pkgs = flake.inputs.nixpkgs.legacyPackages.x86_64-linux;
  profile = builtins.fromJSON (builtins.readFile (builtins.toPath configPath));
  artifacts = import ./image.nix { inherit pkgs profile; };
  checks = import ./checks.nix { inherit pkgs; inherit (artifacts) rootfs image; };
  outputs = artifacts // {
    plan = (import ./resolve.nix { inherit pkgs profile; }).plan;
    checks = pkgs.runCommand "ladyboot-artifact-checks" {} ''
      test -e ${checks.unit}
      test -e ${checks.rootfs}
      test -e ${checks.image}
      touch "$out"
    '';
  };
in assert builtins.elem output [ "plan" "rootfs" "image" "bootTestRootfs" "kernel" "initrd" "checks" ]; outputs.${output}
