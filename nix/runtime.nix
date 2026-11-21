# Build the trusted runtime for the Nix target, never patch a host executable.
# Usage: nix-build --extra-experimental-features "nix-command flakes" --impure nix/runtime.nix --no-out-link
{ pkgs ? import (builtins.getFlake ("path:" + toString ./.)).inputs.nixpkgs {
    system = builtins.currentSystem;
  }
, source ? ../.
}:
let
  ladySource = pkgs.lib.cleanSourceWith {
    src = source;
    filter = path: type:
      let
        rel = pkgs.lib.removePrefix (toString source + "/") (toString path);
        top = builtins.head (pkgs.lib.splitString "/" rel);
      in type != "symlink" &&
        builtins.elem top [ "Cargo.toml" "Cargo.lock" "LICENSE" "src" "crates" "resources" ] &&
        !(builtins.elem "target" (pkgs.lib.splitString "/" rel));
  };
  utilRoot = source + "/vendor/nickel-util";
  utilSource = pkgs.lib.cleanSourceWith {
    src = utilRoot;
    filter = path: type:
      let rel = pkgs.lib.removePrefix (toString utilRoot + "/") (toString path);
          top = builtins.head (pkgs.lib.splitString "/" rel);
      in type != "symlink" && builtins.elem top [ "Cargo.toml" "src" ];
  };
  src = pkgs.runCommand "lady-runtime-source" {} ''
    mkdir -p $out/vendor
    cp -r ${ladySource}/. $out/
    cp -r ${utilSource} $out/vendor/nickel-util
    chmod -R u+w $out
  '';
in pkgs.rustPlatform.buildRustPackage {
  pname = "ladyshell";
  version = "0.1.0";
  inherit src;
  # The audit caller supplies a private staging path. Anchor the vendor lock to
  # the filtered store snapshot so its symlink remains usable inside Nix builds
  # and after the staging directory has been removed.
  cargoLock.lockFile = "${ladySource}/Cargo.lock";
  cargoBuildFlags = [ "--package" "ladyshell-cli" "--bins" ];
  # The host integration suite needs Nix/OpenShell. Run separately, not in the
  # package builder; this derivation asserts the resulting binaries themselves.
  doCheck = false;
  postInstall = ''
    test ! -e $out/bin/ladybom
    test ! -e $out/bin/ladyboot
    mkdir -p $out/share/ladyshell
    cp -r resources/audit $out/share/ladyshell/audit
    install -Dm644 LICENSE $out/share/licenses/ladyshell/LICENSE-Apache-2.0
    install -Dm644 crates/ladyshell/src/audit/validator/LICENSE-MIT \
      $out/share/licenses/ladyshell/audit-validator-MIT
    printf '[]' > empty.json
    $out/bin/ladyshell audit validate findings empty.json
    $out/bin/ladyshell audit validate coverage empty.json
    $out/bin/audit-validator --version
  '';
}
