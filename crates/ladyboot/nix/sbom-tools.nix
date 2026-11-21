# Explicit host-side collectors; never included in the production OS closure.
{ pkgs }:
let
  go = (import ./container-security.nix { inherit pkgs; }).go;
  reader = pkgs.runCommand "ladyboot-go-buildinfo" { nativeBuildInputs = [ go ]; } ''
    mkdir -p "$out/bin"
    GOCACHE="$TMPDIR/go-cache" GOMAXPROCS=2 GOTOOLCHAIN=local GOPROXY=off \
      go build -o "$out/bin/go-buildinfo" ${../tests/go-buildinfo.go}
  '';
  checker = pkgs.writeShellScriptBin "ladyboot-archive-check" ''
    exec ${pkgs.python3}/bin/python3 ${./archive_inventory.py} "$@"
  '';
in pkgs.symlinkJoin {
  name = "ladyboot-sbom-tools";
  paths = [ reader checker ];
}
