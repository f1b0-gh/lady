# Host-owned entry point. Every path names a previously verified private snapshot.
{ flakePath, configPath, sourcePath, codexPath, codexHostPath, runtimeSourcePath, imageName }:
let
  flake = builtins.getFlake ("path:" + flakePath);
  pkgs = import flake.inputs.nixpkgs { system = "x86_64-linux"; };
  built = import ./audit-image.nix {
    inherit pkgs imageName;
    configPath = builtins.toPath configPath;
    sourcePath = builtins.toPath sourcePath;
    codexPath = builtins.toPath codexPath;
    codexHostPath = builtins.toPath codexHostPath;
    runtimeSourcePath = builtins.toPath runtimeSourcePath;
  };
  metadata = {
    archive = toString built.archive;
    runtime_binary = "${built.runtime}/bin/ladyshell";
    codex_binary = "${built.codex}/bin/codex";
  };
in pkgs.runCommand "ladyshell-audit-metadata" { passthru = { inherit metadata; }; } ''
  mkdir -p $out
  cat > $out/metadata.json <<'LADYSHELL_METADATA'
  ${builtins.toJSON metadata}
  LADYSHELL_METADATA
''
