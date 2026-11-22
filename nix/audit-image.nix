# The project is input data. Only this frozen controller distribution is built.
{ pkgs, configPath, sourcePath, codexPath, codexHostPath, runtimeSourcePath, imageName,
  networkTools ? import ./network-tools.nix { inherit pkgs; } }:
let
  cfg = builtins.fromJSON (builtins.readFile configPath);
  zig017 = pkgs.stdenvNoCC.mkDerivation {
    pname = "zig";
    version = "0.17.0";
    src = pkgs.fetchurl {
      url = "https://ziglang.org/download/0.17.0/zig-x86_64-linux-0.17.0.tar.xz";
      sha256 = "1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026";
    };
    dontConfigure = true;
    dontBuild = true;
    dontStrip = true;
    installPhase = ''
      mkdir -p $out/bin $out/lib/zig
      cp zig $out/lib/zig/zig
      cp -r lib $out/lib/zig/lib
      ln -s $out/lib/zig/zig $out/bin/zig
    '';
  };
  rust = (pkgs.buildEnv {
    name = "ladyshell-rust-${pkgs.rustc.version}";
    paths = [ pkgs.rustc networkTools.cargo networkTools.rustfmt pkgs.clippy pkgs.stdenv.cc ];
    pathsToLink = [ "/bin" ];
  }) // { version = pkgs.rustc.version; };
  available = { zig = zig017; node = pkgs.nodejs; inherit rust; };
  requested = builtins.map (name:
    if !(builtins.hasAttr name available) then throw "Unsupported toolchain: ${name}"
    else let package = available.${name}; in
      if cfg.tools.${name}.version != package.version then
        throw "Exact toolchain version unavailable: ${name} ${cfg.tools.${name}.version}"
      else package
  ) (builtins.attrNames cfg.tools);
  # Keep this derivation identical to image.nix: the provider pins its store path.
  codex = pkgs.runCommand "ladyshell-codex" {} ''
    mkdir -p $out/bin
    cp ${builtins.path { path = codexPath; name = "codex"; }} $out/bin/codex
    cp ${builtins.path { path = codexHostPath; name = "codex-code-mode-host"; }} $out/bin/codex-code-mode-host
    chmod 755 $out/bin/*
  '';
  runtime = import ./runtime.nix { inherit pkgs; source = runtimeSourcePath; };
  base = pkgs.buildEnv {
    name = "ladyshell-audit-root";
    paths = requested ++ [ pkgs.bashInteractive pkgs.coreutils pkgs.findutils
      pkgs.gnugrep pkgs.gnused pkgs.gawk pkgs.diffutils networkTools.git networkTools.curl pkgs.python3 pkgs.cacert codex runtime ];
    pathsToLink = [ "/bin" "/etc" ];
  };
  sources = builtins.path { path = sourcePath; name = "audit-project-sources"; };
  responseSchema = builtins.path {
    path = runtimeSourcePath + "/crates/ladyshell/resources/audit/agent-response-schema.json";
    name = "audit-agent-response-schema.json";
  };
  config = {
    User = "10001:10001";
    WorkingDir = "/workspace";
    Env = [ "PATH=/usr/local/bin:/bin" "HOME=/audit/agent" "CODEX_HOME=/audit/agent/.codex"
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "XDG_CACHE_HOME=/audit/agent/cache" ];
    Cmd = [ "/bin/sleep" "infinity" ];
  };
  archive = pkgs.dockerTools.buildLayeredImage {
    name = imageName;
    tag = "nix";
    contents = [ base ];
    fakeRootCommands = ''
      mkdir -p etc tmp audit/source audit/agent/cache audit/scratch workspace usr/local/bin usr/bin
      ln -s ${pkgs.coreutils}/bin/env usr/bin/env
      printf 'root:x:0:0:root:/root:/bin/bash\nsandbox:x:10001:10001:Sandbox:/audit/agent:/bin/bash\n' > etc/passwd
      printf 'root:x:0:\nsandbox:x:10001:\n' > etc/group
      cp -r ${sources}/. audit/source/
      chown -R 0:0 audit/source
      chmod -R a-w audit/source
      chown -R 10001:10001 audit/agent audit/scratch workspace
      chmod 700 audit/agent audit/scratch workspace
      cp ${responseSchema} audit/agent-response-schema.json
      chown 0:0 audit/agent-response-schema.json
      chmod 444 audit/agent-response-schema.json
      chmod 1777 tmp
      ln -s ${runtime}/bin/ladyshell usr/local/bin/ladyshell
      ln -s ${codex}/bin/codex usr/local/bin/codex
      ln -s ${codex}/bin/codex-code-mode-host usr/local/bin/codex-code-mode-host
    '';
    inherit config;
  };
in {
  inherit archive runtime codex config;
  ladyshellRuntimeRoots = [ base ];
  ladyshellNetworkTools = networkTools;
}
