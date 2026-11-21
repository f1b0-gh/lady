# Trusted recipe. All project-provided values are data, never Nix expressions.
{ pkgs, configPath, sourcePath, codexPath, codexHostPath, runtimePath, auditPath, preparationPath ? null,
  openssl ? import ./openssl.nix { inherit pkgs; },
  networkTools ? import ./network-tools.nix { inherit pkgs openssl; },
  tpm2Tss ? import ./tpm2-tss.nix { inherit pkgs openssl networkTools; },
  rustToolchains ? { "${pkgs.rustc.version}" = [ pkgs.rustc networkTools.cargo networkTools.rustfmt pkgs.clippy ]; } }:
let
  cfg = builtins.fromJSON (builtins.readFile configPath);
  pythonCandidates = [ pkgs.python311 pkgs.python312 pkgs.python313 pkgs.python314 ];
  pythonBase = if !(cfg.tools ? python) then pkgs.python3 else
    let matching = builtins.filter (p: p.version == cfg.tools.python.version) pythonCandidates;
    in if matching == [] then throw "Exact Python version unavailable" else builtins.head matching;
  pythonPackages = builtins.filter (name: builtins.hasAttr name cfg.tools) [ "pydantic" "jsonschema" "setuptools" ];
  python = (pythonBase.withPackages (ps: map (name:
    let package = builtins.getAttr name ps;
    in if package.version != cfg.tools.${name}.version then throw "Exact Python package version unavailable: ${name}"
    else package) pythonPackages)) // { version = pythonBase.version; };
  preparation = if preparationPath == null then null else builtins.fromJSON (builtins.readFile preparationPath);
  dependencies = if preparation == null then null else import ./dependencies.nix { inherit pkgs sourcePath preparation python rust; };
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
    name = "ladyshell-rust-${rustVersion}";
    paths = (rustToolchains.${rustVersion} or (throw "Exact Rust version unavailable: ${rustVersion}")) ++ [ pkgs.stdenv.cc ];
    pathsToLink = [ "/bin" ];
  }) // { version = rustVersion; };
  rustVersion = if cfg.tools ? rust then cfg.tools.rust.version else pkgs.rustc.version;
  available = {
    zig = zig017; node = pkgs.nodejs; inherit rust python openssl;
    inherit (pkgs) cmake perl pkg-config maturin uv;
    tpm2-tss = tpm2Tss;
    make = pkgs.gnumake;
    inherit (pythonBase.pkgs) pydantic jsonschema setuptools;
  };
  nativeLibraries = builtins.filter (p: p != null) [
    (if cfg.tools ? openssl then openssl else null)
    (if cfg.tools ? tpm2-tss then tpm2Tss else null)
  ];
  nativeLibraryFiles = pkgs.buildEnv {
    name = "ladyshell-native-libraries";
    paths = map pkgs.lib.getLib nativeLibraries ++ map pkgs.lib.getDev nativeLibraries;
    pathsToLink = [ "/lib" ];
  };
  nativeSupport = pkgs.runCommand "ladyshell-native-support" {} ''
    mkdir -p $out/usr/local/lib
    ln -s ${nativeLibraryFiles}/lib $out/usr/local/lib/ladyshell
  '';
  requested = builtins.map (name:
    if !(builtins.hasAttr name available) then throw "Unsupported toolchain: ${name}"
    else let package = available.${name}; in
      if cfg.tools.${name}.version != package.version then
        throw "Exact toolchain version unavailable: ${name} ${cfg.tools.${name}.version}"
      else package
  ) (builtins.filter (name: !(builtins.elem name pythonPackages)) (builtins.attrNames cfg.tools));
  codex = pkgs.runCommand "ladyshell-codex" {} ''
    mkdir -p $out/bin
    cp ${builtins.path { path = codexPath; name = "codex"; }} $out/bin/codex
    cp ${builtins.path { path = codexHostPath; name = "codex-code-mode-host"; }} $out/bin/codex-code-mode-host
    chmod 755 $out/bin/*
  '';
  runtime = pkgs.runCommand "ladyshell-runtime" {
    nativeBuildInputs = [ pkgs.autoPatchelfHook ];
    buildInputs = [ pkgs.stdenv.cc.cc.lib ];
  } ''
    mkdir -p $out/bin
    cp ${builtins.path { path = runtimePath; name = "ladyshell"; }} $out/bin/ladyshell
    chmod 755 $out/bin/ladyshell
    autoPatchelf $out
  '';
  base = pkgs.buildEnv {
    name = "ladyshell-dev-root";
    paths = requested ++ [ pkgs.bashInteractive pkgs.coreutils pkgs.findutils
      pkgs.gnugrep pkgs.gnused pkgs.gawk pkgs.diffutils networkTools.git networkTools.curl
      pkgs.gnutar pkgs.gzip python pkgs.cacert codex runtime ];
    pathsToLink = [ "/bin" "/etc" ];
  };
  audit = builtins.path { path = auditPath; name = "ladyshell-audit-skills"; };
  sources = builtins.path { path = sourcePath; name = "project-sources"; };
  runtimeRoots = [ base ]
    ++ pkgs.lib.optional (nativeLibraries != []) nativeSupport
    ++ pkgs.lib.optional (dependencies != null) dependencies.bundle;
in (pkgs.dockerTools.buildLayeredImage {
  name = "ladyshell-${cfg.name}";
  tag = "nix";
  contents = runtimeRoots;
  fakeRootCommands = ''
    mkdir -p etc tmp sandbox/workspace/project sandbox/workspace/cache sandbox/.codex usr/local/bin usr/bin
    ln -s ${pkgs.coreutils}/bin/env usr/bin/env
    printf 'root:x:0:0:root:/root:/bin/bash\nsandbox:x:10001:10001:Sandbox:/sandbox:/bin/bash\n' > etc/passwd
    printf 'root:x:0:\nsandbox:x:10001:\n' > etc/group
    cp -r ${sources}/. sandbox/workspace/project/
    ${pkgs.lib.optionalString (dependencies != null) dependencies.install}
    chmod -R u+rwX sandbox
    chown -R 10001:10001 sandbox
    # Codex discovers user skills here. Keep the complete bundle in the Nix store.
    mkdir -p sandbox/.agents
    ln -s ${audit} sandbox/.agents/skills
    chmod 1777 tmp
    ln -s ${runtime}/bin/ladyshell usr/local/bin/ladyshell
    ln -s ${codex}/bin/codex usr/local/bin/codex
    ln -s ${codex}/bin/codex-code-mode-host usr/local/bin/codex-code-mode-host
  '';
  config = {
    User = "10001:10001";
    WorkingDir = "/sandbox/workspace/project";
    Env = [ "PATH=/usr/local/bin:/bin" "HOME=/sandbox" "CODEX_HOME=/sandbox/.codex"
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "XDG_CACHE_HOME=/sandbox/workspace/cache"
      "CARGO_HOME=/sandbox/workspace/cache/cargo"
      "ZIG_GLOBAL_CACHE_DIR=/sandbox/workspace/cache/zig"
      "PKG_CONFIG_PATH=/usr/local/lib/ladyshell/pkgconfig"
      "LD_LIBRARY_PATH=/usr/local/lib/ladyshell" ];
    Cmd = [ "/bin/sleep" "infinity" ];
  };
}) // {
  ladyshellRuntimeRoots = runtimeRoots;
  ladyshellNetworkTools = networkTools;
}
