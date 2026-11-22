# Fixed native carrier; application versions arrive as separately admitted WASI components.
{ pkgs, openssl, configPath, sourcePath, brokerPath, runtimePath }:
let
  cfg = builtins.fromJSON (builtins.readFile configPath);
  checked = cfg.image.backend == "nix" && cfg.image.profile == "openshell-wasi"
    && cfg.image.platform == "x86_64-linux" && cfg.tools == {} && cfg.checks == []
    && !(cfg.sandbox ? provider) && cfg ? storage
    && !(cfg ? dependencies) && !(cfg ? audit)
    && cfg.permissions.network == [] && cfg.permissions.filesystem == [];
  broker = pkgs.runCommand "ladyshell-lo-executor" {
    nativeBuildInputs = [ pkgs.autoPatchelfHook ];
    buildInputs = [ pkgs.stdenv.cc.cc.lib openssl ];
  } ''
    mkdir -p $out/bin
    cp ${builtins.path { path = brokerPath; name = "lo-executor-worker"; }} $out/bin/lo-executor-worker
    chmod 755 $out/bin/lo-executor-worker
    autoPatchelf $out
  '';
  runtime = pkgs.runCommand "ladyshell-broker-runtime" {
    nativeBuildInputs = [ pkgs.autoPatchelfHook ];
    buildInputs = [ pkgs.stdenv.cc.cc.lib ];
  } ''
    mkdir -p $out/bin
    cp ${builtins.path { path = runtimePath; name = "ladyshell"; }} $out/bin/ladyshell
    chmod 755 $out/bin/ladyshell
    autoPatchelf $out
  '';
  base = pkgs.buildEnv {
    name = "ladyshell-broker-root";
    paths = [ pkgs.bashInteractive pkgs.coreutils broker runtime ];
    pathsToLink = [ "/bin" "/etc" ];
  };
  sources = builtins.path { path = sourcePath; name = "broker-project-sources"; };
in assert checked; pkgs.dockerTools.buildLayeredImage {
  name = "ladyshell-${cfg.name}-broker";
  tag = "nix";
  contents = [ base ];
  fakeRootCommands = ''
    mkdir -p etc tmp sandbox/workspace/project usr/local/bin usr/bin var/lib/ladyshell/broker
    ln -s ${pkgs.coreutils}/bin/env usr/bin/env
    printf 'root:x:0:0:root:/root:/bin/bash\nsandbox:x:10001:10001:Sandbox:/sandbox:/bin/bash\n' > etc/passwd
    printf 'root:x:0:\nsandbox:x:10001:\n' > etc/group
    cp -r ${sources}/. sandbox/workspace/project/
    chmod -R a-w sandbox
    # OpenShell checks POSIX workspace writes before applying workload Landlock.
    # The workload policy grants only reads here; all writes stay on capped roots.
    chown 10001:10001 sandbox/workspace/project
    chmod 0755 sandbox/workspace/project
    chmod 1777 tmp
    for area in control artifacts incoming; do
      mkdir -p var/lib/ladyshell/broker/$area
      chmod 0700 var/lib/ladyshell/broker/$area
      chown 10001:10001 var/lib/ladyshell/broker/$area
    done
    ln -s ${runtime}/bin/ladyshell usr/local/bin/ladyshell
    ln -s ${broker}/bin/lo-executor-worker usr/local/bin/lo-executor-worker
  '';
  config = {
    User = "10001:10001";
    Labels = {
      "ladyshell.image.profile" = "openshell-wasi";
      "ladyshell.broker.binary" = "${broker}/bin/lo-executor-worker";
    };
    WorkingDir = "/sandbox/workspace/project";
    Env = [ "PATH=/usr/local/bin:/bin" "HOME=/sandbox" ];
    Cmd = [ "/bin/sleep" "infinity" ];
  };
}
