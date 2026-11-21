# Build variants of the pinned runtime with scoped security corrections.
{ pkgs, debug ? false }:
let
  security = import ./container-security.nix { inherit pkgs; };
  minimalCrun = (security.crun.override { withLibkrun = false; }).overrideAttrs (old: {
    buildInputs = builtins.filter (p: p != security.criu) old.buildInputs;
    configureFlags = old.configureFlags ++ [ "--disable-criu" ];
    env = old.env // {
      NIX_LDFLAGS = pkgs.lib.replaceStrings [ "-lcriu" ] [ "" ] old.env.NIX_LDFLAGS;
    };
  });
  crun = if debug then security.crun else minimalCrun;
  podman = security.podmanFor {
    inherit crun;
    extraRuntimes = pkgs.lib.optional debug security.runc;
  };
in { inherit crun podman; }
