# Scoped upstream security corrections; see container-security.md and locks/.
# The nixpkgs revision and native runtime options remain unchanged.
{ pkgs }:
let
  go = import ./security-go.nix { inherit pkgs; };
  buildGoModule = pkgs.buildGoModule.override { inherit go; };
  skopeoSource = pkgs.fetchzip {
    extension = "tar.gz";
    url = "https://codeload.github.com/podman-container-tools/skopeo/tar.gz/1fb351f23dbde474416ba33c3786a8d04304429b";
    sha256 = "0m8kzdqqslw0lg327pblhmalnwjlhnqk1j7jps8c56a1rmdif7rm";
  };
  skopeoPolicy = pkgs.runCommand "skopeo-1.25.1-policy" {} ''
    install ${skopeoSource}/default-policy.json -Dt "$out"
  '';
  skopeo = (pkgs.skopeo.override { inherit buildGoModule; }).overrideAttrs (old: {
    version = "1.25.1";
    src = skopeoSource;
    deleteVendor = true;
    vendorHash = "sha256-ze1mb98Rz6VIuG75Ie//eKafUwsQhG/FeZixKPzAq58=";
    postPatch = (old.postPatch or "") + ''
      cp ${./locks/skopeo.go.mod} go.mod
      cp ${./locks/skopeo.go.sum} go.sum
    '';
    installPhase = pkgs.lib.replaceStrings [ "${old.passthru.policy}" ] [ "${skopeoPolicy}" ] old.installPhase;
    passthru = old.passthru // { policy = skopeoPolicy; };
    env = (old.env or {}) // { GOMAXPROCS = "2"; GOTOOLCHAIN = "local"; };
  });
  criu = pkgs.criu.overrideAttrs (old: {
    version = "4.3.1";
    src = pkgs.fetchzip {
      extension = "tar.gz";
      url = "https://codeload.github.com/checkpoint-restore/criu/tar.gz/3ce556b7e8291c1bfdca974962f6282d7802b69f";
      sha256 = "0wwg43lgyyjl4zj6pc1ydbqys75a7ki2pl3x1q93k7bl7v7r8vmv";
    };
    # Both nixpkgs compatibility patches are already present upstream.
    patches = [];
    # Upstream's new descriptor rule hardcodes /usr/include; use the pinned
    # protobuf headers already selected by the Nixpkgs recipe.
    postPatch = old.postPatch + ''
      substituteInPlace images/Makefile \
        --replace-fail '--proto_path=/usr/include' '--proto_path=${pkgs.lib.getDev pkgs.protobuf}/include'
    '';
  });
  crun = (pkgs.crun.override { inherit criu; }).overrideAttrs (old: {
    version = "1.31";
    src = pkgs.fetchurl {
      url = "https://github.com/containers/crun/releases/download/1.31/crun-1.31.tar.gz";
      sha256 = "17d04ba159fada1f1300a36b8afe869afb38bf1bbda28da052e83bb4bee20108";
    };
    # The official release bundles submodules and records this commit in
    # .tarball-git-version.h; retain nixpkgs' header and test setup.
    postPatch = ''
      printf '%s\n' a84965e1278d08d6c75d5b8a41a3e72a7a11fa5b > COMMIT
    '' + old.postPatch;
  });
  runc = (pkgs.runc.override { inherit buildGoModule; }).overrideAttrs (old: {
    deleteVendor = true;
    version = "1.5.3";
    src = pkgs.fetchzip {
      extension = "tar.gz";
      url = "https://codeload.github.com/opencontainers/runc/tar.gz/46365c62967c76a765a5e347f48f0c7b3b571fe9";
      sha256 = "16dd4nd238nkrv63qmc3c4d6vj7l8ybqpnvl1hbmapr3s9kcn5p0";
    };
    vendorHash = "sha256-7EGNebs0DIeAQx1QshbdZV+2o8N/zol35iSbrPXIbSY=";
    postPatch = (old.postPatch or "") + ''
      cp ${./locks/runc.go.mod} go.mod
      cp ${./locks/runc.go.sum} go.sum
    '';
    env = (old.env or {}) // { GOMAXPROCS = "2"; GOTOOLCHAIN = "local"; };
  });
  podmanFor = { crun, extraRuntimes }:
    (pkgs.podman.override { inherit buildGoModule crun extraRuntimes; }).overrideAttrs (old: {
      version = "6.2.0";
      src = pkgs.fetchzip {
    extension = "tar.gz";
        url = "https://codeload.github.com/podman-container-tools/podman/tar.gz/055de046937d29450f310fce0fe3071485d8bed9";
        sha256 = "1mi9ffqr5w3f09yq6sjj1kaif3xj989dzvk8qiwf8j52kgfk6kfx";
      };
      # Keep nixpkgs' mac-helper packaging patch. Its completion fix is now
      # upstream; apply its runtime-path patch AFTER the new vendor is copied.
      patches = [ (builtins.elemAt old.patches 1) ];
      deleteVendor = true;
      vendorHash = "sha256-Aq2TRC6UkgYpV6XHVkrcYVh4tX5DnOpOFxZID6ui/1A=";
      postPatch = (old.postPatch or "") + ''
        cp ${./locks/podman.go.mod} go.mod
        cp ${./locks/podman.go.sum} go.sum
      '';
      postConfigure = (old.postConfigure or "") + ''
        chmod u+w vendor/go.podman.io/common/pkg/config vendor/go.podman.io/common/pkg/config/default.go
        patch -p1 < ${builtins.head old.patches}
      '';
      env = old.env // { GOMAXPROCS = "2"; GOTOOLCHAIN = "local"; };
    });
in { inherit go buildGoModule skopeo runc criu crun podmanFor; }
