# Scoped native security update; keep the pinned nixpkgs options and tests.
# Official 4.2.1 archive and detached signature verified on 2026-11-07 against
# publisher key DF46949295D2AA0F3479BF4A965B305B2BFAB54E.
# Fixes GHSA-h664-qxhh-gx3w. Packaging/attestation owners: review by 2026-12-07
# and remove this override when the locked upstream package passes the same checks.
{ pkgs, openssl ? import ./openssl.nix { inherit pkgs; },
  networkTools ? import ./network-tools.nix { inherit pkgs openssl; } }:
let
  inherit (networkTools) curl libssh2 libkrb5 ngtcp2;
  libtpms = pkgs.libtpms.override { inherit openssl; };
  swtpm = (pkgs.swtpm.override { inherit openssl libtpms; }).overrideAttrs (old: {
    # Python is used only by installed test scripts. Keep those scripts and
    # upstream checks, but do not make their interpreter a runtime dependency.
    outputs = old.outputs ++ [ "installedTests" ];
    postInstall = (old.postInstall or "") + ''
      moveToOutput libexec/installed-tests "$installedTests"
    '';
  });
in
(pkgs.tpm2-tss.override { inherit openssl libtpms swtpm curl; }).overrideAttrs (old:
  let
    # Release archives already contain configure and VERSION, but no bootstrap.
    # Drop only the Git-checkout version substitution, retaining every other
    # path/loader patch and the normal autoreconf/install-check hooks.
    bootstrapPatch = ''
      substituteInPlace ./bootstrap \
        --replace-fail 'git describe --tags --always --dirty' 'echo "4.2.1"'
    '';
  in {
    version = "4.2.1";
    src = pkgs.fetchurl {
      url = "https://github.com/tpm2-software/tpm2-tss/releases/download/4.2.1/tpm2-tss-4.2.1.tar.gz";
      sha256 = "d4aadbc1610876385a370494bbfd7d994356f446dff60cd09eea5933befb1471";
    };
    preAutoreconf = "";
    postPatch = assert pkgs.lib.hasInfix bootstrapPatch old.postPatch;
      pkgs.lib.replaceStrings [ bootstrapPatch ] [ "" ] old.postPatch;
    # Expose exactly the packages consumed above for native qualification.
    passthru = (old.passthru or { }) // {
      ladyshellNativeDependencies = { inherit curl swtpm libtpms libssh2 libkrb5 ngtcp2; };
    };
  })
