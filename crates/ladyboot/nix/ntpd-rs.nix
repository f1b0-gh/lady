# Pinned source with a bounded endpoint-policy correction and separately
# reviewed dependency lock; provenance/cost in ntpd-rs-dependencies.md.
{ pkgs }:
pkgs.ntpd-rs.overrideAttrs (old: {
  # Upstream release debug=2 inflates disposable build outputs. Keep release
  # optimization/LTO and runtime assertions unchanged; Nix strips delivered bins.
  env = (old.env or {}) // { CARGO_PROFILE_RELEASE_DEBUG = "0"; };
  patches = (old.patches or []) ++ [ ./ntpd-rs-pin-endpoint.patch ];
  # This upstream test binds [::]:0. IPv6 is unavailable in the native Nix
  # sandbox; keep isolation and qualify direct-name NTS over IPv4 in our VM.
  checkFlags = (old.checkFlags or []) ++ [
    "--skip=daemon::spawn::nts::tests::direct_name_resolution"
  ];
  cargoDeps = pkgs.rustPlatform.importCargoLock {
    lockFile = ./ntpd-rs-Cargo.lock;
  };
  postPatch = (old.postPatch or "") + ''
    cp ${./ntpd-rs-Cargo.lock} Cargo.lock
  '';
})
