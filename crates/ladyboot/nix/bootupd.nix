# Upstream source is unchanged. The separately retained build lock carries the
# scoped RustSec corrections documented in bootupd-dependencies.md.
{ pkgs }:
pkgs.rustPlatform.buildRustPackage {
  pname = "bootupd";
  version = "0.3.2";
  src = pkgs.fetchurl {
    name = "bootupd-0.3.2.tar.gz";
    url = "https://codeload.github.com/coreos/bootupd/tar.gz/refs/tags/v0.3.2";
    sha256 = "7323519fb230d0508e6a9ccbd65763d735fd6af713725aead6c3f015544c48fe";
  };
  cargoLock.lockFile = ./bootupd-Cargo.lock;
  postPatch = ''cp ${./bootupd-Cargo.lock} Cargo.lock'';
  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ pkgs.openssl ];
  # This upstream test reads the build host's /etc/os-release. Nix supplies
  # no host OS identity; exercise product-name lookup in the installation VM.
  checkFlags = [ "--skip=efi::tests::test_get_product_name" ];
  postInstall = ''
    ln -s bootupd "$out/bin/bootupctl"
    make install-grub-static PREFIX="$out"
  '';
  meta = {
    description = "Bootloader updater for the explicit Ladyboot UEFI image";
    homepage = "https://github.com/coreos/bootupd";
    license = pkgs.lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
  };
}
