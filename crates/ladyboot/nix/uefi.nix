# EFI assets for bootupd's upstream component layout; no Secure Boot claim.
{ pkgs }:
let
  grub = pkgs.grub2_efi;
  shim = pkgs.shim-unsigned;
  metadata = pkgs.writeText "ladyboot-efi-metadata.json" (builtins.toJSON {
    timestamp = "1970-01-01T00:00:01Z";
    version = "grub2-${grub.version},shim-${shim.version}";
    versions = [
      { name = "grub2"; rpm_evr = grub.version; }
      { name = "shim"; rpm_evr = shim.version; }
    ];
    default-bootloader = "Grub";
  });
in pkgs.runCommand "ladyboot-uefi-1" {
  nativeBuildInputs = [ grub ];
} ''
  mkdir -p "$out/usr/lib/efi/grub2/${grub.version}/EFI/"{bootc-podman,BOOT}
  mkdir -p "$out/usr/lib/efi/shim/${shim.version}/EFI/"{bootc-podman,BOOT}
  cat > bootstrap.cfg <<'GRUB'
  configfile $prefix/grub.cfg
  GRUB
  grub-mkimage -O x86_64-efi -p /EFI/bootc-podman -c bootstrap.cfg \
    -o grubx64.efi part_gpt fat ext2 normal configfile linux blsuki \
    search search_fs_uuid search_label loadenv test serial terminal echo \
    reboot halt regexp efifwsetup all_video
  grub-file --is-x86_64-efi grubx64.efi
  for directory in bootc-podman BOOT; do
    cp grubx64.efi "$out/usr/lib/efi/grub2/${grub.version}/EFI/$directory/"
  done
  cp ${shim}/share/shim/shimx64.efi "$out/usr/lib/efi/shim/${shim.version}/EFI/bootc-podman/"
  cp ${shim}/share/shim/shimx64.efi "$out/usr/lib/efi/shim/${shim.version}/EFI/BOOT/BOOTX64.EFI"
  cp ${shim}/share/shim/mmx64.efi "$out/usr/lib/efi/shim/${shim.version}/EFI/bootc-podman/"
  mkdir -p "$out/usr/lib/bootupd/updates"
  cp ${metadata} "$out/usr/lib/bootupd/updates/EFI.json"
''
