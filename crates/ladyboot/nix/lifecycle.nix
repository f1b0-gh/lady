# Test-only installer: OCI conversion preserves production config/layer payloads.
{ pkgs, rootfs, imageV1, imageV2 }:
let
  skopeo = (import ./container-security.nix { inherit pkgs; }).skopeo;
  toOCI = image: revision: pkgs.runCommand "ladyboot-lifecycle-oci-${revision}.tar" {
    nativeBuildInputs = [ skopeo pkgs.python3 ];
  } ''
    skopeo --tmpdir "$TMPDIR" --policy ${rootfs}/etc/containers/policy.json copy \
      --format oci --dest-compress-format gzip \
      docker-archive:${image} oci-archive:"$out"
    python3 ${../tests/test_lifecycle_archive.py} ${image} "$out"
  '';
  ociV1 = toOCI imageV1 "1";
  ociV2 = toOCI imageV2 "2";
  closure = pkgs.closureInfo { rootPaths = [ pkgs.python3 ]; };
  smoke = pkgs.dockerTools.buildLayeredImage {
    name = "ladyboot-smoke"; tag = "1";
    contents = [ pkgs.busybox ];
    config.Cmd = [ "/bin/sh" ];
  };
in pkgs.runCommand "ladyboot-lifecycle-installer-rootfs" {
  __structuredAttrs = true;
  unsafeDiscardReferences.out = true;
  outputChecks.out.allowedReferences = [];
} ''
  cp -a ${rootfs} "$out"
  chmod -R u+w "$out"
  while read -r path; do
    if [ ! -e "$out/usr/lib/nix/store/$(basename "$path")" ]; then
      cp -a "$path" "$out/usr/lib/nix/store/"
    fi
  done < ${closure}/store-paths
  mkdir -p "$out/opt/qualification"
  cp ${ociV1} "$out/opt/qualification/os-v1.oci.tar"
  cp ${ociV2} "$out/opt/qualification/os-v2.oci.tar"
  cp ${smoke} "$out/opt/qualification/smoke.tar.gz"
  cp ${../tests/lifecycle_install.py} "$out/opt/qualification/lifecycle_install.py"
  cp ${../tests/lifecycle_guest.sh} "$out/opt/qualification/lifecycle_guest.sh"
  cat > "$out/etc/systemd/system/ladyboot-lifecycle-install.service" <<'UNIT'
  [Unit]
  Description=Disposable bootc installation qualification
  After=multi-user.target
  [Service]
  Type=oneshot
  Environment=PATH=/usr/bin
  ExecStart=${pkgs.python3}/bin/python3 /opt/qualification/lifecycle_install.py
  StandardOutput=journal+console
  StandardError=journal+console
  TimeoutStartSec=1100
  UNIT
  cat > "$out/etc/systemd/system/ladyboot-lifecycle-install.target" <<'UNIT'
  [Unit]
  Requires=multi-user.target ladyboot-lifecycle-install.service
  After=multi-user.target
  UNIT
  rm "$out/etc/systemd/system/default.target"
  ln -s ladyboot-lifecycle-install.target "$out/etc/systemd/system/default.target"
''
