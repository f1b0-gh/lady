{ pkgs, rootfs }:
pkgs.runCommand "ladyboot-boot-test-rootfs" {
  __structuredAttrs = true;
  unsafeDiscardReferences.out = true;
  outputChecks.out.allowedReferences = [ ];
} ''
  cp -a ${rootfs} "$out"
  chmod u+w "$out/etc/systemd/system"
  rm "$out/etc/systemd/system/default.target"
  cat > "$out/etc/systemd/system/ladyboot-boot-test.target" <<'EOF'
  [Unit]
  Description=Disposable rootfs boot test
  Requires=multi-user.target ladyboot-boot-test.service
  After=multi-user.target
  EOF
  cat > "$out/etc/systemd/system/ladyboot-boot-test.service" <<'EOF'
  [Unit]
  Description=Verify PID1 and execute the installed bootc
  After=multi-user.target
  [Service]
  Type=oneshot
  StandardOutput=journal+console
  StandardError=journal+console
  ExecStart=/bin/sh -ec 'test "$(cat /proc/1/comm)" = systemd; /usr/bin/bootc --version; test -w /var; echo LADYBOOT_BOOT_OK'
  ExecStartPost=/usr/bin/systemctl poweroff --no-block
  EOF
  ln -s ladyboot-boot-test.target "$out/etc/systemd/system/default.target"
''
