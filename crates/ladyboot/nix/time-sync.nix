# Client-only authenticated time. No source discovery or plain-NTP fallback.
{ pkgs, profile, resolved }:
let
  inherit (pkgs) lib;
  sources = lib.concatMapStringsSep "\n" (source: ''
    [[source]]
    mode = "nts"
    enable-srv-resolution = false
    address = "${source.server}:4460"
    expected-ntp-address = "${source.address}:123"
    certificate-authority = "/etc/ssl/certs/ca-certificates.crt"
  '') profile.network.nts;
  hosts = lib.concatMapStringsSep "\n" (source: "${source.address} ${source.server}") profile.network.nts;
in ''
  mkdir -p "$out/etc/ntpd-rs"
  cat > "$out/etc/ntpd-rs/ntp.toml" <<'NTS'
  ${sources}
  [synchronization]
  minimum-agreeing-sources = 1
  single-step-panic-threshold = { forward = 1800, backward = 1800 }
  startup-step-panic-threshold = { forward = 1800, backward = 1800 }
  [observability]
  log-level = "info"
  observation-path = "/run/ntpd-rs/observe"
  observation-permissions = 0o600
  NTS
  cat >> "$out/etc/hosts" <<'HOSTS'
  ${hosts}
  HOSTS
  # The binary is also compiled out: a retained old /etc unit cannot run it.
  ln -s /dev/null "$out/etc/systemd/system/systemd-timesyncd.service"
  cat > "$out/usr/lib/systemd/system/ntpd-rs.service" <<'UNIT'
  [Unit]
  Description=Authenticated time from explicitly configured NTS sources
  Wants=network-online.target
  After=network-online.target
  Conflicts=systemd-timesyncd.service
  [Service]
  Type=notify
  ExecStart=${resolved.catalog.ntpd-rs}/bin/ntp-daemon --config=/etc/ntpd-rs/ntp.toml
  Environment=SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
  UnsetEnvironment=SSL_CERT_DIR
  User=ntpd-rs
  DynamicUser=yes
  RuntimeDirectory=ntpd-rs
  RuntimeDirectoryMode=0700
  UMask=0077
  AmbientCapabilities=CAP_SYS_TIME
  CapabilityBoundingSet=CAP_SYS_TIME
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectKernelLogs=yes
  ProtectControlGroups=yes
  RestrictSUIDSGID=yes
  RestrictRealtime=yes
  # Required by timestamped-socket interface change detection, without NET_ADMIN.
  RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK
  LockPersonality=yes
  MemoryDenyWriteExecute=yes
  TasksMax=64
  MemoryMax=256M
  LimitNOFILE=512
  TimeoutStartSec=60
  TimeoutStopSec=15
  # A panic threshold requires administrator intervention; never restart-loop
  # a daemon that refused to adjust the clock.
  Restart=no
  UNIT
  ln -s /usr/lib/systemd/system/ntpd-rs.service "$out/etc/systemd/system/multi-user.target.wants/ntpd-rs.service"
''
