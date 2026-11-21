# Closed IPv4 site configuration, installed before link activation.
{ pkgs, profile, resolved }:
let
  inherit (pkgs) lib;
  n = profile.network;
  rules = flows: direction: lib.concatMapStringsSep "\n" (flow:
    "ip ${direction} ${flow.address} ${flow.protocol} dport ${toString flow.port} accept") flows;
  dns = lib.concatMapStringsSep "\n" (ip: "ip daddr ${ip} udp dport 53 accept\nip daddr ${ip} tcp dport 53 accept") n.dns;
  nts = lib.concatMapStringsSep "\n" (source: "ip daddr ${source.address} udp dport 123 accept\nip daddr ${source.address} tcp dport 4460 accept") n.nts;
in ''
  ${import ./time-sync.nix { inherit pkgs profile resolved; }}
  mkdir -p "$out/etc/systemd/network" "$out/etc/systemd/resolved.conf.d"
  mkdir -p "$out/etc/systemd/system/systemd-networkd.service.d" "$out/usr/lib/sysctl.d"
  cat > "$out/etc/systemd/network/10-ladyboot.network" <<'NETWORK'
  [Match]
  Name=${n.interface}
  [Network]
  DHCP=ipv4
  IPv6AcceptRA=no
  LinkLocalAddressing=no
  LLDP=no
  EmitLLDP=no
  [DHCPv4]
  UseDNS=no
  UseNTP=no
  UseHostname=no
  NETWORK
  cat > "$out/etc/systemd/resolved.conf.d/10-site.conf" <<'DNS'
  [Resolve]
  DNS=${lib.concatStringsSep " " n.dns}
  FallbackDNS=
  LLMNR=no
  MulticastDNS=no
  DNS
  ln -s /run/systemd/resolve/stub-resolv.conf "$out/etc/resolv.conf"
  cat > "$out/etc/nftables.conf" <<'FIREWALL'
  destroy table inet ladyboot
  table inet ladyboot {
    chain input {
      type filter hook input priority 0; policy drop;
      iifname "lo" accept
      meta nfproto ipv6 drop
      ct state invalid drop
      ct state established,related accept
      iifname "${n.interface}" udp sport 67 udp dport 68 accept
      ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
      iifname "${n.interface}" jump site_input
    }
    chain output {
      type filter hook output priority 0; policy drop;
      oifname "lo" accept
      meta nfproto ipv6 drop
      ct state invalid drop
      ct state established,related accept
      oifname "${n.interface}" udp sport 68 udp dport 67 accept
      ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
      oifname "${n.interface}" jump site_output
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain site_input {
      ${rules n.ingress "saddr"}
    }
    chain site_output {
      ${dns}
      ${nts}
      ${rules n.egress "daddr"}
    }
  }
  FIREWALL
  cat > "$out/usr/lib/systemd/system/ladyboot-firewall.service" <<'UNIT'
  [Unit]
  Description=Explicit IPv4 site policy before link activation
  DefaultDependencies=no
  After=local-fs.target systemd-sysctl.service
  Before=network-pre.target
  Wants=network-pre.target
  [Service]
  Type=oneshot
  ExecStart=/usr/bin/nft -f /etc/nftables.conf
  RemainAfterExit=yes
  UNIT
  cat > "$out/etc/systemd/system/systemd-networkd.service.d/10-firewall.conf" <<'UNIT'
  [Unit]
  Requires=ladyboot-firewall.service
  After=ladyboot-firewall.service
  UNIT
  printf 'net.ipv4.ip_forward=0\nnet.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n' > "$out/usr/lib/sysctl.d/50-ladyboot.conf"
  for unit in ladyboot-firewall systemd-networkd systemd-resolved; do
    ln -s /usr/lib/systemd/system/$unit.service "$out/etc/systemd/system/multi-user.target.wants/$unit.service"
  done
  mkdir -p "$out/etc/systemd/system/network-online.target.requires"
  cat > "$out/usr/lib/systemd/system/ladyboot-network-online.service" <<'UNIT'
  [Unit]
  Description=Bounded IPv4 readiness for the declared runtime interface
  Requires=systemd-networkd.service
  After=systemd-networkd.service
  Before=network-online.target
  [Service]
  Type=oneshot
  ExecStart=${resolved.systemd}/lib/systemd/systemd-networkd-wait-online --interface=${n.interface} --ipv4 --timeout=60
  TimeoutStartSec=65
  RemainAfterExit=yes
  UNIT
  ln -s /usr/lib/systemd/system/ladyboot-network-online.service "$out/etc/systemd/system/network-online.target.requires/ladyboot-network-online.service"
  printf 'hosts: files dns\npasswd: files\ngroup: files\n' > "$out/etc/nsswitch.conf"
''
