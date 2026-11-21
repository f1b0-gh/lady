# Debug laboratory variant; identical identity and network policy.
{
  schema_version = 1,
  architecture = "x86_64-linux",
  os_id = "bootc-podman",
  revision = "1",
  needs = ["bootc-base", "virtio-vm", "podman-rootless", "network-runtime", "podman-debug", "diagnostics"],
  podman = {
    user = "containers", uid = 1000, gid = 1000,
    subuid_start = 65536, subgid_start = 65536, range_size = 65536,
  },
  network = {
    interface = "enp0s2",
    dns = ["192.0.2.1"],
    nts = [{ server = "nts.test", address = "192.0.2.1" }],
    egress = [{ address = "192.0.2.2", protocol = "tcp", port = 443 }],
    ingress = [{ address = "192.0.2.3", protocol = "tcp", port = 8080 }],
  },
}
