"""Assertions against realized files, independent of Nix closure references."""
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
plan = json.loads((root / 'usr/share/ladyboot/plan.json').read_text())
needs = plan['requested']['needs']
manifest = json.loads((root / 'usr/share/ladyboot/inventory.json').read_text())
assert manifest['resolved_plan'] == plan
assert len(list((root / 'usr/lib/modules').glob('*/vmlinuz'))) == 1
assert len(list((root / 'usr/lib/modules').glob('*/initramfs.img'))) == 1
assert not (root / 'usr/bin/python3').exists()
for service, required in [('systemd-networkd', 'network-dhcp'), ('ladyboot-firewall', 'network-dhcp'), ('qemu-guest-agent', 'qemu-agent')]:
    selected = required in needs or (required == 'network-dhcp' and 'network-runtime' in needs)
    assert (root / f'etc/systemd/system/multi-user.target.wants/{service}.service').is_symlink() == selected
expected = {row['name'] for row in plan['enabled_services']}
actual = {p.name for directory in ['etc/systemd/system', 'usr/lib/systemd/system'] for pattern in ['*.wants/*.service', '*.requires/*.service'] for p in (root / directory).glob(pattern)}
assert actual == expected, (actual, expected)
assert (root / 'etc/nftables.conf').exists() == ('network-dhcp' in needs or 'network-runtime' in needs)
print('Observed rootfs layout and explicit service selections verified')

expected_links = {row['path'] for row in plan['vendor_unit_links']}
actual_links = {p.relative_to(root).as_posix() for p in (root / 'usr/lib/systemd/system').glob('*.wants/*') if p.is_symlink()}
assert actual_links == expected_links, (sorted(actual_links - expected_links), sorted(expected_links - actual_links))
