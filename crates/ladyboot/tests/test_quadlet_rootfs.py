"""Check Quadlet's delivered dependency and bounded system network readiness."""
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
plan = json.loads((root / 'usr/share/ladyboot/plan.json').read_text())
unit = root / 'usr/lib/systemd/user/podman-user-wait-network-online.service'
assert unit.is_file(), 'Quadlet user network dependency is missing'
packages = {p['selection']: p['store_path'] for p in plan['runtime_packages']}
vendor = root / 'usr/lib/nix/store' / Path(packages['podman']).name / 'share/systemd/user' / unit.name
assert unit.read_bytes() == vendor.read_bytes(), 'Keep the pinned Podman user wait unit unchanged'
assert (root / 'etc/systemd/system/multi-user.target.wants/network-online.target').readlink().as_posix() == '/usr/lib/systemd/system/network-online.target'
if 'network-runtime' in plan['requested']['needs']:
    ready = 'ladyboot-network-online.service'
    assert (root / f'etc/systemd/system/network-online.target.requires/{ready}').readlink().as_posix() == f'/usr/lib/systemd/system/{ready}'
    content = (root / f'usr/lib/systemd/system/{ready}').read_text()
    assert 'Requires=systemd-networkd.service' in content
    assert f"--interface={plan['requested']['network']['interface']}" in content
    assert '--ipv4' in content and '--timeout=60' in content
    assert 'TimeoutStartSec=65' in content
    assert any(s['name'] == ready and s['origin'] == 'network-runtime' for s in plan['enabled_services'])
print('Quadlet dependency and bounded network readiness layout verified')
