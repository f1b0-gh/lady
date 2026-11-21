"""Check custom generators against the pinned systemd binary's search paths."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
plan = json.loads((root / 'usr/share/ladyboot/plan.json').read_text())
packages = {p['selection']: p['store_path'] for p in plan['runtime_packages']}
expected = [('system', 'ostree-system-generator')]
if 'podman-rootless' in plan['requested']['needs']:
    expected.append(('user', 'podman-user-generator'))
aliases = {}
for kind, name in expected:
    directory = f'/etc/systemd/{kind}-generators'
    search = subprocess.check_output(
        [packages['systemd'] + '/bin/systemd-path', f'systemd-search-{kind}-generator'],
        text=True, env={}, timeout=10).strip().split(':')
    assert directory in search, (directory, search)
    path = f'etc/systemd/{kind}-generators/{name}'
    target = f'/usr/lib/systemd/{kind}-generators/{name}'
    alias = root / path
    assert alias.is_symlink(), f'Generator is outside the native search path: {name}'
    assert alias.readlink().as_posix() == target
    delivered = root / target.lstrip('/')
    if delivered.is_symlink():
        native = delivered.readlink().as_posix()
        assert native.startswith('/nix/store/')
        delivered = root / 'usr/lib/nix/store' / native.removeprefix('/nix/store/')
    assert delivered.is_file() and not delivered.is_symlink(), delivered
    assert delivered.stat().st_mode & 0o111, f"Generator is not executable: {delivered}"
    aliases[path] = target
assert {row['path']: row['target'] for row in plan['generator_aliases']} == aliases
print('Custom generators are reachable through native systemd search paths')
