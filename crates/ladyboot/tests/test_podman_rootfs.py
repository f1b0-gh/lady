"""Check the delivered rootless OS integration, not just Nix references."""
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
plan = json.loads((root / 'usr/share/ladyboot/plan.json').read_text())
assert (root / 'usr/bin/podman').is_symlink(), 'Podman is absent from the delivered OS'
assert plan['requested']['os_id'] == 'bootc-podman'
p = plan['requested']['podman']
assert (root / 'etc/subuid').read_text() == f"{p['user']}:{p['subuid_start']}:{p['range_size']}\n"
assert (root / 'etc/subgid').read_text() == f"{p['user']}:{p['subgid_start']}:{p['range_size']}\n"
assert (root / 'usr/lib/systemd/user-generators/podman-user-generator').is_symlink()
for name in ['podman', 'crun', 'conmon', 'pasta', 'agetty']:
    assert (root / f'usr/bin/{name}').is_symlink(), name
for path in ['usr/lib/systemd/user/dbus.service', 'usr/lib/systemd/user/dbus.socket',
             'etc/pam.d/systemd-user', 'etc/containers/policy.json',
             'etc/containers/storage.conf', 'etc/containers/containers.conf',
             'usr/lib/systemd/system/ladyboot-podman-init.service']:
    assert (root / path).is_file(), path
helper = root / 'usr/libexec/ladyboot-podman-init'
assert helper.is_symlink()
target = helper.readlink().as_posix()
assert target.startswith('/nix/store/')
assert (root / 'usr/lib/nix/store' / target.removeprefix('/nix/store/')).is_file()
assert not (root / 'etc/systemd/system/sockets.target.wants/podman.socket').exists()
assert not (root / 'usr/bin/nix').exists()
assert not (root / 'usr/bin/cargo').exists()
assert not (root / 'usr/bin/nickel').exists()
policy = json.loads((root / 'etc/containers/policy.json').read_text())
assert policy['default'] == [{'type': 'reject'}]
for directory in ['etc/containers/systemd', 'usr/share/containers/systemd']:
    assert not list((root / directory).glob('*.container'))
print('Delivered rootless integration verified')

for kind in ['system', 'user']:
    service = (root / f'usr/lib/systemd/{kind}/dbus.service').read_text()
    config = service.split('--config-file=', 1)[1].split()[0]
    assert config.startswith('/nix/store/')
    assert (root / 'usr/lib/nix/store' / config.removeprefix('/nix/store/')).is_file()

import tomllib
storage = tomllib.loads((root / 'etc/containers/storage.rootless.conf.d/10-ladyboot.conf').read_text())['storage']
assert storage['graphroot'] == f"/var/home/{p['user']}/.local/share/containers/storage"
assert storage['runroot'] == f"/run/user/{p['uid']}/containers"

variant = plan['runtime_variant']
names = [path.name[33:] for path in (root / 'usr/lib/nix/store').iterdir()]
for package in ['python3-', 'criu-', 'libkrun-', 'libkrunfw-', 'runc-']:
    assert any(name.startswith(package) for name in names) == (variant == 'debug'), package

packages = {package['selection']: package['store_path'] for package in plan['runtime_packages']}
for command in ['podman', 'crun']:
    assert (root / 'usr/bin' / command).readlink().as_posix() == f"{packages[command]}/bin/{command}"
assert (root / 'usr/lib/systemd/user-generators/podman-user-generator').readlink().as_posix() == f"{packages['podman']}/libexec/podman/quadlet"
