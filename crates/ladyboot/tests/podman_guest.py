"""Disposable guest checks. This file is never installed in the production OS."""
import json
import os
from pathlib import Path
import subprocess
import time
import sys
import traceback

plan = json.loads(Path('/usr/share/ladyboot/plan.json').read_text())
p = plan['requested']['podman']
uid, gid, user = p['uid'], p['gid'], p['user']
home = Path(f'/var/home/{user}')

def run(args, *, user_mode=False, expected=0, timeout=90):
    if user_mode:
        args = ['setpriv', f'--reuid={uid}', f'--regid={gid}', '--init-groups',
                'env', '-i', f'USER={user}', f'LOGNAME={user}', f'HOME={home}', f'XDG_RUNTIME_DIR=/run/user/{uid}',
                f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus', 'PATH=/usr/bin', *args]
    print(json.dumps({'event': 'start', 'command': args, 'timeout_seconds': timeout}), flush=True)
    try:
        result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        output = error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else error.stdout
        print(json.dumps({'event': 'timeout', 'command': args, 'timeout_seconds': timeout, 'output': output}), flush=True)
        raise
    print(json.dumps({'command': args, 'returncode': result.returncode, 'output': result.stdout}), flush=True)
    if expected is not None and result.returncode != expected:
        raise AssertionError(f'{args}: {result.returncode}: {result.stdout}')
    return result


def main():
    run(['systemctl', 'is-active', f'user@{uid}.service'])
    run(['systemctl', '--user', 'is-active', 'dbus.socket'], user_mode=True)
    for helper in ['newuidmap', 'newgidmap']:
        m = Path(f'/run/ladyboot-helpers/{helper}').stat()
        assert m.st_uid == 0 and m.st_mode & 0o7777 == 0o4755
    info = json.loads(run(['podman', 'info', '--format=json'], user_mode=True).stdout)
    assert info['host']['security']['rootless'] is True
    assert info['host']['cgroupVersion'] == 'v2'
    assert info['store']['graphDriverName'] == 'overlay'
    assert info['store']['graphRoot'] == str(home / '.local/share/containers/storage')
    assert info['store']['runRoot'] == f'/run/user/{uid}/containers'
    # Image decompression/copy is CPU-heavy under the bounded TCG test VM.
    run(['podman', 'load', '--input', '/opt/qualification/smoke.tar.gz'], user_mode=True, timeout=300)
    probe = run(['podman', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=all',
                 '--memory=64m', '--pids-limit=32', 'localhost/ladyboot-smoke:1',
                 '/bin/sh', '-ec', 'cat /proc/self/uid_map; cat /proc/self/status; cat /sys/fs/cgroup/pids.max; cat /sys/fs/cgroup/memory.max'], user_mode=True).stdout
    assert 'Seccomp:\t2' in probe
    assert 'CapEff:\t0000000000000000' in probe
    assert 'CapBnd:\t0000000000000000' in probe
    assert '67108864' in probe and '\n32\n' in probe
    mappings = [line.split() for line in probe.splitlines() if len(line.split()) == 3 and all(x.isdecimal() for x in line.split())]
    assert ['0', str(uid), '1'] in mappings
    assert any(row[1] == str(p['subuid_start']) and int(row[2]) > 1 for row in mappings)
    if plan['runtime_variant'] == 'debug':
        runtime_info = json.loads(run(['podman', '--runtime=runc', 'info', '--format=json'], user_mode=True).stdout)
        runtime = runtime_info['host']['ociRuntime']
        assert runtime['name'] == 'runc'
        assert runtime['version'].splitlines()[0] == 'runc version 1.5.3'
        optional = run(['podman', '--runtime=runc', 'run', '--rm', '--pull=never',
                        '--network=none', '--cap-drop=all', '--memory=64m', '--pids-limit=32',
                        'localhost/ladyboot-smoke:1', '/bin/sh', '-ec',
                        'cat /proc/self/uid_map; cat /proc/self/status'], user_mode=True).stdout
        assert 'Seccomp:\t2' in optional and 'CapEff:\t0000000000000000' in optional
        optional_maps = [line.split() for line in optional.splitlines()
                         if len(line.split()) == 3 and all(x.isdecimal() for x in line.split())]
        assert ['0', str(uid), '1'] in optional_maps
        print('LADYBOOT_RUNC_OK', flush=True)
    unit_dir = home / '.config/containers/systemd'
    unit_dir.mkdir(parents=True)
    for directory in [home / '.config', home / '.config/containers', unit_dir]:
        os.chown(directory, uid, gid)
    unit = unit_dir / 'probe.container'
    # This fixture has no NIC and explicitly uses Network=none.
    unit.write_text('''[Quadlet]
DefaultDependencies=false
[Container]
Image=localhost/ladyboot-smoke:1
ContainerName=bootc-podman-probe
Pull=never
Network=none
Exec=/bin/sleep 600
PodmanArgs=--replace=false --cidfile=%t/bootc-podman-probe.cid --memory=64m --pids-limit=32
[Service]
TimeoutStartSec=90
''')
    os.chown(unit, uid, gid)
    # Quadlet appends cleanup by name to generated units. A service drop-in
    # overrides that cleanup after generation and targets only our recorded ID.
    dropin_dir = home / '.config/systemd/user/probe.service.d'
    dropin_dir.mkdir(parents=True)
    for directory in [home / '.config/systemd', home / '.config/systemd/user', dropin_dir]:
        os.chown(directory, uid, gid)
    dropin = dropin_dir / '10-owned-cleanup.conf'
    dropin.write_text('''[Service]
ExecStop=
ExecStop=/usr/bin/podman rm --force --ignore --volumes --cidfile=%t/bootc-podman-probe.cid
ExecStopPost=
ExecStopPost=-/usr/bin/podman rm --force --ignore --volumes --cidfile=%t/bootc-podman-probe.cid
''')
    os.chown(dropin, uid, gid)
    run(['systemctl', '--user', 'daemon-reload'], user_mode=True)
    cidfile = Path(f'/run/user/{uid}/bootc-podman-probe.cid')
    for _ in range(2):
        assert not cidfile.exists()
        run(['systemctl', '--user', 'start', 'probe.service'], user_mode=True)
        run(['systemctl', '--user', 'is-active', 'probe.service'], user_mode=True)
        active = run(['podman', 'inspect', '--format={{.Id}}', 'bootc-podman-probe'], user_mode=True).stdout.strip()
        assert cidfile.read_text().strip() == active
        run(['systemctl', '--user', 'stop', 'probe.service'], user_mode=True)
        assert not cidfile.exists()
        assert run(['podman', 'container', 'exists', 'bootc-podman-probe'], user_mode=True, expected=None).returncode == 1
    foreign = run(['podman', 'create', '--name=bootc-podman-probe', '--network=none',
                   'localhost/ladyboot-smoke:1', '/bin/sleep', '600'], user_mode=True).stdout.strip()
    assert run(['systemctl', '--user', 'start', 'probe.service'], user_mode=True, expected=None).returncode != 0
    remaining = run(['podman', 'inspect', '--format={{.Id}}', 'bootc-podman-probe'], user_mode=True).stdout.strip()
    assert remaining == foreign
    assert not cidfile.exists()
    print('LADYBOOT_PODMAN_OK', flush=True)

try:
    main()
except Exception:
    traceback.print_exc()
    sys.stderr.flush()
    run(['systemctl', '--failed'], expected=None)
    run(['journalctl', '-b', '--no-pager', '-n', '120'], expected=None)
    raise
finally:
    run(['systemctl', 'poweroff', '--no-block'], expected=None)
