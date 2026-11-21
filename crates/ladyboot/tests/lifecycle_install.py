"""Install the production archive onto the newly created second guest disk."""
import json
import re
from pathlib import Path
import shutil
import subprocess
import traceback


def run(command, timeout=120):
    print(json.dumps({'event': 'start', 'command': command, 'timeout': timeout}), flush=True)
    subprocess.run(command, check=True, timeout=timeout)


def main():
    assert Path('/sys/firmware/efi').is_dir(), 'installer must boot with UEFI'
    devices = json.loads(subprocess.check_output(
        ['lsblk', '--json', '--bytes', '--nodeps', '--output', 'PATH,SERIAL,SIZE'],
        text=True, timeout=10))['blockdevices']
    # SCSI probing is asynchronous: /dev/sda and /dev/sdb can swap names.
    targets = [device for device in devices if device['serial'] == 'ladyboot-target']
    assert len(targets) == 1, 'expected exactly one explicitly identified target'
    target_device = targets[0]['path']
    assert re.fullmatch(r'/dev/sd[a-z]+', target_device), 'expected a whole SCSI disk'
    assert int(targets[0]['size']) == 16 * 1024**3
    name = target_device.removeprefix('/dev/')
    assert not list(Path('/sys/block/' + name).glob(name + '[0-9]*')), 'target is not blank'
    source = '/opt/qualification/os-v1.oci.tar'
    target = '/var/lib/ladyboot-qualification/current.oci.tar'
    run(['bootc', 'install', 'to-disk', '--filesystem=ext4',
         '--source-imgref=oci-archive:' + source, '--target-transport=oci-archive',
         '--target-imgref=' + target, '--karg=console=ttyS0', target_device], timeout=900)
    mount = Path('/mnt/lifecycle-target')
    mount.mkdir(parents=True)
    run(['mount', '/dev/disk/by-label/root', str(mount)])
    try:
        deployments = list((mount / 'ostree/deploy/default/deploy').glob('*.0'))
        assert len(deployments) == 1, deployments
        etc = deployments[0] / 'etc'
        var = mount / 'ostree/deploy/default/var'
        state = var / 'lib/ladyboot-qualification'
        state.mkdir(parents=True)
        for name in ['os-v1.oci.tar', 'os-v2.oci.tar', 'smoke.tar.gz', 'lifecycle_guest.sh']:
            shutil.copyfile('/opt/qualification/' + name, state / name)
        shutil.copyfile(state / 'os-v1.oci.tar', state / 'current.oci.tar')
        (state / 'lifecycle_guest.sh').chmod(0o755)
        (state / 'phase').write_text('prepare\n')
        unit = etc / 'systemd/system/ladyboot-lifecycle-test.service'
        unit.write_text('''[Unit]
Description=Disposable bootc lifecycle qualification
After=local-fs.target user@1000.service
[Service]
Type=oneshot
Environment=PATH=/usr/bin
ExecStart=/var/lib/ladyboot-qualification/lifecycle_guest.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=1100
''')
        wants = unit.parent / 'multi-user.target.wants'
        wants.mkdir(exist_ok=True)
        (wants / unit.name).symlink_to('../' + unit.name)
        run(['sync'])
    finally:
        run(['umount', str(mount)])
    print('LADYBOOT_INSTALL_OK', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        raise
    finally:
        run(['systemctl', 'poweroff', '--no-block'])
