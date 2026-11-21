"""Install and boot production archives on fresh disposable UEFI QEMU disks."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from network_vm import owned_directory, prepare, read_log, safe_qemu_path, wait_for


def records(serial):
    statuses = {}
    observations = []
    name, buffer = None, []
    for line in serial.splitlines():
        line = re.sub(r'^\[\s*\d+\.\d+\]\s+\S+\[\d+\]:\s?', '', line)
        if line.startswith('LADYBOOT_STATUS_BEGIN '):
            name, buffer = line.split()[-1], []
        elif line == 'LADYBOOT_STATUS_END':
            assert name is not None
            statuses[name] = json.loads('\n'.join(buffer))
            name = None
        elif name is not None:
            buffer.append(line)
        elif line.startswith('LADYBOOT_OBSERVATION '):
            observations.append(dict(item.split('=', 1) for item in line.split()[1:]))
    assert name is None, 'incomplete status record'
    return statuses, observations


def boot(qemu, firmware, variables, target, directory, installer=None, rootfs=None):
    directory.mkdir(mode=0o700, exist_ok=False)
    command = [qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
               '-nographic', '-no-reboot', '-monitor', 'none', '-nic', 'none',
               '-drive', f'if=pflash,format=raw,readonly=on,file={firmware / "OVMF_CODE.fd"}',
               '-drive', f'if=pflash,format=raw,file={variables}',
               '-device', 'virtio-scsi-pci,id=scsi0,addr=0x3',
               '-drive', f'file={target},format=raw,if=none,id=targetdisk',
               '-device', 'scsi-hd,drive=targetdisk,bus=scsi0.0,scsi-id=1,serial=ladyboot-target',
               '-device', 'virtio-rng-pci']
    if installer:
        kernels = list((rootfs / 'usr/lib/modules').glob('*/vmlinuz'))
        assert len(kernels) == 1
        command.extend(['-drive', f'file={installer},format=raw,if=none,id=installerdisk',
                        '-device', 'scsi-hd,drive=installerdisk,bus=scsi0.0,scsi-id=0',
                        '-kernel', str(kernels[0]), '-initrd', str(kernels[0].parent / 'initramfs.img'),
                        '-append', 'root=LABEL=network-test console=ttyS0 panic=1'])
    else:
        assert '-kernel' not in command and '-initrd' not in command
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (directory / 'serial.log').open('x') as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    try:
        wait_for(process, directory / 'serial.log', 1200)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        (directory / 'qemu-result.json').write_text(json.dumps({'returncode': process.returncode}) + '\n')
    assert process.returncode == 0, process.returncode
    return read_log(directory / 'serial.log')


def digest(status, slot='booted'):
    return status['status'][slot]['image']['imageDigest']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installer-rootfs', required=True, type=Path)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--mkfs', required=True)
    parser.add_argument('--firmware', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    for path in [args.output, args.installer_rootfs, args.firmware]:
        safe_qemu_path(path)
    owned_directory(args.output.parent)
    assert args.installer_rootfs.is_dir() and not args.installer_rootfs.is_symlink()
    args.output.mkdir(mode=0o700, exist_ok=False)
    result = {'passed': False, 'installed': False, 'uefi_boots': 0,
              'network_qualified': False, 'stages': {}}
    try:
        installer = prepare(args.installer_rootfs, args.output / 'installer-disk', args.mkfs)
        target = args.output / 'target.raw'
        with target.open('xb') as stream:
            stream.truncate(16 * 1024**3)
        variables = args.output / 'OVMF_VARS.fd'
        shutil.copyfile(args.firmware / 'OVMF_VARS.fd', variables)
        serial = boot(args.qemu, args.firmware, variables, target, args.output / 'install',
                      installer, args.installer_rootfs)
        assert 'LADYBOOT_INSTALL_OK' in serial, 'installation did not succeed'
        result['installed'] = True
        machine, original, updated = None, None, None
        for phase, version in [('prepare', '1'), ('recover', '1'), ('stage', '1'),
                               ('updated', '2'), ('rolled-back', '1'), ('collision', '1')]:
            serial = boot(args.qemu, args.firmware, variables, target, args.output / phase)
            assert f'LADYBOOT_PHASE_OK {phase}' in serial, f'guest failed phase {phase}'
            statuses, observations = records(serial)
            assert len(observations) == 1
            row = observations[0]
            assert row['phase'] == phase and row['version'] == version and row['home_uid'] == '1000'
            assert re.fullmatch('[0-9a-f]{32}', row['machine']) and row['machine'] != '0' * 32
            if machine is None:
                machine = row['machine']
                original = digest(statuses['booted'])
            assert row['machine'] == machine
            assert digest(statuses['booted']) == (updated if version == '2' else original)
            if phase == 'prepare':
                assert statuses['rejected-truncated-image']['status']['staged'] is None
                assert digest(statuses['rejected-truncated-image']) == original
            elif phase == 'recover':
                assert statuses['metadata-only']['status']['staged'] is None
                assert digest(statuses['metadata-only']) == original
            elif phase == 'stage':
                updated = digest(statuses['staged-update'], 'staged')
                assert updated != original and digest(statuses['staged-update']) == original
            elif phase == 'updated':
                assert statuses['rollback-queued']['status']['rollbackQueued'] is True
                assert digest(statuses['rollback-queued'], 'rollback') == original
            result['uefi_boots'] += 1
            result['stages'][phase] = {'observation': row, 'statuses': statuses}
        assert 'LADYBOOT_LIFECYCLE_OK' in serial
        result['passed'] = True
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
