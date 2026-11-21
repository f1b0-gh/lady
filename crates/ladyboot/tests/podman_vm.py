"""Bounded direct-kernel QEMU qualification; not a bootc installation test."""
import argparse
import json
from pathlib import Path
import subprocess
from network_vm import owned_directory, read_log, safe_qemu_path, wait_for


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', required=True, type=Path)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--mkfs', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--timeout', type=int, default=1200)
    args = parser.parse_args()
    if not 30 <= args.timeout <= 1800:
        parser.error('timeout must be between 30 and 1800 seconds')
    for path in [args.output, args.rootfs]:
        safe_qemu_path(path)
    owned_directory(args.output.parent)
    if args.rootfs.is_symlink() or not args.rootfs.is_dir():
        parser.error('rootfs must be a realized directory, not a symlink')
    args.output.mkdir(mode=0o700, exist_ok=False)
    result = {'passed': False, 'direct_kernel_boot': True,
              'bootc_lifecycle_qualified': False, 'network_qualified': False,
              'qemu_returncode': None}
    try:
        run_vm(args, result)
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if not result['passed']:
        raise SystemExit(f'qualification failed; inspect {args.output / "result.json"}')
    print('QEMU rootless Podman/Quadlet checks passed; bootc lifecycle remains separate')


def run_vm(args, result):
    # Reuse bounded preparation and preserve root-owned delivered inodes.
    from network_vm import prepare
    disk = prepare(args.rootfs, args.output / 'disk', args.mkfs)
    kernels = list((args.rootfs / 'usr/lib/modules').glob('*/vmlinuz'))
    if len(kernels) != 1:
        raise ValueError('expected exactly one delivered kernel')
    command = [args.qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2',
               '-m', '2048', '-nographic', '-no-reboot', '-monitor', 'none',
               '-kernel', str(kernels[0]), '-initrd', str(kernels[0].parent / 'initramfs.img'),
               '-append', 'root=/dev/sda console=ttyS0 panic=1',
               '-device', 'virtio-scsi-pci,id=scsi0',
               '-drive', f'file={disk},format=raw,if=none,id=rootdisk',
               '-device', 'scsi-hd,drive=rootdisk,bus=scsi0.0', '-nic', 'none',
               '-device', 'virtio-rng-pci']
    (args.output / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (args.output / 'serial.log').open('x') as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_for(process, args.output / 'serial.log', args.timeout)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            result['qemu_returncode'] = process.returncode
    serial = read_log(args.output / 'serial.log')
    result['passed'] = process.returncode == 0 and 'LADYBOOT_PODMAN_OK' in serial


if __name__ == '__main__':
    main()
