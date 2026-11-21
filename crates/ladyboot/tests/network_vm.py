"""Bounded two-VM network test. Only an inherited Unix socketpair joins guests."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import time


def safe_qemu_path(path):
    if not path.is_absolute() or any(c == ',' or ord(c) < 32 for c in str(path)):
        raise ValueError('QEMU paths must be absolute and contain no commas or control characters')


def owned_directory(path):
    for parent in [path, *path.parents]:
        if parent.is_symlink():
            raise ValueError(f'linked directory: {parent}')
    if not path.is_dir() or path.stat().st_uid != os.getuid():
        raise ValueError('expected an existing owned output parent')


def prepare(rootfs, directory, mkfs):
    directory.mkdir(mode=0o700)
    disk = directory / 'root.ext4'
    with disk.open('xb') as stream:
        stream.truncate(8 * 1024**3)
    archive = directory / 'rootfs.tar'
    def root_owner(info):
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        return info
    with tarfile.open(archive, 'x', dereference=False) as tar:
        tar.add(rootfs, arcname='.', filter=root_owner)
    with (directory / 'mkfs.log').open('x') as log:
        subprocess.run([mkfs, '-F', '-L', 'network-test', '-d', str(archive), str(disk)],
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
    # The filesystem now contains the copied inputs; keep no duplicate archive
    # during the VM run. All three drivers share this preparation function.
    archive.unlink()
    return disk


def launch(qemu, rootfs, directory, disk, endpoint, mac):
    kernels = list((rootfs / 'usr/lib/modules').glob('*/vmlinuz'))
    if len(kernels) != 1:
        raise ValueError('expected exactly one delivered kernel')
    command = [qemu, '-machine', 'q35,accel=tcg', '-cpu', 'max', '-smp', '2', '-m', '2048',
               '-nographic', '-no-reboot', '-monitor', 'none',
               '-rtc', 'base=2026-11-18T12:00:00,clock=vm',
               '-kernel', str(kernels[0]), '-initrd', str(kernels[0].parent / 'initramfs.img'),
               '-append', 'root=/dev/sda console=ttyS0 panic=1',
               '-device', 'virtio-scsi-pci,id=scsi0,addr=0x3',
               '-drive', f'file={disk},format=raw,if=none,id=rootdisk',
               '-device', 'scsi-hd,drive=rootdisk,bus=scsi0.0',
               '-netdev', f'socket,id=isolated,fd={endpoint.fileno()}',
               '-device', f'virtio-net-pci,netdev=isolated,addr=0x2,mac={mac}',
               '-device', 'virtio-rng-pci']
    (directory / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (directory / 'serial.log').open('x') as log:
        return subprocess.Popen(command, pass_fds=(endpoint.fileno(),), stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT)


def read_log(path):
    if path.stat().st_size > 16 * 1024**2:
        raise ValueError('serial log exceeds 16 MiB budget')
    with path.open('rb') as stream:
        data = stream.read(16 * 1024**2 + 1)
    if len(data) > 16 * 1024**2:
        raise ValueError('serial log exceeds 16 MiB budget')
    return data.decode(errors='replace')


def wait_for(process, log, seconds, marker=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        output = read_log(log)
        if marker and marker in output:
            return
        if process.poll() is not None:
            if marker:
                raise RuntimeError(f'VM exited before {marker}: {process.returncode}')
            return
        time.sleep(0.5)
    raise TimeoutError(f'VM exceeded {seconds}s')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', required=True, type=Path)
    parser.add_argument('--peer-rootfs', required=True, type=Path)
    parser.add_argument('--qemu', required=True)
    parser.add_argument('--mkfs', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--legacy-dhcp', action='store_true', help='Expect only DHCP; DNS/TLS must remain unavailable')
    args = parser.parse_args()
    for path in [args.output, args.rootfs, args.peer_rootfs]:
        safe_qemu_path(path)
    owned_directory(args.output.parent)
    for root in [args.rootfs, args.peer_rootfs]:
        if root.is_symlink() or not root.is_dir():
            parser.error('rootfs must be a realized directory, not a symlink')
    args.output.mkdir(mode=0o700, exist_ok=False)
    processes = []
    result = {'passed': False, 'network_transport': 'inherited AF_UNIX SOCK_STREAM socketpair',
              'internet_access': False, 'bootc_lifecycle_qualified': False,
              'legacy_dhcp_control': args.legacy_dhcp, 'network_qualified': False}
    try:
        peer_dir, dut_dir = args.output / 'peer', args.output / 'dut'
        peer_disk = prepare(args.peer_rootfs, peer_dir, args.mkfs)
        dut_disk = prepare(args.rootfs, dut_dir, args.mkfs)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer = launch(args.qemu, args.peer_rootfs, peer_dir, peer_disk, left, '52:54:00:00:02:01')
            processes.append(peer)
            wait_for(peer, peer_dir / 'serial.log', 300, 'LADYBOOT_NETWORK_PEER_READY')
            dut = launch(args.qemu, args.rootfs, dut_dir, dut_disk, right, '52:54:00:00:02:10')
            processes.append(dut)
        finally:
            left.close()
            right.close()
        wait_for(dut, dut_dir / 'serial.log', 1200)
        dut_output = read_log(dut_dir / 'serial.log')
        if args.legacy_dhcp:
            result['passed'] = dut.returncode == 0 and 'LADYBOOT_LEGACY_DHCP_ONLY' in dut_output
        elif dut.returncode == 0 and all(marker in dut_output for marker in ['LADYBOOT_NETWORK_OK', 'LADYBOOT_NTS_OK']):
            wait_for(peer, peer_dir / 'serial.log', 60)
            result['passed'] = peer.returncode == 0 and 'LADYBOOT_PEER_RESULT' in read_log(peer_dir / 'serial.log')
            result['network_qualified'] = result['passed']
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        result['qemu_returncodes'] = [p.returncode for p in processes]
        (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
