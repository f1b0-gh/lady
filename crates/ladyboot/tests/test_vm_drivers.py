"""Refusals must happen before disk creation or external tool execution."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import podman_vm
import network_vm
import bootc_lifecycle
import lifecycle_install

from bootc_lifecycle import records
from network_vm import read_log


class DriverRefusals(unittest.TestCase):
    def invoke(self, directory, output, lifecycle):
        root = directory / 'rootfs'
        root.mkdir(exist_ok=True)
        firmware = directory / 'firmware'
        firmware.mkdir(exist_ok=True)
        (firmware / 'OVMF_VARS.fd').write_bytes(b'fixture')
        source = Path(__file__).parent
        if lifecycle == 'podman':
            command = [sys.executable, str(source / 'podman_vm.py'), '--rootfs', str(root)]
        elif lifecycle:
            command = [sys.executable, str(source / 'bootc_lifecycle.py'), '--installer-rootfs', str(root),
                       '--firmware', str(firmware)]
        else:
            command = [sys.executable, str(source / 'network_vm.py'), '--rootfs', str(root),
                       '--peer-rootfs', str(root)]
        # Neither tool may be reached. Python rejects mkfs/QEMU flags if reached.
        command += ['--qemu', sys.executable, '--mkfs', sys.executable, '--output', str(output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)

    def test_ambiguous_qemu_paths_refused_before_creating_disks(self):
        for lifecycle in [False, True, 'podman']:
            for name in ['out,format=raw', 'out\nline']:
                with self.subTest(lifecycle=lifecycle, name=name), tempfile.TemporaryDirectory() as temp:
                    directory = Path(temp)
                    output = directory / name
                    self.invoke(directory, output, lifecycle)
                    self.assertFalse(output.exists(), 'unsafe QEMU path created output before refusal')

    def test_linked_parent_refused_without_touching_its_target(self):
        for lifecycle in [False, True, 'podman']:
            with self.subTest(lifecycle=lifecycle), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                target = directory / 'actual'
                target.mkdir()
                linked = directory / 'linked'
                linked.symlink_to(target)
                self.invoke(directory, linked / 'output', lifecycle)
                self.assertEqual(list(target.iterdir()), [])
                nested = target / 'nested'
                nested.mkdir()
                self.invoke(directory, linked / 'nested' / 'output', lifecycle)
                self.assertEqual(list(nested.iterdir()), [])

    def test_podman_timeout_retains_failure_result(self):
        class StuckProcess:
            returncode = None
            def poll(self):
                return self.returncode
            def wait(self, timeout=None):
                if timeout is not None:
                    raise subprocess.TimeoutExpired('synthetic-qemu', timeout)
                self.returncode = -9
                return self.returncode
            def terminate(self):
                pass
            def kill(self):
                pass

        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root = directory / 'rootfs'
            kernel = root / 'usr/lib/modules/test/vmlinuz'
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b'fixture')
            (kernel.parent / 'initramfs.img').write_bytes(b'fixture')
            output = directory / 'output'
            argv = ['podman_vm.py', '--rootfs', str(root), '--qemu', 'synthetic-qemu',
                    '--mkfs', 'synthetic-mkfs', '--output', str(output), '--timeout', '30']
            with mock.patch.object(sys, 'argv', argv), \
                 mock.patch.object(podman_vm.subprocess, 'run'), \
                 mock.patch.object(podman_vm.subprocess, 'Popen', return_value=StuckProcess()), \
                 mock.patch.object(podman_vm, 'wait_for', create=True, side_effect=TimeoutError('fixture timeout')):
                try:
                    podman_vm.main()
                except (Exception, SystemExit):
                    pass
            self.assertTrue((output / 'result.json').is_file(), 'timeout lost its structured failure result')
            result = json.loads((output / 'result.json').read_text())
            self.assertFalse(result['passed'])
            self.assertIn('Timeout', result['error'])

    def test_network_refuses_a_pre_nts_success_marker(self):
        class Completed:
            returncode = 0
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root = directory / 'rootfs'
            root.mkdir()
            output = directory / 'output'
            def prepare(_root, path, _mkfs):
                path.mkdir()
                return path / 'synthetic-disk'
            def launch(_qemu, _root, path, *_args):
                (path / 'serial.log').write_text('LADYBOOT_NETWORK_OK\nLADYBOOT_PEER_RESULT {}\n')
                return Completed()
            argv = ['network_vm.py', '--rootfs', str(root), '--peer-rootfs', str(root),
                    '--qemu', 'unused', '--mkfs', 'unused', '--output', str(output)]
            with mock.patch.object(sys, 'argv', argv), \
                 mock.patch.object(network_vm, 'prepare', side_effect=prepare), \
                 mock.patch.object(network_vm, 'launch', side_effect=launch), \
                 mock.patch.object(network_vm, 'wait_for'):
                with self.assertRaises(SystemExit):
                    network_vm.main()
            self.assertFalse(json.loads((output / 'result.json').read_text())['passed'])


    def test_installer_creates_mountpoint_on_minimal_filesystem(self):
        class ReachedMount(Exception):
            pass
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'sys/firmware/efi').mkdir(parents=True)
            (root / 'sys/block/sda').mkdir(parents=True)
            devices = {'blockdevices': [
                {'path': '/dev/sda', 'serial': 'ladyboot-target', 'size': 16 * 1024**3}]}
            def run(command, **_kwargs):
                if command[0] == 'mount':
                    self.assertTrue(Path(command[-1]).is_dir())
                    raise ReachedMount
            with mock.patch.object(lifecycle_install, 'Path',
                                   side_effect=lambda name: root / name.removeprefix('/')), \
                 mock.patch.object(lifecycle_install.subprocess, 'check_output',
                                   return_value=json.dumps(devices)), \
                 mock.patch.object(lifecycle_install, 'run', side_effect=run):
                with self.assertRaises(ReachedMount):
                    lifecycle_install.main()

    def test_installer_target_selection_survives_reversed_disk_names(self):
        class ReachedInstall(Exception):
            pass
        for target, installer in [('/dev/sda', '/dev/sdb'), ('/dev/sdb', '/dev/sda')]:
            with self.subTest(target=target):
                devices = [
                    {'path': installer, 'serial': None, 'size': 8 * 1024**3},
                    {'path': target, 'serial': 'ladyboot-target', 'size': 16 * 1024**3},
                ]
                def lsblk(command, **_kwargs):
                    requested = [x for x in command if x.startswith('/dev/')]
                    return json.dumps({'blockdevices': [d for d in devices
                                       if not requested or d['path'] in requested]})
                fake_path = mock.Mock()
                fake_path.is_dir.return_value = True
                fake_path.glob.return_value = []
                with mock.patch.object(lifecycle_install.subprocess, 'check_output', side_effect=lsblk), \
                     mock.patch.object(lifecycle_install, 'Path', return_value=fake_path), \
                     mock.patch.object(lifecycle_install, 'run', side_effect=ReachedInstall) as run:
                    with self.assertRaises(ReachedInstall):
                        lifecycle_install.main()
                self.assertEqual(run.call_args.args[0][-1], target)

    def test_installer_rejects_ambiguous_or_invalid_targets_before_install(self):
        target = {'path': '/dev/sda', 'serial': 'ladyboot-target', 'size': 16 * 1024**3}
        for devices in [[], [target, dict(target, path='/dev/sdb')],
                        [dict(target, size=8 * 1024**3)],
                        [dict(target, path='/dev/sda1')],
                        [dict(target, path='/dev/../sda')]]:
            with self.subTest(devices=devices):
                fake_path = mock.Mock()
                fake_path.is_dir.return_value = True
                fake_path.glob.return_value = []
                with mock.patch.object(lifecycle_install.subprocess, 'check_output',
                                       return_value=json.dumps({'blockdevices': devices})), \
                     mock.patch.object(lifecycle_install, 'Path', return_value=fake_path), \
                     mock.patch.object(lifecycle_install, 'run') as run:
                    with self.assertRaises((ValueError, AssertionError)):
                        lifecycle_install.main()
                    run.assert_not_called()

    def test_installer_boot_uses_the_prepared_filesystem_label(self):
        class Completed:
            returncode = 0
            def poll(self): return 0
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            root = directory / 'rootfs'
            kernel = root / 'usr/lib/modules/test/vmlinuz'
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b'fixture')
            (kernel.parent / 'initramfs.img').write_bytes(b'fixture')
            with mock.patch.object(network_vm.subprocess, 'run') as mkfs:
                installer = network_vm.prepare(root, directory / 'installer', 'synthetic-mkfs')
            command = mkfs.call_args.args[0]
            label = command[command.index('-L') + 1]
            with mock.patch.object(bootc_lifecycle.subprocess, 'Popen', return_value=Completed()) as qemu, \
                 mock.patch.object(bootc_lifecycle, 'wait_for'):
                bootc_lifecycle.boot('synthetic-qemu', directory, directory / 'vars',
                                     directory / 'target', directory / 'boot', installer, root)
            command = qemu.call_args.args[0]
            self.assertIn('root=LABEL=' + label, command[command.index('-append') + 1].split())

    def test_log_size_checked_before_reading(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'serial.log'
            with path.open('xb') as stream:
                stream.truncate(16 * 1024**2 + 1)
            with self.assertRaises(ValueError):
                read_log(path)

    def test_journal_status_records_preserve_json_and_reject_truncation(self):
        serial = '''[  12.100] sh[25]: LADYBOOT_STATUS_BEGIN booted
[  12.101] bootc[26]: {"status": {"staged": null, "booted": {"incompatible": false}}}
[  12.102] sh[25]: LADYBOOT_STATUS_END
[  12.103] sh[25]: LADYBOOT_OBSERVATION phase=prepare version=1 machine=1234 home_uid=1000
'''
        statuses, observations = records(serial)
        self.assertEqual(statuses['booted']['status'], {'staged': None, 'booted': {'incompatible': False}})
        self.assertEqual(observations, [{'phase': 'prepare', 'version': '1', 'machine': '1234', 'home_uid': '1000'}])
        with self.assertRaises(AssertionError):
            records(serial.split('LADYBOOT_STATUS_END')[0])


if __name__ == '__main__':
    unittest.main()
