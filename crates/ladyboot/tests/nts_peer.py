"""Manage a real chrony NTS server ONLY inside the isolated peer fixture."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


class NtsPeer:
    def __init__(self):
        self.process = None
        self.log = None
        self.directory = Path('/run/ladyboot-nts-peer')
        self.directory.mkdir(mode=0o700)

    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
            self.log.close()

    def configure(self, mode):
        assert mode in {'valid', 'wrong-name', 'expired', 'future', 'outside',
                        'ke-only', 'plain-only', 'drop-ke', 'wrong-port'}
        def firewall(drop):
            policy = 'destroy table inet nts_fixture\ntable inet nts_fixture { chain input { type filter hook input priority -10; policy accept; ' + (drop + '; ' if drop else '') + '}\n}\n'
            subprocess.run(['nft', '-f', '-'], input=policy, text=True, check=True, timeout=10)
        if mode == 'plain-only':
            # Avoid ICMP port-unreachable removing the client's NTS source during
            # the handover. Keep UDP closed until the plain server confirms bind.
            firewall('udp dport 123 drop')
        if mode != 'drop-ke':
            self.stop()
        if mode != 'plain-only':
            firewall({'ke-only': 'udp dport 123 drop', 'drop-ke': 'tcp dport 4460 drop'}.get(mode, ''))
        if mode == 'drop-ke':
            assert self.process is not None and self.process.poll() is None
            return
        self.log = (self.directory / 'current.log').open('w')
        if mode == 'plain-only':
            command = [sys.executable, '/opt/qualification/guest.py', '--plain-ntp']
        else:
            certificate = mode if mode in {'wrong-name', 'expired', 'future'} else 'valid'
            config = '\n'.join([
                'local stratum 1', 'allow 192.0.2.0/24', 'cmdport 0',
                'bindcmdaddress /run/ladyboot-nts-peer/control.sock',
                'pidfile /run/ladyboot-nts-peer/chrony.pid',
                'ntsdumpdir /run/ladyboot-nts-peer',
                'ntsservercert /opt/qualification/nts/' + certificate + '.pem',
                'ntsserverkey /opt/qualification/nts/server-key.pem',
                'ntsport 4460', 'port 124' if mode == 'wrong-port' else 'port 123',
                'ntsntpserver 192.0.2.3\nntsrotate 0' if mode == 'outside' else '',
            ]) + '\n'
            path = self.directory / 'chrony.conf'
            path.write_text(config)
            # -x prevents clock adjustment even inside this disposable VM.
            command = [os.environ['CHRONYD'], '-n', '-x', '-u', 'root', '-f', str(path)]
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.log,
                                        stderr=subprocess.STDOUT)
        if mode == 'plain-only':
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with (self.directory / 'current.log').open() as stream:
                    output = stream.read(65537)
                if len(output) > 65536:
                    raise RuntimeError('plain server readiness log exceeds budget')
                if self.process.poll() is not None:
                    raise RuntimeError(output)
                if 'LADYBOOT_PLAIN_READY' in output.splitlines():
                    firewall('')
                    return
                time.sleep(0.1)
            raise TimeoutError('plain NTP server did not confirm bind')
        if mode != 'plain-only':
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError((self.directory / 'current.log').read_text()[:65536])
                try:
                    with socket.create_connection(('192.0.2.1', 4460), timeout=1):
                        return
                except OSError:
                    time.sleep(0.2)
            raise TimeoutError('real NTS-KE server did not listen')
