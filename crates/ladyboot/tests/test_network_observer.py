"""Exercise actual Linux outgoing capture in a disposable user/network namespace."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest


def isolated_child(parent_namespace):
    assert os.readlink('/proc/self/ns/net') != parent_namespace, 'host network is forbidden'
    import network_fixture as fixture
    for args in [('link', 'add', 'enp0s2', 'type', 'veth', 'peer', 'name', 'peer0'),
                 ('link', 'set', 'enp0s2', 'up'), ('link', 'set', 'peer0', 'up')]:
        subprocess.run(['ip', *args], check=True, timeout=5)
    observer = threading.Thread(target=fixture.observe)
    observer.start()
    # A synthetic IPv4 UDP frame, emitted on the private veth. No NTP daemon,
    # clock operation, Internet access, or host interface is involved.
    frame = (b'\xff' * 6 + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
             + struct.pack('!BBHHHBBH4s4s', 0x45, 0, 76, 1, 0, 64, 17, 0,
                           socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.10'))
             + struct.pack('!HHHH', 123, 40000, 56, 0) + bytes(48))
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sender:
            sender.bind(('enp0s2', 0))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and fixture.snapshot()['plain_responses'] == 0:
                sender.send(frame)
                time.sleep(0.05)
        assert fixture.snapshot()['plain_responses'] > 0, 'outgoing plain response was invisible'
    finally:
        fixture.STOP.set()
        observer.join(timeout=3)
        assert not observer.is_alive(), 'capture did not terminate'


class OutgoingObservation(unittest.TestCase):
    def test_real_outgoing_frame_is_observed(self):
        result = subprocess.run([
            'unshare', '--user', '--map-root-user', '--net', sys.executable,
            str(Path(__file__).resolve()), '--isolated-child', os.readlink('/proc/self/ns/net')],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--isolated-child':
        isolated_child(sys.argv[2])
    else:
        unittest.main()
