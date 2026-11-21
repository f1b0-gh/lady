"""Exercise the exact upstream length-prefixed observation wire format."""
import io
import json
import struct
import unittest
from unittest.mock import patch

import nts_guest


class WireSocket:
    def __init__(self, data):
        self.stream = io.BytesIO(data)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def settimeout(self, _seconds):
        pass
    def connect(self, _path):
        pass
    def recv(self, count):
        return self.stream.read(min(count, 3))


class ObservationWire(unittest.TestCase):
    def test_reads_fragmented_upstream_frame(self):
        value = {'system': {'stratum': 16}, 'sources': []}
        data = json.dumps(value).encode()
        with patch.object(nts_guest.socket, 'socket', return_value=WireSocket(struct.pack('!Q', len(data)) + data)):
            self.assertEqual(nts_guest.state(), value)

    def test_rejects_oversized_header_before_reading_body(self):
        stream = WireSocket(struct.pack('!Q', 65537) + b'x' * 100)
        with patch.object(nts_guest.socket, 'socket', return_value=stream):
            with self.assertRaisesRegex(ValueError, 'budget'):
                nts_guest.state()
        self.assertEqual(stream.stream.tell(), 8)

    def test_rejects_truncated_frame(self):
        with patch.object(nts_guest.socket, 'socket', return_value=WireSocket(struct.pack('!Q', 20) + b'{}')):
            with self.assertRaisesRegex(ValueError, 'truncated'):
                nts_guest.state()


if __name__ == '__main__':
    unittest.main()
