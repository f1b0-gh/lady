"""Deterministic refusal/recovery races in the actual NTS scenario driver."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import nts_guest
import nts_peer


def observation(synced=False, source=False, stamp=1):
    return {'system': {'stratum': 2 if synced else 16,
                       'leap_indicator': 'NoWarning' if synced else 'Unknown'},
            'sources': [{'address': '192.0.2.1:123', 'nts_cookies': 8,
                         'last_update': {'timestamp': stamp}, 'id': 1}] if source else []}


class ScenarioRaces(unittest.TestCase):
    def simulate(self, check_warm=False, check_recovery=False, accept_plain=False):
        mode, invocation, calls = 'valid', 'initial', 0
        value = observation()
        restored_invocation = None
        counter = 0
        def cold(config):
            nonlocal invocation, calls, value
            calls += 1
            invocation = f'invocation-{calls}'
            if mode == 'ke-only':
                self.assertIn('min = 4, max = 4', config)
                self.assertIn('initial-poll-interval = 4', config)
            trusted = '/opt/qualification/nts/ca.pem' in config
            value = observation(synced=trusted and mode == 'valid',
                                source=trusted and mode in {'valid', 'ke-only'})
            return invocation
        def request(_host, path='/probe', timeout=6):
            nonlocal mode, value, counter, restored_invocation
            self.assertEqual(timeout, 40 if path.startswith('/nts/') else 6)
            if path.startswith('/nts/'):
                previous, mode = mode, path.removeprefix('/nts/')
                if mode == 'plain-only' and accept_plain:
                    value['sources'][0]['last_update']['timestamp'] += 1
                if mode == 'drop-ke':
                    # A response arrived before the server acknowledged the cut.
                    value['sources'][0]['last_update']['timestamp'] += 1
                if mode == 'valid' and previous == 'drop-ke':
                    restored_invocation = invocation
                    value = observation(synced=True, source=True, stamp=4)
            counter += 1
            return {'nts_ke_syn': counter, 'plain_responses': counter, 'udp_destinations': {}}
        def wait(predicate, seconds=60):
            nonlocal value
            if mode == 'drop-ke' and nts_guest.synchronized(value):
                if check_warm:
                    self.assertFalse(predicate(copy.deepcopy(value)),
                                     'pre-outage measurement satisfied warm-cookie test')
                value['sources'][0]['last_update']['timestamp'] += 1
            self.assertTrue(predicate(copy.deepcopy(value)), (mode, value))
            return copy.deepcopy(value)
        def run(*args):
            if args[0] == 'journalctl':
                endpoint = '192.0.2.3:123' if mode == 'outside' else '192.0.2.1:124'
                return ('UnknownIssuer NotValidForName Expired NotValidYet\n'
                        'Negotiated NTP endpoint refused by source policy address=' + endpoint)
            if args[0] == 'adjtimex': return 'return value: 0'
            return invocation
        def record(name, _value):
            if check_recovery and name == 'recovered-authenticated':
                self.assertEqual(invocation, restored_invocation,
                                 'recovery restarted the client and hid retry failure')
        config = Mock()
        config.read_text.return_value = 'certificate-authority = "/etc/ssl/certs/ca-certificates.crt"\n'
        fake_path = MagicMock()
        fake_path.is_file.return_value = True
        fake_path.exists.return_value = False
        with patch.object(nts_guest, 'CONFIG', config), patch.object(nts_guest, 'Path', return_value=fake_path), \
             patch.object(nts_guest, 'cold', side_effect=cold), patch.object(nts_guest, 'request', side_effect=request), \
             patch.object(nts_guest, 'state', side_effect=lambda: copy.deepcopy(value)), \
             patch.object(nts_guest, 'wait', side_effect=wait), patch.object(nts_guest, 'run', side_effect=run), \
             patch.object(nts_guest, 'record', side_effect=record), patch.object(nts_guest.time, 'sleep'):
            nts_guest.check()

    def test_warm_cookie_proof_requires_a_post_outage_measurement(self):
        self.simulate(check_warm=True)

    def test_recovery_uses_the_same_client_invocation(self):
        self.simulate(check_recovery=True)

    def test_plain_measurement_is_refused_before_system_sync(self):
        with self.assertRaisesRegex(AssertionError, 'unauthenticated measurement'):
            self.simulate(accept_plain=True)

    def test_plain_peer_blocks_udp_until_the_plain_listener_is_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            peer = object.__new__(nts_peer.NtsPeer)
            peer.directory = Path(temporary)
            peer.log = None
            events = []
            def firewall(*args, **kwargs):
                if 'udp dport 123 drop' in kwargs['input']:
                    events.append('block')
                else:
                    self.assertEqual(events, ['block', 'stop', 'ready'])
                    events.append('open')
            def launch(*args, **kwargs):
                self.assertEqual(events, ['block', 'stop'])
                kwargs['stdout'].write('LADYBOOT_PLAIN_READY\n')
                kwargs['stdout'].flush()
                events.append('ready')
                process = Mock()
                process.poll.return_value = None
                return process
            with patch.object(peer, 'stop', side_effect=lambda: events.append('stop')), \
                 patch.object(nts_peer.subprocess, 'run', side_effect=firewall), \
                 patch.object(nts_peer.subprocess, 'Popen', side_effect=launch):
                peer.configure('plain-only')
            peer.log.close()
            self.assertEqual(events, ['block', 'stop', 'ready', 'open'])


if __name__ == '__main__':
    unittest.main()
