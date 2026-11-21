"""Verify the delivered NTS-only client policy, independently of Nix text."""
import configparser
import json
from pathlib import Path
import sys
import tomllib
import unittest

ROOT = Path(sys.argv.pop(1))
PLAN = json.loads((ROOT / 'usr/share/ladyboot/plan.json').read_text())


class NtsRootfs(unittest.TestCase):
    def test_sources_and_clock_bounds(self):
        path = ROOT / 'etc/ntpd-rs/ntp.toml'
        self.assertTrue(path.is_file(), 'NTS client configuration missing')
        config = tomllib.loads(path.read_text())
        self.assertEqual(set(config), {'source', 'synchronization', 'observability'})
        sources = PLAN['requested']['network']['nts']
        self.assertEqual(config['source'], [
            {'mode': 'nts', 'enable-srv-resolution': False, 'address': source['server'] + ':4460',
             'expected-ntp-address': source['address'] + ':123',
             'certificate-authority': '/etc/ssl/certs/ca-certificates.crt'}
            for source in sources])
        sync = config['synchronization']
        self.assertEqual(sync['minimum-agreeing-sources'], 1)
        for key in ['single-step-panic-threshold', 'startup-step-panic-threshold']:
            self.assertEqual(sync[key], {'forward': 1800, 'backward': 1800})
        self.assertEqual(config['observability']['observation-path'], '/run/ntpd-rs/observe')
        self.assertEqual(config['observability']['observation-permissions'], 0o600)

    def test_client_service_and_no_plain_ntp(self):
        unit = ROOT / 'usr/lib/systemd/system/ntpd-rs.service'
        self.assertTrue(unit.is_file(), 'NTS client service missing')
        config = configparser.ConfigParser(interpolation=None, strict=True)
        config.read_string(unit.read_text())
        service = config['Service']
        self.assertEqual(service['AmbientCapabilities'], 'CAP_SYS_TIME')
        self.assertEqual(service['CapabilityBoundingSet'], 'CAP_SYS_TIME')
        # Native timestamped-socket watches interface changes through NETLINK_ROUTE.
        self.assertEqual(set(service['RestrictAddressFamilies'].split()),
                         {'AF_UNIX', 'AF_INET', 'AF_NETLINK'})
        self.assertEqual(service['RuntimeDirectoryMode'], '0700')
        self.assertEqual(service['ProtectSystem'], 'strict')
        self.assertEqual(service['NoNewPrivileges'], 'yes')
        self.assertEqual(service['User'], 'ntpd-rs')
        self.assertEqual(service['Restart'], 'no')
        self.assertEqual(service['Environment'], 'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt')
        self.assertIn('SSL_CERT_DIR', service['UnsetEnvironment'].split())
        self.assertEqual((ROOT / 'etc/systemd/system/systemd-timesyncd.service').readlink().as_posix(), '/dev/null')
        for directory in ['etc/systemd/system', 'usr/lib/systemd/system']:
            self.assertFalse(list((ROOT / directory).glob('*.wants/systemd-timesyncd.service')))
        packages = {p['selection']: p for p in PLAN['runtime_packages']}
        self.assertEqual(packages['ntpd-rs']['version'], '1.9.0')
        systemd = ROOT / 'usr/lib/nix/store' / Path(packages['systemd']['store_path']).name
        self.assertFalse((systemd / 'lib/systemd/systemd-timesyncd').exists())
        self.assertFalse(list((ROOT / 'usr/lib/nix/store').glob('*/lib/systemd/systemd-timesyncd')),
                         'another delivered systemd output retains the plain time client')
        enabled = {s['name'] for s in PLAN['enabled_services']}
        self.assertIn('ntpd-rs.service', enabled)
        self.assertFalse(enabled.intersection({'systemd-timesyncd.service', 'ntpd-rs-metrics.service'}))

    def test_explicit_hosts_and_network_destinations(self):
        requested = PLAN['requested']['network']
        self.assertIn('nts', requested, 'NTS sources absent from delivered plan')
        hosts = [line.split() for line in (ROOT / 'etc/hosts').read_text().splitlines()]
        self.assertTrue(any(row[:2] == ['127.0.0.1', 'localhost'] for row in hosts))
        firewall = (ROOT / 'etc/nftables.conf').read_text()
        for source in requested['nts']:
            self.assertIn([source['address'], source['server']], hosts)
        expected = {(s['address'], protocol, port) for s in requested['nts']
                    for protocol, port in [('tcp', '4460'), ('udp', '123')]}
        actual = set()
        for line in firewall.splitlines():
            words = line.split()
            if len(words) == 7 and words[:2] == ['ip', 'daddr'] and words[4] == 'dport' and (words[3], words[5]) in {('tcp', '4460'), ('udp', '123')}:
                actual.add((words[2], words[3], words[5]))
        self.assertEqual(actual, expected)
        network = (ROOT / 'etc/systemd/network/10-ladyboot.network').read_text()
        self.assertIn('UseNTP=no', network)


if __name__ == '__main__':
    unittest.main()
