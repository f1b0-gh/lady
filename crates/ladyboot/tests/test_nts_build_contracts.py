"""Evaluate real Nix generators and exercise their NTS check dispatch."""
import argparse
import configparser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--nix-instantiate', required=True)
PARSER.add_argument('--nixpkgs', required=True, type=Path)
ARGS, remaining = PARSER.parse_known_args()
sys.argv[1:] = remaining
ROOT = Path(__file__).resolve().parents[1]
# Allows running the same maintained test from staging before installation.
ROOT = Path(os.environ.get('LADYBOOT_TEST_ROOT', str(ROOT)))


def quote(path):
    return json.dumps(str(path)).replace('${', r'\${')


def evaluate(expression):
    result = subprocess.run([ARGS.nix_instantiate, '--eval', '--strict', '--json',
                             '--readonly-mode', '--expr', expression],
                            capture_output=True, text=True, check=True, timeout=30)
    return json.loads(result.stdout)


class NativeBuildContracts(unittest.TestCase):
    def test_generated_service_uses_only_the_selected_ca_bundle(self):
        script = evaluate(f'''import {quote(ROOT / 'nix/time-sync.nix')} {{
          pkgs.lib = import {quote(ARGS.nixpkgs / 'lib')};
          profile = builtins.fromJSON (builtins.readFile {quote(ROOT / 'profiles/podman-vm.json')});
          resolved.catalog.ntpd-rs = "/never-executed";
        }}''')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'etc/systemd/system/multi-user.target.wants').mkdir(parents=True)
            (root / 'usr/lib/systemd/system').mkdir(parents=True)
            subprocess.run(['bash', '-eu', '-c', script], env={**os.environ, 'out': str(root)},
                           check=True, timeout=10)
            unit = configparser.ConfigParser(interpolation=None)
            unit.read(root / 'usr/lib/systemd/system/ntpd-rs.service')
            self.assertEqual(unit['Service']['Environment'],
                             'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt')
            self.assertIn('SSL_CERT_DIR', unit['Service'].get('UnsetEnvironment', '').split())

    def test_declared_time_client_cannot_skip_checks_when_config_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'bin'
            binary.mkdir()
            # Stub unrelated validators and the bootc lint boundary only. The
            # real Nix build script must dispatch its NTS validator, which already
            # has a separate missing-config regression on a delivered rootfs.
            for name, text in {
                'python3': '#!/bin/sh\ncase "$1" in *test_nts_rootfs.py) exit 17;; esac\nexit 0\n',
                'bootc': '#!/bin/sh\nexit 0\n',
            }.items():
                path = binary / name
                path.write_text(text)
                path.chmod(0o700)
            for present in [False, True]:
                with self.subTest(time_client_requested=present):
                    client = '"/unused-client"' if present else 'null'
                    expression = f'''let
                      pkgs = {{
                        lib = import {quote(ARGS.nixpkgs / 'lib')};
                        runCommand = name: attrs: script: script;
                        bootc = {quote(root)};
                        cacert = "/unused-ca";
                        go_1_26.overrideAttrs = callback: "/unused-go";
                      }};
                      rootfs = {{
                        outPath = {quote(root / 'rootfs')};
                        __toString = self: self.outPath;
                        timeClient = {client};
                      }};
                    in (import {quote(ROOT / 'nix/checks.nix')} {{
                      inherit pkgs rootfs; image = "/unused-image";
                    }}).rootfs'''
                    script = evaluate(expression)
                    result = subprocess.run(['bash', '-eu', '-c', script],
                                            env={**os.environ, 'PATH': str(binary) + ':' + os.environ['PATH'],
                                                 'out': str(root / 'check-result')},
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 17 if present else 0,
                                     result.stdout + result.stderr)


    def test_delivered_policy_checker_preserves_other_protocols(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['usr/share/ladyboot', 'etc/systemd/network']:
                (root / name).mkdir(parents=True)
            sources = [{'address': '192.0.2.1', 'server': 'nts.test'}]
            (root / 'usr/share/ladyboot/plan.json').write_text(json.dumps(
                {'requested': {'network': {'nts': sources}}}))
            (root / 'etc/hosts').write_text('127.0.0.1 localhost\n192.0.2.1 nts.test\n')
            (root / 'etc/systemd/network/10-ladyboot.network').write_text('[DHCPv4]\nUseNTP=no\n')
            (root / 'etc/nftables.conf').write_text(
                'ip daddr 192.0.2.1 udp dport 123 accept\n'
                'ip daddr 192.0.2.1 tcp dport 4460 accept\n'
                'ip daddr 192.0.2.42 tcp dport 123 accept\n'
                'ip daddr 192.0.2.42 udp dport 4460 accept\n')
            result = subprocess.run([sys.executable, str(ROOT / 'tests/test_nts_rootfs.py'),
                                     str(root), 'NtsRootfs.test_explicit_hosts_and_network_destinations'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
