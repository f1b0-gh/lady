"""Exercise real Nickel and direct Nix contracts with public hostile data."""
import argparse
import copy
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nickel', required=True)
    parser.add_argument('--nix-instantiate', required=True)
    parser.add_argument('--nixpkgs', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    valid = {
        'schema_version': 1, 'architecture': 'x86_64-linux', 'os_id': 'bootc-podman',
        'revision': '1', 'needs': ['bootc-base', 'podman-rootless', 'network-runtime'],
        'podman': {'user': 'containers', 'uid': 1000, 'gid': 1000,
                   'subuid_start': 65536, 'subgid_start': 65536, 'range_size': 65536},
        'network': {'interface': 'enp0s2', 'dns': ['192.0.2.1'], 'nts': [{'server': 'nts.test', 'address': '192.0.2.1'}],
                    'egress': [{'address': '192.0.2.2', 'protocol': 'tcp', 'port': 443}],
                    'ingress': []},
    }
    debug = copy.deepcopy(valid)
    debug['needs'].append('podman-debug')
    orphan = copy.deepcopy(debug)
    orphan['needs'].remove('podman-rootless')
    del orphan['podman']
    cases = [('valid', valid, True), ('debug', debug, True), ('orphan-debug', orphan, False)]
    collision = copy.deepcopy(valid)
    collision['podman']['user'] = 'ntpd-rs'
    cases.append(('nts-service-identity-collision', collision, False))
    no_time = copy.deepcopy(collision)
    no_time['needs'].remove('network-runtime')
    del no_time['network']
    cases.append(('same-name-without-time-service', no_time, True))
    for protocol, port in [('udp', 123), ('tcp', 4460)]:
        for address, expected in [('192.0.2.42', False), ('192.0.2.1', True)]:
            item = copy.deepcopy(valid)
            item['network']['egress'] = [{'address': address, 'protocol': protocol, 'port': port}]
            cases.append(('reserved-time-flow', item, expected))
    for protocol, port in [('tcp', 123), ('udp', 4460)]:
        item = copy.deepcopy(valid)
        item['network']['egress'] = [{'address': '192.0.2.42', 'protocol': protocol, 'port': port}]
        cases.append(('other-application-protocol', item, True))
    legacy = copy.deepcopy(valid)
    del legacy['network']['nts']
    legacy['network']['ntp'] = ['192.0.2.1']
    cases.append(('legacy-ntp', legacy, False))
    for server in ['', 'nts', 'NTS.test', '.nts.test', 'nts.test.', 'nts..test',
                   '-nts.test', 'nts-.test', 'nts_test.example', '*.test',
                   'nts.test:4460', 'nts.test\n[[source]]', '192.0.2.1', '1.2',
                   '1.0x0201', 'ntś.test', 'a' * 64 + '.test',
                   '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 62])]:
        item = copy.deepcopy(valid)
        item['network']['nts'][0]['server'] = server
        cases.append(('hostile-nts-name', item, False))
    for sources in [[], [{'server': 'nts.test', 'address': '192.0.2.1'},
                         {'server': 'nts.test', 'address': '192.0.2.2'}],
                    [{'server': 'nts.test', 'address': '192.0.2.1'},
                     {'server': 'other.test', 'address': '192.0.2.1'}],
                    [{'server': f'time-{n}.test', 'address': f'192.0.2.{n}'} for n in range(1, 66)]]:
        item = copy.deepcopy(valid)
        item['network']['nts'] = sources
        cases.append(('ambiguous-or-unbounded-nts', item, False))
    for server in ['a.b', '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 61])]:
        item = copy.deepcopy(valid)
        item['network']['nts'][0]['server'] = server
        cases.append(('valid-nts-boundary', item, True))
    full = copy.deepcopy(valid)
    full['network']['nts'] = [{'server': f'time-{n}.test', 'address': f'192.0.2.{n}'} for n in range(1, 65)]
    cases.append(('valid-64-sources', full, True))
    for path, value in [
        (['unknown'], True), (['podman', 'password'], 'forbidden'),
        (['podman', 'uid'], 0), (['podman', 'subuid_start'], 1000),
        (['podman', 'subuid_start'], 4294967295), (['podman', 'range_size'], 0),
        (['network', 'nts', 0, 'port'], 4460),
        (['network', 'nts', 0, 'fallback'], True),
        (['network', 'nts', 0, 'address'], '127.0.0.1'),
        (['network', 'nts', 0, 'address'], '192.000.2.1'),
        (['network', 'nts', 0, 'address'], '192.0.2.1/24'),
        (['network', 'fallback'], True), (['network', 'interface'], 'en*'),
        (['network', 'interface'], 'eth0\n[Network]'), (['network', 'dns'], []),
        (['network', 'dns'], ['127.0.0.1']), (['network', 'dns'], ['192.000.2.1']),
        (['network', 'dns'], ['192.0.2.1'] * 65),
        (['network', 'egress', 0, 'port'], 0),
        (['network', 'egress', 0, 'protocol'], 'tcp; accept'),
        (['network', 'egress', 0, 'address'], '0.0.0.0/0'),
        (['needs'], valid['needs'] + ['offline']),
        (['needs'], valid['needs'] + ['network-dhcp']),
        (['network'], None), (['podman'], None),
    ]:
        item = copy.deepcopy(valid)
        parent = item
        for part in path[:-1]:
            parent = parent[part]
        parent[path[-1]] = value
        cases.append((str(path), item, False))
    with tempfile.TemporaryDirectory(prefix='contracts-') as temporary:
        path = Path(temporary) / 'profile.json'
        for name, value, expected in cases:
            path.write_text(json.dumps(value))
            # Paths are tool-generated and quoted as Nix literals; no input interpolation.
            quote = lambda p: json.dumps(str(p)).replace('${', r'\${')
            expression = (f'import {quote(root / "nix/profile.nix")} {{ '
                          f'lib = import {quote(args.nixpkgs / "lib")}; '
                          f'profile = builtins.fromJSON (builtins.readFile {quote(path)}); }}')
            commands = [
                [args.nickel, 'export', '--format', 'json', '--apply-contract', str(root / 'profiles/schema.ncl'), str(path)],
                [args.nix_instantiate, '--eval', '--strict', '--json', '--expr', expression],
            ]
            for command in commands:
                result = subprocess.run(command, capture_output=True, timeout=30)
                if (result.returncode == 0) != expected:
                    raise AssertionError(f'{command[0]}: {name}: {result.stderr.decode(errors="replace")}')
                if expected and json.loads(result.stdout) != value:
                    raise AssertionError(f'{name}: contract changed the public data')
    print(f'{len(cases)} cases passed through Nickel and direct Nix')


if __name__ == '__main__':
    main()
