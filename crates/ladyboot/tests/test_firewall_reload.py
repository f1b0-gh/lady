"""Exercise a real nftables policy only inside a disposable network namespace/VM."""
import json
from pathlib import Path
import subprocess
import sys


def check(nft, policy):
    assert policy.stat().st_size <= 1024**2
    original = policy.read_text()
    flow = 'ip daddr 192.0.2.2 tcp dport 443 accept'
    assert original.count(flow) == 1

    def run(args, text=None, expected=0):
        result = subprocess.run([nft, *args], input=text, capture_output=True, text=True, timeout=30)
        if expected is not None:
            assert result.returncode == expected, result.stderr
        return result

    def table(name):
        return json.loads(run(['-j', 'list', 'table', 'inet', name]).stdout)

    def rules(value):
        return [row['rule']['expr'] for row in value['nftables'] if 'rule' in row]

    run(['-f', '-'], 'table inet qualification_foreign {\n chain keep {\n  counter\n }\n}\n')
    foreign = table('qualification_foreign')
    try:
        run(['-f', '-'], original)
        initial_rules = rules(table('ladyboot'))
        run(['-f', '-'], original)
        assert rules(table('ladyboot')) == initial_rules, 'reapplying policy duplicates rules'
        restricted = original.replace(flow, '')
        run(['-f', '-'], restricted)
        active = table('ladyboot')
        output_rules = [row['rule'] for row in active['nftables']
                        if 'rule' in row and row['rule']['chain'] == 'site_output']
        assert '192.0.2.2' not in json.dumps(output_rules), 'removed destination remains allowed'
        assert table('qualification_foreign') == foreign
        invalid = run(['-f', '-'], original + '\ndeliberately invalid fixture\n', expected=None)
        assert invalid.returncode != 0
        assert table('ladyboot') == active, 'invalid update changed active policy'
        assert table('qualification_foreign') == foreign
        run(['-f', '-'], original)
        assert rules(table('ladyboot')) == initial_rules
        print('LADYBOOT_FIREWALL_RELOAD_OK', flush=True)
    finally:
        run(['-f', '-'], original)
        run(['delete', 'table', 'inet', 'qualification_foreign'])


if __name__ == '__main__':
    check(sys.argv[1], Path(sys.argv[2]))
