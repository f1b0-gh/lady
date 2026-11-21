"""Exercise the delivered site policy and rootless pasta in a disposable VM."""
import json
from pathlib import Path
import subprocess
import sys
import time
import traceback

from network_probe import request
from test_firewall_reload import check as check_firewall_reload
from nts_guest import check as check_nts

PROFILE = json.loads(Path('/usr/share/ladyboot/plan.json').read_text())['requested']
P = PROFILE['podman']
HOME = f"/var/home/{P['user']}"
ENDPOINT = '192.0.2.2'
IMAGE = 'localhost/ladyboot-network:1'


def run(args, *, user=False, expected=0, timeout=90):
    if user:
        args = ['setpriv', f"--reuid={P['uid']}", f"--regid={P['gid']}", '--init-groups',
                'env', '-i', f"USER={P['user']}", f"LOGNAME={P['user']}", f'HOME={HOME}',
                f"XDG_RUNTIME_DIR=/run/user/{P['uid']}",
                f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{P['uid']}/bus", 'PATH=/usr/bin', *args]
    print(json.dumps({'event': 'start', 'command': args, 'timeout': timeout}), flush=True)
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout)
    print(json.dumps({'command': args, 'returncode': result.returncode, 'output': result.stdout}), flush=True)
    if expected is not None:
        assert result.returncode == expected, result.stdout
    return result


def probe(arguments, container=False, expected=0):
    if container:
        operation, host, *rest = arguments
        port = rest[0] if rest else '443'
        command = ['podman', 'run', '--rm', '--pull=never', '--network=pasta', '--cap-drop=all',
                   '--memory=128m', '--pids-limit=32',
                   '-v', '/opt/qualification/net-cert.pem:/test-ca.pem:ro',
                   IMAGE, '--cacert', '/test-ca.pem', '--fail', '--silent', '--show-error',
                   '--connect-timeout', '4', '--max-time', '8', '--write-out', '\n%{remote_ip}',
                   f'https://{host}:{port}/probe']
        result = run(command, user=True, expected=expected)
        if result.returncode == 0:
            body, remote = result.stdout.rsplit('\n', 1)
            if operation == 'dns':
                assert host == 'probe.test' and remote == '192.0.2.2', (host, remote)
                result.stdout = json.dumps([remote])
            else:
                result.stdout = body
        return result
    return run([sys.executable, '/opt/qualification/network_probe.py', *arguments], expected=expected)


def main():
    assert PROFILE['network']['interface'] == 'enp0s2'
    check_firewall_reload('/usr/bin/nft', Path('/etc/nftables.conf'))
    assert run(['systemctl', 'is-active', 'ladyboot-network-online.service']).stdout.strip() == 'active'
    run(['ip', '-4', 'addr', 'show', 'dev', 'enp0s2'])
    assert '192.0.2.10/24' in run(['ip', '-4', 'addr', 'show', 'dev', 'enp0s2']).stdout
    # Explicit system resolvers must win over the hostile DHCP DNS/NTP options.
    dns_status = run(['resolvectl', 'status']).stdout
    assert '192.0.2.1' in dns_status and '192.0.2.99' not in dns_status
    assert 'Fallback DNS Servers:' not in dns_status
    assert json.loads(probe(['dns', 'probe.test']).stdout) == ['192.0.2.2']
    assert json.loads(probe(['tls', 'probe.test']).stdout)['fixture'] == 'ladyboot-isolated-network'
    # Qualify time before expensive workload checks; both remain mandatory.
    check_nts()
    run(['podman', 'load', '--input', '/opt/qualification/network-smoke.tar.gz'], user=True, timeout=300)
    assert json.loads(probe(['dns', 'probe.test'], container=True).stdout) == ['192.0.2.2']
    assert json.loads(probe(['tls', 'probe.test'], container=True).stdout)['fixture'] == 'ladyboot-isolated-network'
    # A removed grant must stop NEW connections, then reapplication restores it.
    # Established connections retain the documented conntrack policy.
    policy = Path('/etc/nftables.conf')
    original = policy.read_text()
    flow = 'ip daddr 192.0.2.2 tcp dport 443 accept'
    assert original.count(flow) == 1
    try:
        policy.write_text(original.replace(flow, ''))
        run(['nft', '-f', str(policy)])
        for container in [False, True]:
            denied = probe(['tls', ENDPOINT], container=container, expected=None)
            assert denied.returncode != 0 and ('TimeoutError' in denied.stdout or 'timed out' in denied.stdout or 'Timeout was reached' in denied.stdout)
    finally:
        policy.write_text(original)
        run(['nft', '-f', str(policy)])
    for container in [False, True]:
        assert json.loads(probe(['tls', ENDPOINT], container=container).stdout)['fixture'] == 'ladyboot-isolated-network'
    print('LADYBOOT_FIREWALL_REVOKE_OK', flush=True)
    for container in [False, True]:
        for address, port in [('192.0.2.3', '443'), ('192.0.2.2', '444')]:
            denied = probe(['tls', address, port], container=container, expected=None)
            assert denied.returncode != 0 and ('TimeoutError' in denied.stdout or 'timed out' in denied.stdout or 'Timeout was reached' in denied.stdout), denied.stdout
    # Both destination services exist; the peer verifies them locally with TLS.
    state = request(ENDPOINT, path='/self-check')
    assert state['listeners_verified'] is True
    run(['podman', 'run', '-d', '--name=network-ingress', '--pull=never', '--network=pasta',
         '--cap-drop=all', '--memory=128m', '--pids-limit=32', '-p', '8080:8000',
         '--entrypoint=/bin/httpd', '-v', '/opt/qualification/http:/www:ro', IMAGE, '-f', '-p', '8000', '-h', '/www'], user=True)
    for _ in range(10):
        ingress = request(ENDPOINT, path='/ingress')
        if ingress[0].get('http_ok') and ingress[2].get('http_ok'):
            break
        time.sleep(1)
    assert ingress[0]['http_ok'] and ingress[2]['http_ok'], ingress
    assert ingress[1]['connected'] is False and ingress[1]['error'] == 'TimeoutError', ingress
    print('LADYBOOT_INGRESS ' + json.dumps(ingress), flush=True)
    run(['podman', 'rm', '-f', 'network-ingress'], user=True)
    before = request(ENDPOINT, path='/stop-dns')
    run(['resolvectl', 'flush-caches'])
    # Silence is an expected outcome only for this deliberate DNS outage.
    # The peer query counter and the still-working TLS control channel below
    # distinguish it from a dead peer or an unissued request.
    try:
        unavailable = run(['resolvectl', 'query', 'after-loss.test'], expected=None, timeout=90)
    except subprocess.TimeoutExpired as error:
        print(json.dumps({'event': 'dns-unavailable', 'timeout': error.timeout,
                          'output': (error.output or b'').decode(errors='replace')}), flush=True)
    else:
        assert unavailable.returncode != 0
    after = request(ENDPOINT)
    assert after['dns_queries'] > before['dns_queries'] and not after['dns_enabled']
    assert set(after['udp_destinations']) == {'192.0.2.1:53', '192.0.2.1:123'}, after
    print('LADYBOOT_NETWORK_OBSERVED ' + json.dumps(after), flush=True)
    request(ENDPOINT, path='/finish')
    # Mutate only the disposable VM. A failed firewall load must prevent networkd.
    # Stop activation sockets first: pending netlink/varlink requests otherwise
    # restart networkd and cancel the firewall stop job during this fault setup.
    run(['systemctl', 'stop', 'systemd-networkd.socket',
         'systemd-networkd-varlink.socket', 'systemd-networkd-varlink-metrics.socket',
         'systemd-networkd-resolve-hook.socket'])
    run(['systemctl', 'stop', 'systemd-networkd.service'])
    run(['systemctl', 'stop', 'ladyboot-firewall.service'])
    assert run(['systemctl', 'is-active', 'systemd-networkd.service'], expected=None).returncode != 0
    Path('/etc/nftables.conf').write_text('deliberately invalid nftables fixture\n')
    run(['systemctl', 'reset-failed'])
    failed = run(['systemctl', 'start', 'systemd-networkd.service'], expected=None)
    assert failed.returncode != 0
    assert run(['systemctl', 'is-active', 'systemd-networkd.service'], expected=None).returncode != 0
    assert run(['systemctl', 'is-failed', 'ladyboot-firewall.service'], expected=None).stdout.strip() == 'failed'
    print('LADYBOOT_NETWORK_OK', flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.stderr.flush()
        run(['journalctl', '-b', '--no-pager', '-n', '100'], expected=None)
        raise
    finally:
        run(['systemctl', 'poweroff', '--no-block'], expected=None)
