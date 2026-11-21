"""Negative control: the maintained DHCP-only need cannot provide runtime flows."""
import subprocess
import sys
import time
import traceback


def run(command, timeout=30):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    print(repr(command), result.returncode, result.stdout, flush=True)
    return result


try:
    for _ in range(30):
        address = run(['ip', '-4', 'addr', 'show', 'dev', 'enp0s2'])
        if '192.0.2.10/24' in address.stdout:
            break
        time.sleep(2)
    assert '192.0.2.10/24' in address.stdout
    dns = run([sys.executable, '/opt/qualification/network_probe.py', 'dns', 'probe.test'])
    assert dns.returncode != 0 and 'gaierror' in dns.stdout
    tls = run([sys.executable, '/opt/qualification/network_probe.py', 'tls', '192.0.2.2'])
    assert tls.returncode != 0 and 'TimeoutError' in tls.stdout
    assert run(['systemctl', 'is-active', 'systemd-resolved.service']).returncode != 0
    assert run(['systemctl', 'is-active', 'systemd-timesyncd.service']).returncode != 0
    print('LADYBOOT_LEGACY_DHCP_ONLY', flush=True)
except Exception:
    traceback.print_exc()
    sys.stderr.flush()
    run(['journalctl', '-b', '--no-pager', '-n', '70'])
    raise
finally:
    run(['systemctl', 'poweroff', '--no-block'])
