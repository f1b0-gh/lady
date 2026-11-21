"""Real NTS checks inside the disposable DUT; never run on the build host."""
import json
import re
from pathlib import Path
import socket
import subprocess
import time

from network_probe import request

CONFIG = Path('/etc/ntpd-rs/ntp.toml')
ENDPOINT = '192.0.2.2'


def run(*args):
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=30)
    return result.stdout


def state():
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(3)
        sock.connect('/run/ntpd-rs/observe')
        deadline = time.monotonic() + 3
        def exact(count):
            data = bytearray()
            while len(data) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("NTS observation deadline")
                sock.settimeout(remaining)
                chunk = sock.recv(count - len(data))
                if not chunk:
                    raise ValueError('truncated NTS observation frame')
                data.extend(chunk)
            return data
        # ntpd-rs 1.9.0 writes a big-endian u64 length before the JSON payload.
        size = int.from_bytes(exact(8), 'big')
        if size > 65536:
            raise ValueError('NTS observation exceeds budget')
        return json.loads(exact(size))


def synchronized(value):
    return (value['system']['stratum'] < 16
            and value['system']['leap_indicator'] != 'Unknown'
            and len(value['sources']) == 1
            and value['sources'][0]['nts_cookies'] is not None
            and value['sources'][0]['address'] == '192.0.2.1:123')


def wait(predicate, seconds=60):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            last = state()
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.5)
            continue
        if predicate(last):
            return last
        time.sleep(0.5)
    raise AssertionError(f'NTS observation deadline: {last}')


def invocation_id():
    return run('systemctl', 'show', 'ntpd-rs.service', '--property=InvocationID', '--value').strip()


def cold(config):
    run('systemctl', 'stop', 'ntpd-rs.service')
    assert not Path('/run/ntpd-rs/observe').exists(), 'old observation survived stop'
    CONFIG.write_text(config)
    run('ntp-ctl', 'validate', '-c', str(CONFIG))
    run('systemctl', 'start', 'ntpd-rs.service')
    pid = run('systemctl', 'show', 'ntpd-rs.service', '--property=MainPID', '--value').strip()
    status = dict(line.split(':', 1) for line in Path('/proc/' + pid + '/status').read_text().splitlines())
    uid = int(status['Uid'].split()[0])
    plan = json.loads(Path('/usr/share/ladyboot/plan.json').read_text())
    assert uid not in {0, plan['requested']['podman']['uid']}, 'time/workload identities overlap'
    assert int(status['CapEff'], 16) == int(status['CapBnd'], 16) == 1 << 25
    assert status['NoNewPrivs'].strip() == '1'
    return invocation_id()


def record(name, value):
    # Observations contain counts/timestamps, never raw NTS cookie/key material.
    print('LADYBOOT_NTS ' + json.dumps({'case': name, 'system': value['system'],
                                      'sources': value['sources']}), flush=True)


def check():
    assert Path('/opt/qualification/nts/ca.pem').is_file(), 'fixture-only CA missing'
    original = CONFIG.read_text()
    # Only fixture trust and polling cadence change; TLS checks and clock bounds
    # remain those of the delivered configuration. No host clock is involved.
    trusted = original.replace('/etc/ssl/certs/ca-certificates.crt', '/opt/qualification/nts/ca.pem')
    trusted += '\n[source-defaults]\npoll-interval-limits = { min = 0, max = 1 }\ninitial-poll-interval = 0\n'
    extra_ca = Path('/etc/ssl/certs/ladyboot-qualification-only.pem')
    # Model a PEM retained in /etc across an update: it must not extend trust.
    with extra_ca.open('xb') as stream:
        stream.write(Path('/opt/qualification/nts/ca.pem').read_bytes())
    try:
        for mode, reason, config in [
            ('valid', 'UnknownIssuer', trusted.replace('/opt/qualification/nts/ca.pem', '/etc/ssl/certs/ca-certificates.crt')),
            ('wrong-name', 'NotValidForName', trusted),
            ('expired', 'Expired', trusted),
            ('future', 'NotValidYet', trusted),
        ]:
            request(ENDPOINT, path='/nts/' + mode, timeout=40)
            invocation = cold(config)
            wait(lambda value: not synchronized(value))
            deadline = time.monotonic() + 40
            journal = ''
            while time.monotonic() < deadline:
                journal = run('journalctl', '--no-pager', '-o', 'cat', '_SYSTEMD_INVOCATION_ID=' + invocation)
                current = state()
                assert current['system']['stratum'] == 16 and not current['sources'], 'hostile source synchronized the client'
                if reason in journal:
                    break
                time.sleep(1)
            assert reason in journal, (reason, journal)
            record(reason, state())

        for mode, endpoint in [('outside', '192.0.2.3:123'), ('wrong-port', '192.0.2.1:124')]:
            request(ENDPOINT, path='/nts/' + mode, timeout=40)
            before = request(ENDPOINT)
            invocation = cold(trusted)
            deadline = time.monotonic() + 40
            journal = ''
            while time.monotonic() < deadline:
                journal = run('journalctl', '--no-pager', '-o', 'cat', '_SYSTEMD_INVOCATION_ID=' + invocation)
                value = state()
                assert value['system']['stratum'] == 16 and not value['sources']
                if 'Negotiated NTP endpoint refused by source policy' in journal:
                    break
                time.sleep(1)
            clean = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', journal)
            assert any('Negotiated NTP endpoint refused by source policy' in line
                       and re.search(r'\baddress=' + re.escape(endpoint) + r'(?:\s|$)', line)
                       for line in clean.splitlines()), ('endpoint mismatch in refusal log', endpoint, clean)
            after = request(ENDPOINT)
            assert after['nts_ke_syn'] > before['nts_ke_syn']
            assert after['udp_destinations'].get(endpoint, 0) == before['udp_destinations'].get(endpoint, 0)
            record('negotiated-' + mode + '-rejected', value)

        request(ENDPOINT, path='/nts/ke-only', timeout=40)
        # Native startup resets after three unanswered polls. Only this handover
        # uses 16-second polls so the bounded peer transition cannot exhaust them.
        plain_config = trusted.replace('min = 0, max = 1', 'min = 4, max = 4').replace(
            'initial-poll-interval = 0', 'initial-poll-interval = 4')
        cold(plain_config)
        baseline = wait(lambda value: bool(value['sources']) and value['sources'][0]['nts_cookies'] is not None)
        before = request(ENDPOINT)
        request(ENDPOINT, path='/nts/plain-only', timeout=40)
        deadline = time.monotonic() + 40
        while True:
            after = request(ENDPOINT)
            value = state()
            assert value['system']['stratum'] == 16 and not synchronized(value)
            assert len(value['sources']) == 1 and value['sources'][0]['id'] == baseline['sources'][0]['id'], 'NTS source lost during plain handover'
            assert value['sources'][0]['last_update'] == baseline['sources'][0]['last_update'], 'unauthenticated measurement accepted'
            # Two replies span a subsequent poll, allowing the client to process
            # the first reply before asserting it accepted no measurement.
            if after['plain_responses'] >= before['plain_responses'] + 2:
                break
            if time.monotonic() >= deadline:
                raise AssertionError(('plain response fixture was not exercised',
                                      {'before': before, 'after': after, 'client': value}))
            time.sleep(0.5)
        record('plain-ntp-rejected', value)

        request(ENDPOINT, path='/nts/valid', timeout=40)
        cold(trusted)
        value = wait(synchronized)
        assert re.search(r'return value:\s+0\b', run('adjtimex')), 'guest kernel clock is not synchronized'
        record('authenticated', value)
        warm_invocation = invocation_id()
        source_id = value['sources'][0]['id']
        request(ENDPOINT, path='/nts/drop-ke', timeout=40)
        # Sample AFTER the peer acknowledged the cut; earlier in-flight progress
        # cannot satisfy the next-measurement proof.
        baseline = state()
        assert synchronized(baseline)
        last_update = baseline['sources'][0]['last_update']
        value = wait(lambda value: synchronized(value)
                     and value['sources'][0]['id'] == source_id
                     and value['sources'][0]['last_update'] != last_update)
        assert invocation_id() == warm_invocation, 'warm-cookie test restarted the client'
        record('warm-cookies-ke-unavailable', value)
        before = request(ENDPOINT)
        cold_invocation = cold(trusted)
        time.sleep(8)
        value = state()
        after = request(ENDPOINT)
        assert after['nts_ke_syn'] > before['nts_ke_syn'], 'cold KE attempt unobserved'
        assert value['system']['stratum'] == 16 and not value['sources']
        record('cold-ke-unavailable', value)
        request(ENDPOINT, path='/nts/valid', timeout=40)
        recovered = wait(synchronized)
        assert invocation_id() == cold_invocation, 'recovery restarted the client'
        record('recovered-authenticated', recovered)
        print('LADYBOOT_NTS_OK', flush=True)
    finally:
        run('systemctl', 'stop', 'ntpd-rs.service')
        CONFIG.write_text(original)
        extra_ca.unlink()
