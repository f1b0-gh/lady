"""Validate the generated client config with ntpd-rs itself, without a daemon.

Only the certificate file location changes in this build-only copy: the supplied
path is the very same Nix CA bundle used by the image's /etc symlink. The daemon
is never launched and the host clock/network are never touched.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

root, ctl, bundle = map(Path, sys.argv[1:])
config = (root / 'etc/ntpd-rs/ntp.toml').read_text()
values = tomllib.loads(config)
assert all(source['certificate-authority'] == '/etc/ssl/certs/ca-certificates.crt'
           for source in values['source'])
assert (root / 'etc/ssl/certs/ca-certificates.crt').readlink() == bundle
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'ntp.toml'
    path.write_text(config.replace('/etc/ssl/certs/ca-certificates.crt', str(bundle)))
    subprocess.run([str(ctl), 'validate', '-c', str(path)], check=True, timeout=20)
print('Native NTS config parser passed with the identical delivered CA bundle')
