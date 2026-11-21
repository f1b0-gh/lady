"""Native parser regression for a pinned, negotiated NTP endpoint."""
from pathlib import Path
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / 'ntp.toml'
    path.write_text('''[[source]]
mode = "nts"
address = "nts.test:4460"
expected-ntp-address = "192.0.2.1:123"
[synchronization]
minimum-agreeing-sources = 1
single-step-panic-threshold = 1800
startup-step-panic-threshold = 1800
''')
    result = subprocess.run([sys.argv[1], 'validate', '-c', str(path)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
print('Explicit expected NTP endpoint accepted by native client parser')
