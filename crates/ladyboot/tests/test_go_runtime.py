"""Read delivered ELF build metadata without executing guest programs."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1])
reader, go = sys.argv[2:4]
plan = json.loads((root / 'usr/share/ladyboot/plan.json').read_text())
packages = {p['selection']: p for p in plan['runtime_packages']}
assert packages['podman']['version'] == '6.2.0'
assert packages['skopeo']['version'] == '1.25.1'
assert packages['crun']['version'] == '1.31'
if plan['runtime_variant'] == 'debug':
    assert packages['criu']['version'] == '4.3.1'
store = root / 'usr/lib/nix/store'
expected = {'.podman-wrapped', '.skopeo-wrapped', 'quadlet', 'rootlessport'}
if plan['runtime_variant'] == 'debug':
    expected.add('.runc-wrapped')
found = set()
for path in store.rglob('*'):
    if path.name not in expected or path.is_symlink() or not path.is_file():
        continue
    with path.open('rb') as stream:
        assert stream.read(4) == b'\x7fELF', path
    result = subprocess.run([reader, str(path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert len(result.stdout) < 1024**2
    info = json.loads(result.stdout)
    assert info['GoVersion'] == 'go1.26.11', (path, info['GoVersion'])
    modules = {p['Path']: p['Version'] for p in info.get('Deps', [])}
    for module, version in {
        'go.podman.io/image/v5': 'v5.42.1',
        'go.podman.io/storage': 'v1.65.1',
        'github.com/go-jose/go-jose/v4': 'v4.1.9',
        'golang.org/x/net': 'v0.62.0',
        'go.opentelemetry.io/otel/trace': 'v1.47.0',
        'github.com/moby/sys/user': 'v0.4.1',
        'github.com/cilium/ebpf': 'v0.22.0',
    }.items():
        if module in modules:
            assert modules[module] == version, (path, module, modules[module])
    if path.name in {'.podman-wrapped', '.skopeo-wrapped'}:
        assert modules['go.podman.io/image/v5'] == 'v5.42.1'
        assert modules['go.podman.io/storage'] == 'v1.65.1'
    if path.name == 'quadlet':
        native = json.loads(subprocess.check_output([go, 'version', '-m', '-json', str(path)], timeout=30))
        native.pop('File', None)
        assert info == native, 'ELF-section reader disagrees with native Go reader'
        with tempfile.TemporaryDirectory() as temporary:
            truncated = Path(temporary) / 'truncated.elf'
            with path.open('rb') as stream:
                truncated.write_bytes(stream.read(1024))
            assert subprocess.run([reader, str(truncated)], capture_output=True, timeout=30).returncode != 0
        assert subprocess.run([reader, str(root / 'usr/share/ladyboot/plan.json')],
                              capture_output=True, timeout=30).returncode != 0
    found.add(path.name)
assert found == expected, (found, expected)
print('Delivered Go compiler/module build metadata matches the scoped security locks')
