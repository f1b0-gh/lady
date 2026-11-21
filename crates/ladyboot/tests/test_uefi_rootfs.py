"""Delivered UEFI assets and installation tools; does not prove disk boot."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys

root = Path(sys.argv[1])
for name in ['bootupctl', 'skopeo', 'grub2-editenv', 'mkfs.ext4', 'mkfs.fat', 'fsfreeze', 'wipefs', 'nsenter']:
    assert (root / 'usr/bin' / name).is_symlink(), name
metadata = json.loads((root / 'usr/lib/bootupd/updates/EFI.json').read_text())
assert metadata['default-bootloader'] == 'Grub'
assert {p['name'] for p in metadata['versions']} == {'grub2', 'shim'}
assets = list((root / 'usr/lib/efi').rglob('*.efi')) + list((root / 'usr/lib/efi').rglob('*.EFI'))
assert len(assets) == 5, assets
for asset in assets:
    with asset.open('rb') as f:
        assert f.read(2) == b'MZ', asset
assert len(list((root / 'usr/lib/efi').rglob('shimx64.efi'))) == 1
assert (root / 'usr/lib/bootupd/grub2-static/grub-static-pre.cfg').is_file()
# OSTree deduplicates equal EFI files as hardlinks. FAT cannot preserve them.
# Exercise the actual delivered cp with bootupd's upstream installation options.
with tempfile.TemporaryDirectory(prefix='ladyboot-efi-copy-') as temporary:
    directory = Path(temporary)
    source = directory / 'EFI'
    source.mkdir()
    (source / 'vendor').mkdir()
    (source / 'BOOT').mkdir()
    (source / 'vendor/grubx64.efi').write_bytes(b'efi-copy-fixture')
    os.link(source / 'vendor/grubx64.efi', source / 'BOOT/grubx64.efi')
    destination = directory / 'destination'
    destination.mkdir()
    subprocess.run([str(root / 'usr/bin/cp'), '-rp', '--reflink=auto',
                    str(source), str(destination)], check=True, timeout=10)
    first, second = [destination / 'EFI' / name / 'grubx64.efi' for name in ['vendor', 'BOOT']]
    assert first.read_bytes() == second.read_bytes() == b'efi-copy-fixture'
    assert not os.path.samefile(first, second), 'bootupd cp must not preserve FAT-incompatible hardlinks'
print('Delivered UEFI assets verified; installation and boot require VM qualification')
