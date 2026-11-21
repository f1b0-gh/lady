"""Verify Docker-format bootc archive layers without extracting untrusted paths."""
import hashlib
import json
from pathlib import PurePosixPath, Path
import sys
import tarfile

MANIFEST = 'usr/share/ladyboot/inventory.json'
MAX_BYTES = 32 * 1024**3


def normalized(name):
    while name.startswith('./'):
        name = name[2:]
    name = name.rstrip('/')
    if name in ['', '.']:
        return ''
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ['', '.', '..'] for part in name.split('/')):
        raise ValueError('unsafe archive inventory path')
    return name


def verify(image, manifest_bytes):
    expected_manifest = json.loads(manifest_bytes)
    expected = {row['path']: row for row in expected_manifest['files']}
    observed = {}
    links = {}
    total = 0
    count = 0
    found_inventory = False
    with tarfile.open(image, 'r:*') as outer:
        descriptor = outer.getmember('manifest.json')
        if descriptor.size > 1024 * 1024:
            raise ValueError('oversized image inventory descriptor')
        description = json.load(outer.extractfile(descriptor))
        if len(description) != 1 or not 1 <= len(description[0]['Layers']) <= 64:
            raise ValueError('expected one bounded bootc image')
        for layer in description[0]['Layers']:
            if normalized(layer) != layer:
                raise ValueError('unsafe layer path')
            with tarfile.open(fileobj=outer.extractfile(layer), mode='r|*') as archive:
                for member in archive:
                    name = normalized(member.name)
                    if not name:
                        continue
                    count += 1
                    if count > 300_000:
                        raise ValueError('archive file count limit')
                    # Deferred hardlinks must never replace an observed path,
                    # regardless of layer or archive entry order.
                    if name in links or (member.islnk() and (name in observed or name == MANIFEST)):
                        raise ValueError('hardlink collision in image inventory')
                    row = {'path': name, 'mode': member.mode}
                    if member.isdir():
                        row['kind'] = 'directory'
                    elif member.issym():
                        row.update(kind='symlink', target=member.linkname)
                    elif member.islnk():
                        links[name] = (normalized(member.linkname), member.mode)
                        continue
                    elif member.isfile():
                        total += member.size
                        if total > MAX_BYTES:
                            raise ValueError('archive byte limit')
                        stream = archive.extractfile(member)
                        if name == MANIFEST:
                            if found_inventory:
                                raise ValueError('duplicate embedded inventory')
                            found_inventory = True
                            if member.size != len(manifest_bytes) or stream.read(len(manifest_bytes) + 1) != manifest_bytes:
                                raise ValueError('image inventory manifest differs from assembled rootfs')
                            continue
                        digest = hashlib.sha256()
                        for block in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(block)
                        row.update(kind='file', bytes=member.size, sha256=digest.hexdigest())
                    else:
                        raise ValueError('unsupported image entry type')
                    if name in observed and observed[name] != row:
                        raise ValueError('conflicting image layer inventory entries')
                    observed[name] = row
    if not found_inventory:
        raise ValueError("missing embedded inventory")
    for name, (target, mode) in links.items():
        if target not in observed or observed[target]['kind'] != 'file':
            raise ValueError('unsupported image hardlink')
        if mode != observed[target]['mode']:
            raise ValueError('hardlink mode collision in image inventory')
        observed[name] = dict(observed[target], path=name)
    if observed != expected:
        missing = sorted(set(expected) - set(observed))[:5]
        extra = sorted(set(observed) - set(expected))[:5]
        changed = [name for name in expected.keys() & observed.keys() if expected[name] != observed[name]][:5]
        raise ValueError(f'image inventory mismatch: missing={missing}, extra={extra}, changed={changed}')


if __name__ == '__main__':
    verify(sys.argv[1], Path(sys.argv[2]).read_bytes())
    print('Delivered image archive matches the rootfs inventory')
