"""Build-time assembly verification; never installed as an OS controller."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MANIFEST = 'usr/share/ladyboot/inventory.json'


def link_commands(destination, selections, overrides):
    owners = {}
    for package in selections:
        available = set()
        for directory in ['bin', 'sbin']:
            source = Path(package['store_path']) / directory
            if not source.is_dir():
                continue
            for binary in sorted(source.iterdir()):
                if package.get('commands') is not None and binary.name not in package['commands']:
                    continue
                if not binary.is_file():
                    continue
                available.add(binary.name)
                previous = owners.get(binary.name)
                if previous:
                    if previous[1].resolve() == binary.resolve():
                        continue
                    rule = overrides.get(binary.name)
                    if not rule or not rule.get('reason') or rule['winner'] not in [previous[0], package['selection']]:
                        raise ValueError(f'command collision: {binary.name}: {previous[0]} / {package["selection"]}')
                    if rule['winner'] == previous[0]:
                        continue
                    (destination / binary.name).unlink()
                owners[binary.name] = (package['selection'], binary)
                (destination / binary.name).symlink_to(binary)
        missing = set(package.get('commands', [])) - available
        if missing:
            raise ValueError(f'missing declared commands for {package["selection"]}: {sorted(missing)}')
    return {name: owner for name, (owner, _) in sorted(owners.items())}


def scan(root):
    rows = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            info = path.lstat()
            row = {'path': relative, 'mode': stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                row.update(kind='file', bytes=info.st_size, sha256=digest.hexdigest())
            elif stat.S_ISDIR(info.st_mode):
                row.update(kind='directory')
            else:
                raise ValueError(f'unsupported delivered file type: {relative}')
            rows.append(row)
    return sorted(rows, key=lambda row: row['path'])


def verify(root, manifest):
    if manifest['schema_version'] != 1 or scan(root) != manifest['files']:
        raise ValueError('delivered filesystem differs from assembly inventory')


def main():
    operation, root, plan_file = sys.argv[1:]
    root = Path(root)
    plan = json.loads(Path(plan_file).read_text())
    if operation == 'link':
        link_commands(root / 'usr/bin', plan['runtime_packages'], plan['command_overrides'])
    elif operation == 'manifest':
        manifest = {'schema_version': 1, 'resolved_plan': plan, 'self_excluded': MANIFEST,
                    'files': scan(root)}
        (root / MANIFEST).write_text(json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n')
        verify(root, manifest)
    elif operation == 'verify':
        verify(root, json.loads((root / MANIFEST).read_text()))
    else:
        raise ValueError('unknown inventory operation')

if __name__ == '__main__':
    main()
