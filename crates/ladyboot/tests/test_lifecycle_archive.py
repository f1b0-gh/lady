"""Check the offline OCI conversion without changing the production payload."""
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile

LIMIT = 4 * 1024**3


def small(archive, name):
    member = archive.getmember(name)
    assert member.isfile() and member.size <= 1024**2, name
    return json.load(archive.extractfile(member))


def digest(stream):
    h = hashlib.sha256()
    count = 0
    while chunk := stream.read(1024**2):
        count += len(chunk)
        assert count <= LIMIT
        h.update(chunk)
    return 'sha256:' + h.hexdigest(), count


def blob(descriptor):
    algorithm, value = descriptor['digest'].split(':')
    assert algorithm == 'sha256' and len(value) == 64
    assert all(c in '0123456789abcdef' for c in value)
    return 'blobs/sha256/' + value


def normalize_dates(config):
    for entry in [config, *config.get('history', [])]:
        if 'created' in entry:
            entry['created'] = datetime.fromisoformat(entry['created'].replace('Z', '+00:00')).isoformat()
    return config


def main(original, converted):
    assert Path(original).stat().st_size <= LIMIT
    assert Path(converted).stat().st_size <= LIMIT
    with tarfile.open(original, 'r|*') as source:
        config = None
        for number, member in enumerate(source):
            assert number < 4096 and member.size <= LIMIT
            if member.isfile() and member.name.endswith('.json') and member.name != 'manifest.json':
                assert member.size <= 1024**2
                value = json.load(source.extractfile(member))
                if 'rootfs' in value:
                    assert config is None
                    config = value
        assert config is not None
    with tarfile.open(converted, 'r:') as archive:
        names = set()
        for number, member in enumerate(archive):
            assert number < 4096
            assert member.name not in names
            names.add(member.name)
            assert member.isfile() or member.isdir()
            assert member.size <= LIMIT
        assert small(archive, 'oci-layout')['imageLayoutVersion'] == '1.0.0'
        index = small(archive, 'index.json')
        assert len(index['manifests']) == 1
        manifest_desc = index['manifests'][0]
        manifest = small(archive, blob(manifest_desc))
        assert manifest['mediaType'] == 'application/vnd.oci.image.manifest.v1+json'
        assert normalize_dates(small(archive, blob(manifest['config']))) == normalize_dates(config)
        assert len(manifest['layers']) == len(config['rootfs']['diff_ids'])
        for descriptor in [manifest_desc, manifest['config'], *manifest['layers']]:
            with archive.extractfile(blob(descriptor)) as stream:
                actual, size = digest(stream)
            assert actual == descriptor['digest'] and size == descriptor['size']
        for layer, diff_id in zip(manifest['layers'], config['rootfs']['diff_ids']):
            assert layer['mediaType'] == 'application/vnd.oci.image.layer.v1.tar+gzip'
            with archive.extractfile(blob(layer)) as stream, gzip.GzipFile(fileobj=stream) as content:
                assert digest(content)[0] == diff_id
    print('OCI archive preserves config and uncompressed layer digests; compressed descriptors verified')


if __name__ == '__main__':
    main(*sys.argv[1:])
