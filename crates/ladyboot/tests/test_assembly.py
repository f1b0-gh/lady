import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

source = Path(__file__).resolve().parents[1] / 'nix' / 'inventory.py'

class InventoryTests(unittest.TestCase):
    def module(self):
        self.assertTrue(source.exists(), 'assembly inventory implementation is required')
        spec = importlib.util.spec_from_file_location('inventory', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_collision_requires_a_qualified_declared_winner(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for package in ['a', 'b']:
                (root / package / 'bin').mkdir(parents=True)
                (root / package / 'bin' / 'shared').write_text(package)
            dest = root / 'out'; dest.mkdir()
            selections = [{'selection': p, 'store_path': str(root / p)} for p in ['a', 'b']]
            with self.assertRaisesRegex(ValueError, 'collision'):
                module.link_commands(dest, selections, {})
            (dest / 'shared').unlink()
            module.link_commands(dest, selections, {'shared': {'winner': 'b', 'reason': 'requires full implementation'}})
            self.assertEqual((dest / 'shared').resolve().read_text(), 'b')

    def test_command_selection_refuses_missing_tools_and_excludes_unselected_tools(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            (root / 'out').mkdir()
            (root / 'bin' / 'wanted').write_text('selected')
            (root / 'bin' / 'other').write_text('unselected')
            selection = {'selection': 'tools', 'store_path': str(root), 'commands': ['absent']}
            with self.assertRaisesRegex(ValueError, 'missing declared commands'):
                module.link_commands(root / 'out', [selection], {})
            selection['commands'] = ['wanted']
            module.link_commands(root / 'out', [selection], {})
            self.assertEqual((root / 'out' / 'wanted').read_text(), 'selected')
            self.assertFalse((root / 'out' / 'other').exists())

    def test_inventory_hashes_generated_kernel_and_symlink_entries(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'usr/lib/modules/v1').mkdir(parents=True)
            (root / 'usr/lib/modules/v1/vmlinuz').write_bytes(b'kernel')
            (root / 'usr/lib/modules/v1/initramfs.img').write_bytes(b'initrd')
            (root / 'usr/lib/os-release').write_text('ID=test\n')
            (root / 'bin').symlink_to('usr/bin')
            result = module.scan(root)
            rows = {row['path']: row for row in result}
            self.assertEqual(rows['usr/lib/modules/v1/vmlinuz']['sha256'], hashlib.sha256(b'kernel').hexdigest())
            self.assertEqual(rows['bin']['target'], 'usr/bin')
            manifest = {'schema_version': 1, 'files': result}
            module.verify(root, manifest)
            (root / 'usr/lib/os-release').write_text('changed')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                module.verify(root, manifest)

    def test_inventory_detects_extra_files_and_does_not_follow_links(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'escape').symlink_to('/not/available')
            manifest = {'schema_version': 1, 'files': module.scan(root)}
            (root / 'extra').touch()
            with self.assertRaisesRegex(ValueError, 'inventory'):
                module.verify(root, manifest)

if __name__ == '__main__': unittest.main()

class ImageTests(unittest.TestCase):
    def test_image_layer_bytes_must_match_delivered_manifest(self):
        import io
        import tarfile
        source = Path(__file__).resolve().parents[1] / 'nix' / 'archive_inventory.py'
        self.assertTrue(source.exists(), 'image archive verifier is required')
        spec = importlib.util.spec_from_file_location('archive_inventory', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'image.tar'
            manifest = {'schema_version': 1, 'files': [{'path':'kernel','kind':'file','mode':0o444,'bytes':6,'sha256':hashlib.sha256(b'kernel').hexdigest()}]}
            manifest_bytes = json.dumps(manifest).encode()
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode='w') as archive:
                for name, data in [('kernel', b'kernel'), ('usr/share/ladyboot/inventory.json', manifest_bytes)]:
                    info = tarfile.TarInfo(name); info.size=len(data); info.mode=0o444
                    archive.addfile(info, io.BytesIO(data))
            with tarfile.open(image,'w') as archive:
                for name, data in [('manifest.json',b'[{"Layers":["layer.tar"]}]'),('layer.tar',layer.getvalue())]:
                    info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
            module.verify(image, manifest_bytes)
            manifest['files'][0]['sha256']='0'*64
            with self.assertRaisesRegex(ValueError,'inventory'):
                module.verify(image,json.dumps(manifest).encode())

    def test_archive_without_embedded_inventory_is_refused(self):
        import io
        import tarfile
        source = Path(__file__).resolve().parents[1] / 'nix' / 'archive_inventory.py'
        spec = importlib.util.spec_from_file_location('archive_inventory', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / 'image.tar'
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode='w'):
                pass
            with tarfile.open(image, 'w') as archive:
                for name,data in [('manifest.json',b'[{"Layers":["layer.tar"]}]'), ('layer.tar', layer.getvalue())]:
                    info=tarfile.TarInfo(name); info.size=len(data); archive.addfile(info,io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, 'missing embedded inventory'):
                module.verify(image, b'{"schema_version":1,"files":[]}')

class HardlinkCollisionTests(unittest.TestCase):
    def test_hardlink_collisions_are_rejected_in_both_orders_and_across_layers(self):
        import io
        import tarfile
        source = Path(__file__).resolve().parents[1] / 'nix' / 'archive_inventory.py'
        spec = importlib.util.spec_from_file_location('archive_inventory_collision', source)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        manifest = {'schema_version':1,'files':[{'path':name,'kind':'file','mode':0o444,'bytes':4,'sha256':hashlib.sha256(b'good').hexdigest()} for name in ['target','kernel']]}
        manifest_bytes=json.dumps(manifest).encode()
        variants = [ [('link','kernel'),('file','kernel')], [('file','kernel'),('link','kernel')], [('link','kernel'),('link','kernel')], [('mode','kernel')] ]
        for entries in variants:
            for separate_layers in [False, True]:
                with self.subTest(entries=entries, separate_layers=separate_layers), tempfile.TemporaryDirectory() as directory:
                    layers=[]
                    groups=[[('file','target')]+entries+[('manifest',module.MANIFEST)]] if not separate_layers else [[('file','target')]+entries[:1],entries[1:]+[('manifest',module.MANIFEST)]]
                    for group in groups:
                        layer=io.BytesIO()
                        with tarfile.open(fileobj=layer,mode='w') as archive:
                            for kind,name in group:
                                info=tarfile.TarInfo(name);info.mode=0o444
                                if kind in ['link','mode']:
                                    if kind=='mode': info.mode=0o777
                                    info.type=tarfile.LNKTYPE;info.linkname='target';archive.addfile(info)
                                else:
                                    data=manifest_bytes if kind=='manifest' else b'good' if name=='target' else b'evil'
                                    info.size=len(data);archive.addfile(info,io.BytesIO(data))
                        layers.append(layer.getvalue())
                    image=Path(directory)/'image.tar'
                    descriptor=json.dumps([{'Layers':[f'layer{i}.tar' for i in range(len(layers))]}]).encode()
                    with tarfile.open(image,'w') as archive:
                        for name,data in [('manifest.json',descriptor)]+[(f'layer{i}.tar',data) for i,data in enumerate(layers)]:
                            info=tarfile.TarInfo(name);info.size=len(data);archive.addfile(info,io.BytesIO(data))
                    with self.assertRaisesRegex(ValueError, 'collision|duplicate|conflicting'):
                        module.verify(image,manifest_bytes)
