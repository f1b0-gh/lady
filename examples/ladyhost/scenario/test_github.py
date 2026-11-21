"""Host bootstrap regression cases; no network or credentials are used."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('jjpr_github',Path(__file__).parents[1]/'github.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class BootstrapTests(unittest.TestCase):
    def test_repository_receipt_alone_is_not_prepared(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)
            config={'provider':'github','endpoint':'https://api.github.com','gh_cli':'/opt/gh',
                    'expected_actor':'owner','owner':'owner','repository':'repo','workspace':str(state/'workspace')}
            (state/'config.json').write_text(json.dumps(config))
            (state/'repository.json').write_text(json.dumps({'id':1}))
            answers=[json.dumps({'login':'owner','id':1}),json.dumps({'id':1,'private':True})]
            with patch.object(module,'run',side_effect=answers):
                with self.assertRaisesRegex(RuntimeError,'incomplete'):
                    module.prepare(state)


if __name__=='__main__':
    unittest.main()
