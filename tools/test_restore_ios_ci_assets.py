#!/usr/bin/env python3
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile
import importlib.util
_spec = importlib.util.spec_from_file_location('restore_ios_ci_assets', Path(__file__).with_name('restore-ios-ci-assets.py'))
asset = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(asset)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.assets = self.root / 'app/assets'
        self.assets.mkdir(parents=True)
        self.content = b'reviewed-resource-fixture'
        self.digest = hashlib.sha256(self.content).hexdigest()
        (self.assets / 'xio-server-release.json').write_text(json.dumps({'sha256': self.digest}))
        self.target = self.assets / 'xio-server.tar.gz'

    def package(self, content=None):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as output:
            output.writestr('XIO/data/flutter_assets/assets/xio-server.tar.gz', self.content if content is None else content)
            output.writestr('../../escape.txt', b'must-not-be-extracted')
        return stream.getvalue()

    def download(self, data, digest=None):
        return mock.patch.multiple(asset, ZIP_BYTES=len(data), ZIP_SHA256=digest or hashlib.sha256(data).hexdigest())

    def test_existing_valid_never_downloads(self):
        self.target.write_bytes(self.content)
        with mock.patch.object(asset.urllib.request, 'urlopen', side_effect=AssertionError('unexpected network')):
            asset.restore(self.root)
        self.assertEqual(self.target.read_bytes(), self.content)

    def test_existing_invalid_is_preserved(self):
        self.target.write_bytes(b'existing-owner-data')
        with self.assertRaisesRegex(RuntimeError, 'preserved'):
            asset.restore(self.root)
        self.assertEqual(self.target.read_bytes(), b'existing-owner-data')

    def test_verified_member_only(self):
        data = self.package()
        with self.download(data), mock.patch.object(asset.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            asset.restore(self.root)
        self.assertEqual(self.target.read_bytes(), self.content)
        self.assertFalse((self.root / 'escape.txt').exists())
        self.assertFalse((self.root.parent / 'escape.txt').exists())

    def test_bad_zip_digest_is_rejected(self):
        data = self.package()
        with self.download(data, '0' * 64), mock.patch.object(asset.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            with self.assertRaisesRegex(RuntimeError, 'SHA-256/size mismatch'):
                asset.restore(self.root)
        self.assertFalse(self.target.exists())

    def test_bad_resource_digest_is_rejected(self):
        data = self.package(b'different-resource')
        with self.download(data), mock.patch.object(asset.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            with self.assertRaisesRegex(RuntimeError, 'checked-in recipe'):
                asset.restore(self.root)
        self.assertFalse(self.target.exists())


if __name__ == '__main__':
    unittest.main()
