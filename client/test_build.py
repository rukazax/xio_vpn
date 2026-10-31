import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name('build.py')

def load_module():
    spec = importlib.util.spec_from_file_location('xio_client_build_fixture', MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class ClientStageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.stage = Path(self.temp.name) / 'candidate'
        self.module = load_module()
        self.module.ROOT = self.root
        self.module.STAGE = self.stage
        self.module.APP = self.stage / 'app'
        self.put('app/pubspec.yaml', 'name: xio\ndescription: Full app\nversion: 0.23.1+5016\nflutter:\n  assets:\n    - assets/xio-server.tar.gz\n')
        for name in ['pubspec.lock', 'analysis_options.yaml']:
            self.put('app/' + name, 'fixture')
        self.put('app/lib/client_main.dart', '// client fixture')
        ns = 'http://schemas.android.com/apk/res/android'
        permission = chr(36) + '{installPermission}'
        self.put('app/android/app/src/main/AndroidManifest.xml',
            '<manifest xmlns:android="' + ns + '"><uses-permission android:name="' + permission + '"/>'
            '<application android:label="XIO"><activity android:name=".MainActivity"/>'
            '<service android:name=".UpdateJob"/><receiver android:name=".UpdateCleanupReceiver"/>'
            '</application></manifest>')
        self.put('app/android/app/build.gradle.kts', '// fixture == ".MainActivity"')
        self.put('app/android/build.gradle.kts', '// fixture')
        self.put('app/android/settings.gradle.kts', '// fixture')
        self.put('app/android/gradle.properties', 'force-version-code-ignoring-abi=true')
        self.put('app/android/app/libs/rivet.aar', b'fake AAR fixture')
        for folder in ['help', 'licenses', 'l10n', 'security']:
            self.put('app/assets/' + folder + '/fixture.txt', folder)
        self.put('app/assets/fonts/NotoSans-Regular.ttf', b'fake font fixture')
        self.put('app/assets/xio-server.tar.gz', b'forbidden server fixture')
        self.put('app/assets/install-wireguard.sh', 'forbidden installer fixture')
        self.put('vendor/amneziawg/android/src/GoBackend.java', '// protected bridge fixture')
        for language in ['ru', 'en']:
            for document in ['privacy', 'legal']:
                self.put('client/' + document + '.' + language + '.txt', 'Client ' + document)
        self.run = patch.object(self.module.subprocess, 'run').start()
        self.addCleanup(patch.stopall)

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode('utf-8'))
        return path

    def prepare(self):
        try:
            self.module.prepare()
        except OSError as error:
            if getattr(error, 'winerror', None) == 1314:
                self.skipTest('Windows token cannot create staging directory symlink')
            raise

    def test_unknown_version_fails_before_writes(self):
        self.put('app/pubspec.yaml', 'version: 9.9.9+1\n# version: 0.23.1+5016\n')
        with self.assertRaises(RuntimeError): self.module.prepare()
        self.assertFalse(self.stage.exists())

    def test_unowned_staging_is_not_removed(self):
        canary = self.stage / 'app/lib/keep.txt'
        canary.parent.mkdir(parents=True)
        canary.write_text('keep')
        with self.assertRaises(RuntimeError): self.module.prepare()
        self.assertEqual(canary.read_text(), 'keep')

    def test_foreign_owned_staging_is_not_removed(self):
        self.stage.mkdir()
        marker = self.stage / '.xio-client-stage.json'
        marker.write_text(json.dumps({'owner': 'other-owner', 'sourceRoot': str(self.root)}))
        before = marker.read_bytes()
        with self.assertRaises(RuntimeError): self.module.prepare()
        self.assertEqual(marker.read_bytes(), before)

    def test_prepare_removes_server_assets_and_keeps_source_unchanged(self):
        original = (self.root / 'app/pubspec.yaml').read_bytes()
        self.prepare()
        app = self.module.APP
        self.assertEqual((self.root / 'app/pubspec.yaml').read_bytes(), original)
        self.assertFalse((app / 'assets/xio-server.tar.gz').exists())
        self.assertFalse((app / 'assets/install-wireguard.sh').exists())
        self.assertIn('XIO Client', (app / 'pubspec.yaml').read_text())
        manifest = (app / 'android/app/src/main/AndroidManifest.xml').read_text()
        self.assertNotIn('UpdateJob', manifest)
        self.assertNotIn('installPermission', manifest)
        self.assertIn('app.xio.xio.MainActivity', manifest)
        self.assertEqual(json.loads((self.stage / '.xio-client-stage.json').read_text())['owner'], 'xio-client-staging-v1')

    def test_native_aar_and_awg_source_are_in_input_hashes(self):
        self.prepare()
        inputs = json.loads((self.stage / 'source-inputs.json').read_text())
        aar_keys = [key for key in inputs if key.replace(chr(92), '/') == 'android/app/libs/rivet.aar']
        self.assertEqual(len(aar_keys), 1)
        self.assertEqual(inputs[aar_keys[0]], hashlib.sha256(b'fake AAR fixture').hexdigest())
        self.assertIn('vendor/amneziawg/android/src/GoBackend.java', inputs)

    def test_refresh_only_owned_source_and_preserve_other_stage_files(self):
        self.prepare()
        canary = self.stage / 'keep-build.log'
        canary.write_text('keep')
        stale = self.module.APP / 'lib/stale.dart'
        stale.write_text('stale')
        self.prepare()
        self.assertFalse(stale.exists())
        self.assertEqual(canary.read_text(), 'keep')

if __name__ == '__main__': unittest.main(verbosity=2)
