import unittest
from pathlib import Path
from launcher_manifest import install_aliases, validate_manifest

class LauncherManifestTest(unittest.TestCase):
    def setUp(self):
        self.source = (Path(__file__).resolve().parent.parent/'app/android/app/src/main/AndroidManifest.xml').read_text()
    def test_current_manifest_and_idempotent_regeneration(self):
        validate_manifest(self.source)
        first = install_aliases(self.source)
        self.assertEqual(first, install_aliases(first))
    def test_service_attributes_cannot_drop_launchers(self):
        for declaration in ['<service android:stopWithTask="false" android:name=".XioVpnService"', '<service android:name=".XioVpnService" android:stopWithTask="false"']:
            source = self.source.replace('<service android:stopWithTask="false" android:name=".XioVpnService"', declaration)
            validate_manifest(install_aliases(source))
    def test_missing_target_fails_closed(self):
        with self.assertRaises(ValueError):install_aliases(self.source.replace('android:name=".MainActivity"', 'android:name=".RenamedActivity"'))
    def test_other_activity_intents_preserved(self):
        source = self.source.replace('</activity>', '<intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter></activity>', 1)
        self.assertIn('android.intent.action.VIEW', install_aliases(source))
    def test_missing_launcher_rejected(self):
        import re
        source = re.sub(r'<activity-alias\b.*?</activity-alias>', '', self.source, flags=re.S)
        with self.assertRaises(AssertionError):validate_manifest(source)
        validate_manifest(install_aliases(source))

if __name__ == '__main__':unittest.main()
