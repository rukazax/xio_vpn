"""Bounded packaging tests: no Flutter, Go, Wine, driver or application launch."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('client_windows_build',
                                               ROOT / 'client/build_windows_on_linux.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)


class ClientWindowsVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.helper = BUILD.version_helper(ROOT)
        self.args = argparse.Namespace(engine_cache=self.root / 'engine',
                                       runtime_template=self.root / 'runtime',
                                       wine_prefix=self.root / 'wine', go='go')
        self.put('app/pubspec.yaml', 'version: 0.24.2+5019\n')
        for relative in ['client/brand/client-windows.ico', 'LICENSE', 'COPYRIGHT',
                         'THIRD-PARTY-0.22.md', 'client/README.ru.md', 'client/README.en.md',
                         'tooling/cross-platform/windows.manifest', 'runtime/data/icudtl.dat',
                         'runtime/flutter_windows.dll', 'runtime/libexec/wintun.dll',
                         'runtime/libexec/WINTUN-LICENSE.txt']:
            self.put(relative, 'fixture')
        self.put('tooling/cross-platform/windows_runner.cpp',
                 'wc.lpszClassName=L"XIOClient019"; CreateWindowW(wc.lpszClassName,L"XIO");')
        self.commands = []
        self.prepared_version = None
        self.compiler_fixture = None
        self.seen = {}
        self.mock_pe = True

    def put(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode('utf-8'))
        return path

    def fake_run(self, cmd, **kwargs):
        cmd = list(map(str, cmd))
        self.commands.append((cmd, kwargs))
        stage = '.build-support/client-windows/'
        if len(cmd) > 1 and cmd[1].endswith('prepare_platform.py'):
            source = self.prepared_version or (self.root / 'app/pubspec.yaml').read_text()
            self.put(stage + 'app/pubspec.yaml', source)
        elif cmd[:3] == ['flutter', 'build', 'bundle']:
            self.put(stage + 'cross/assets/AssetManifest.bin', b'client assets')
            self.put(stage + 'app/.dart_tool/flutter_build/kernel/app.dill', b'client kernel')
        elif cmd[0] == 'x86_64-w64-mingw32-g++':
            exe = self.root / (stage + 'cross/XIOClient/XIOClient.exe')
            if self.compiler_fixture:
                shutil.copy2(self.compiler_fixture, exe)
            else:
                exe.write_bytes(b'cached old runner')
        elif cmd[0] == 'xvfb-run':
            self.put(stage + 'cross/XIOClient/data/app.so', b'client AOT fixture')
        elif cmd[:2] == ['go', 'build']:
            self.put(stage + 'cross/XIOClient/libexec/xio-tunnel.exe', b'amd64 tunnel fixture')

    def fake_stamp(self, exe, version):
        self.assertEqual(exe.read_bytes(), b'cached old runner')
        quad = '.'.join(map(str, self.helper.version_parts(version)))
        self.seen = {'FileVersion': version, 'ProductVersion': version,
                     'fileVersion': quad, 'productVersion': quad}
        return self.seen.copy()

    def package(self):
        with patch.object(BUILD, 'version_helper', return_value=self.helper), \
             patch.object(BUILD, 'run', side_effect=self.fake_run):
            if self.mock_pe:
                with patch.object(self.helper, 'stamp_version', side_effect=self.fake_stamp) as stamp, \
                     patch.object(self.helper, 'read_version', side_effect=lambda _: self.seen.copy()) as read:
                    result = BUILD.build(self.args, self.root)
                    self.assertEqual(stamp.call_count, 2)
                    self.assertEqual(read.call_count, 2)
                    return result
            return BUILD.build(self.args, self.root)

    def check_package(self, version):
        self.put('app/pubspec.yaml', f'version: {version}\n')
        archive = self.package()
        release = version.split('+')[0]
        self.assertEqual(archive, self.root / f'releases/client-{release}/XIO-Client-{release}-windows-x64.zip')
        self.assertFalse(archive.with_suffix('.zip.part').exists())
        resource = (self.root / '.build-support/client-windows/cross/windows.rc').read_text()
        version = version if '+' in version else version + '+0'
        quad = ','.join(map(str, self.helper.version_parts(version)))
        for field in ['FILEVERSION', 'PRODUCTVERSION']:
            self.assertIn(f'{field} {quad}', resource)
        for field in ['FileVersion', 'ProductVersion']:
            self.assertIn(f'VALUE "{field}", "{version}\\0"', resource)
        self.assertIn('"ProductName", "XIO Client\\0"', resource)
        source = (self.root / '.build-support/client-windows/cross/runner.cpp').read_text()
        self.assertIn('L"XIOClient"', source)
        self.assertIn('L"XIO Client"', source)
        with zipfile.ZipFile(archive) as zipped:
            self.assertIn('XIOClient/XIOClient.exe', zipped.namelist())
            self.assertIn('XIOClient/data/app.so', zipped.namelist())
            self.assertNotIn('XIOClient/XIO.exe', zipped.namelist())
            self.assertTrue(all(name.startswith('XIOClient/') for name in zipped.namelist()))
        flutter = next(cmd for cmd, _ in self.commands if cmd[:3] == ['flutter', 'build', 'bundle'])
        self.assertIn('--target=lib/client_main.dart', flutter)
        self.assertIn('--dart-define=XIO_CLIENT_ONLY=true', flutter)
        self.assertIn('--target-platform=windows-x64', flutter)
        go_env = next(kw['env'] for cmd, kw in self.commands if cmd[:2] == ['go', 'build'])
        self.assertEqual((go_env['GOOS'], go_env['GOARCH'], go_env['CGO_ENABLED']), ('windows', 'amd64', '0'))
        return archive

    def test_current_pubspec_drives_resource_stamp_and_package(self):
        self.check_package(self.helper.pubspec_version(ROOT / 'app/pubspec.yaml'))

    def test_alternate_pubspec_is_not_hardcoded(self):
        self.check_package('9.9.9+999')

    def test_missing_build_normalizes_to_zero(self):
        self.check_package('1.2.3')
        self.assertEqual(self.seen['FileVersion'], '1.2.3+0')

    def test_prepared_version_mismatch_fails_before_compilation(self):
        self.prepared_version = 'version: 0.1.0+1\n'
        with self.assertRaisesRegex(RuntimeError, 'Prepared Client pubspec'):
            self.package()
        self.assertEqual(len(self.commands), 1)
        self.assertFalse((self.root / 'releases').exists())

    def test_invalid_or_oversized_version_fails_before_processes(self):
        for source in ['version: broken\n', 'version: 1.2.3+65536\n']:
            with self.subTest(source=source):
                self.put('app/pubspec.yaml', source)
                with self.assertRaises(ValueError):
                    self.package()
                self.assertEqual(self.commands, [])
                self.assertFalse((self.root / '.build-support').exists())

    def test_each_readback_field_is_required(self):
        version = '9.9.9+999'
        valid = {'FileVersion': version, 'ProductVersion': version,
                 'fileVersion': '9.9.9.999', 'productVersion': '9.9.9.999'}
        for key in valid:
            with self.subTest(field=key):
                wrong = dict(valid, **{key: 'stale'})
                with patch.object(self.helper, 'stamp_version'), \
                     patch.object(self.helper, 'read_version', return_value=wrong), \
                     self.assertRaisesRegex(RuntimeError, 'VERSIONINFO mismatch'):
                    BUILD.stamp_runner(self.root / 'unused.exe', version, self.helper)

    def test_readback_failure_prevents_archive(self):
        with patch.object(BUILD, 'stamp_runner', side_effect=RuntimeError('bad cached version')):
            with self.assertRaisesRegex(RuntimeError, 'bad cached version'):
                self.package()
        self.assertFalse((self.root / 'releases').exists())

    def test_final_readback_failure_prevents_archive(self):
        original_stamp = BUILD.stamp_runner
        calls = []

        def stamp(exe, version, helper):
            calls.append(exe)
            if len(calls) == 2:
                raise RuntimeError('final cached version mismatch')
            return original_stamp(exe, version, helper)

        with patch.object(BUILD, 'stamp_runner', side_effect=stamp):
            with self.assertRaisesRegex(RuntimeError, 'final cached version mismatch'):
                self.package()
        self.assertEqual(len(calls), 2)
        self.assertFalse((self.root / 'releases').exists())

    @unittest.skipUnless(os.environ.get('XIO_CLIENT_PE_FIXTURE'), 'set XIO_CLIENT_PE_FIXTURE to a real Client PE')
    def test_real_cached_pe_alternate_version_in_archive(self):
        # All compilers/processes remain mocked, but PE stamping, reading and ZIP
        # bytes are real. Only a scratch copy is changed; never execute the PE.
        self.compiler_fixture = Path(os.environ['XIO_CLIENT_PE_FIXTURE'])
        original = self.compiler_fixture.read_bytes()
        self.mock_pe = False
        archive = self.check_package('9.9.9+999')
        with zipfile.ZipFile(archive) as zipped:
            extracted = self.put('extracted/XIOClient.exe', zipped.read('XIOClient/XIOClient.exe'))
        seen = self.helper.read_version(extracted)
        self.assertEqual(seen['FileVersion'], '9.9.9+999')
        self.assertEqual(seen['ProductVersion'], '9.9.9+999')
        self.assertEqual(seen['fileVersion'], '9.9.9.999')
        self.assertEqual(seen['productVersion'], '9.9.9.999')
        self.assertEqual(self.compiler_fixture.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
