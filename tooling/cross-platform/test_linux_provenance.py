import argparse
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import linux_provenance as gate


def tar_bytes(files, mode='w:gz', extra=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode=mode) as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if extra:
            tar.addfile(extra[0], io.BytesIO(extra[1]) if extra[1] is not None else None)
    return raw.getvalue()


def deb_bytes(files, extra=None):
    raw = bytearray(b'!<arch>\n')
    for name, content in [('debian-binary', b'2.0\n'),
                          ('control.tar.gz', tar_bytes({'control': (
                              b'Package: fixture\nVersion: 1.0\nArchitecture: all\n'
                              b'Maintainer: Fixture <fixture@example.invalid>\n'
                              b'Description: valid tiny fixture\n')})),
                          ('data.tar.xz', tar_bytes(files, 'w:xz', extra))]:
        raw += f'{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(content):<10}`\n'.encode('ascii')
        raw += content
        if len(content) % 2:
            raw += b'\n'
    return bytes(raw)


def full_payload(recipe=28, translation='current'):
    mirrors = {name: (f'RECIPE={recipe}\n' if member == 'admin.py' else member + '\n').encode()
               for name, member in gate.MIRRORS.items()}
    mirrors['xio-bootstrap.sh'] = b'#!/bin/sh\n# current bootstrap\n'
    mirrors['xio-server-update.py'] = f'RECIPE={recipe}\n'.encode()
    archive = tar_bytes({member: mirrors[name] for name, member in gate.MIRRORS.items()})
    manifest = {'schema': 1, 'recipeVersion': recipe, 'sha256': gate.digest(archive),
                'bootstrapSha256': gate.digest(mirrors['xio-bootstrap.sh']),
                'updateSha256': gate.digest(mirrors['xio-server-update.py']),
                'artifacts': {name: gate.digest(data) for name, data in mirrors.items()}}
    return dict(mirrors, **{'xio-server.tar.gz': archive,
                           'xio-server-release.json': json.dumps(manifest).encode(),
                           'l10n/en.json': json.dumps({'cascade': translation}).encode(),
                           'l10n/ru.json': b'{"cascade":"current ru"}'})


class LinuxProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / 'app'
        self.payload = full_payload()
        self.write_source(self.payload)
        self.expected = gate.capture(self.app, 'full')

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def write_source(self, payload, app=None):
        app = app or self.app
        self.put(app / 'pubspec.yaml', b'name: fixture\nversion: 9.9.9+999\n')
        for name, data in payload.items():
            self.put(app / 'assets' / name, data)

    def package(self, payload, container, flavor='full', extra=None):
        prefix = ('opt/xio' if flavor == 'full' else 'opt/xio-client') if container == 'deb' else (
            'XIO' if flavor == 'full' else 'XIOClient')
        files = {prefix + '/data/flutter_assets/assets/' + name: data for name, data in payload.items()}
        path = self.root / f'same-release-name.{container}'
        return self.put(path, deb_bytes(files, extra) if container == 'deb' else tar_bytes(files, extra=extra))

    def test_good_staged_payload_passes_both_containers(self):
        for container in ('deb', 'tar'):
            with self.subTest(container=container):
                result = gate.verify_package(self.package(self.payload, container), self.expected)
                self.assertEqual(result['recipeVersion'], 28)
                self.assertEqual(result['checkedAssets'], len(self.payload))

    def test_same_named_stale_recipe_payload_fails_both(self):
        for container in ('deb', 'tar'):
            with self.subTest(container=container), self.assertRaisesRegex(gate.ProvenanceError, 'differs from staged'):
                gate.verify_package(self.package(full_payload(27), container), self.expected)

    def test_same_recipe_tampered_archive_fails_both(self):
        stale = dict(self.payload, **{'xio-server.tar.gz': self.payload['xio-server.tar.gz'] + b'tampered'})
        for container in ('deb', 'tar'):
            with self.subTest(container=container), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(self.package(stale, container), self.expected)

    def test_manifest_bootstrap_updater_and_translation_bytes_all_gate(self):
        for name in ['xio-server-release.json', 'xio-bootstrap.sh', 'xio-server-update.py', 'l10n/en.json']:
            for container in ('deb', 'tar'):
                bad = dict(self.payload, **{name: self.payload[name] + b' '})
                with self.subTest(asset=name, container=container), self.assertRaisesRegex(gate.ProvenanceError, 'differs from staged'):
                    gate.verify_package(self.package(bad, container), self.expected)

    def test_missing_or_extra_localization_member_fails_both(self):
        for container in ('deb', 'tar'):
            for extra in (False, True):
                bad = dict(self.payload)
                if extra:
                    bad['l10n/obsolete.json'] = b'{}'
                else:
                    del bad['l10n/ru.json']
                with self.subTest(container=container, extra=extra), self.assertRaisesRegex(gate.ProvenanceError, 'Localization member set'):
                    gate.verify_package(self.package(bad, container), self.expected)

    def test_manifest_internally_inconsistent_source_fails_before_build(self):
        for field in ['sha256', 'bootstrapSha256', 'updateSha256', 'recipeVersion']:
            bad = full_payload()
            manifest = json.loads(bad['xio-server-release.json'])
            manifest[field] = 27 if field == 'recipeVersion' else '0' * 64
            bad['xio-server-release.json'] = json.dumps(manifest).encode()
            self.write_source(bad)
            with self.subTest(field=field), self.assertRaises(gate.ProvenanceError):
                gate.capture(self.app, 'full')

    def test_recipe_label_cannot_hide_stale_archive_admin(self):
        bad = full_payload(27)
        manifest = json.loads(bad['xio-server-release.json'])
        manifest['recipeVersion'] = 28
        bad['xio-server-release.json'] = json.dumps(manifest).encode()
        self.write_source(bad)
        with self.assertRaisesRegex(gate.ProvenanceError, 'recipe mismatch'):
            gate.capture(self.app, 'full')

    def test_source_change_after_snapshot_fails(self):
        self.put(self.app / 'assets/l10n/en.json', b'{"cascade":"changed during build"}')
        with self.assertRaisesRegex(gate.ProvenanceError, 'changed since'):
            gate.verify_source(self.app, self.expected)

    def test_bundle_preflight_detects_stale_assets(self):
        bundle = self.root / 'bundle'
        for name, data in self.payload.items():
            self.put(bundle / 'data/flutter_assets/assets' / name, data)
        gate.verify_bundle(bundle, self.expected)
        self.put(bundle / 'data/flutter_assets/assets/l10n/en.json', b'old translation')
        with self.assertRaises(gate.ProvenanceError):
            gate.verify_bundle(bundle, self.expected)

    def test_duplicate_traversal_and_symlink_assets_fail_both(self):
        for container in ('deb', 'tar'):
            prefix = 'opt/xio' if container == 'deb' else 'XIO'
            name = prefix + '/data/flutter_assets/assets/l10n/en.json'
            duplicate = tarfile.TarInfo(name)
            duplicate.size = 2
            traversal = tarfile.TarInfo('../outside')
            traversal.size = 2
            link = tarfile.TarInfo(prefix + '/data/flutter_assets/assets/l10n/injected.json')
            link.type, link.linkname = tarfile.SYMTYPE, '/etc/passwd'
            ancestor = tarfile.TarInfo(prefix + '/data/flutter_assets')
            ancestor.type, ancestor.linkname = tarfile.SYMTYPE, '/tmp/foreign-assets'
            drive = tarfile.TarInfo('C:/foreign')
            drive.size = 2
            for item, data in [(duplicate, b'{}'), (traversal, b'{}'), (link, None), (ancestor, None), (drive, b'{}')]:
                with self.subTest(container=container, name=item.name), self.assertRaises(gate.ProvenanceError):
                    gate.verify_package(self.package(self.payload, container, extra=(item, data)), self.expected)

    def test_client_good_and_server_payload_exclusions_both(self):
        client = {name: data for name, data in self.payload.items() if name.startswith('l10n/')}
        app = self.root / 'prepared-client'
        self.write_source(client, app)
        expected = gate.capture(app, 'client')
        for container in ('deb', 'tar'):
            gate.verify_package(self.package(client, container, 'client'), expected)
            for name in ['xio-server.tar.gz', 'xio-bootstrap.sh', 'xio_vici/admin.py', 'unexpected.bin']:
                bad = dict(client, **{name: b'forbidden'})
                with self.subTest(container=container, name=name), self.assertRaises(gate.ProvenanceError):
                    gate.verify_package(self.package(bad, container, 'client'), expected)
        self.put(app / 'assets/xio-server.tar.gz', b'forbidden')
        with self.assertRaises(gate.ProvenanceError):
            gate.capture(app, 'client')

    def test_client_server_payload_outside_flutter_assets_rejected(self):
        client = {name: data for name, data in self.payload.items() if name.startswith('l10n/')}
        app = self.root / 'prepared-client'
        self.write_source(client, app)
        expected = gate.capture(app, 'client')
        for container in ('deb', 'tar'):
            info = tarfile.TarInfo('unrelated/xio-server.tar.gz')
            info.size = 6
            with self.subTest(container=container), self.assertRaisesRegex(gate.ProvenanceError, 'server-only'):
                gate.verify_package(self.package(client, container, 'client', (info, b'server')), expected)

    def test_invalid_deb_is_rejected(self):
        path = self.put(self.root / 'bad.deb', b'!<arch>\ntruncated')
        with self.assertRaises(gate.ProvenanceError):
            gate.verify_package(path, self.expected)

    def test_wrong_container_cannot_masquerade_as_other_output(self):
        deb = self.package(self.payload, 'deb').read_bytes()
        tar = self.package(self.payload, 'tar').read_bytes()
        for name, data in [('misnamed.deb.part', tar), ('misnamed.tar.gz.part', deb)]:
            with self.subTest(name=name), self.assertRaises(gate.ProvenanceError):
                gate.verify_package(self.put(self.root / name, data), self.expected)

    def run_packager(self, flavor, tamper=None, real_dpkg=False):
        source = (HERE / 'package-ubuntu.py' if flavor == 'full' else
                  HERE.parents[1] / 'client/build_linux.py')
        spec = importlib.util.spec_from_file_location('linux_packaging_fixture_' + flavor, source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        payload = self.payload if flavor == 'full' else {
            name: data for name, data in self.payload.items() if name.startswith('l10n/')}
        app = self.app if flavor == 'full' else self.root / '.build-support/client-linux/app'
        self.write_source(payload, app)
        bundle = app / 'build/linux/x64/release/bundle'
        for name, data in payload.items():
            self.put(bundle / 'data/flutter_assets/assets' / name, data)
        executable = 'XIO' if flavor == 'full' else 'XIOClient'
        self.put(bundle / executable, b'fixture executable, never executed')
        self.put(bundle / 'libexec/xio-tunnel', b'fixture tunnel, never executed')
        for name in ['app/assets/icons/green_dark_0.png', 'client/brand/client-linux.png',
                     'LICENSE', 'COPYRIGHT', 'THIRD-PARTY-0.22.md',
                     'client/README.ru.md', 'client/README.en.md']:
            self.put(self.root / name, b'fixture')
        import subprocess
        real_run = subprocess.run
        calls = []
        prefix = 'opt/xio' if flavor == 'full' else 'opt/xio-client'

        def run(cmd, **kwargs):
            cmd = list(map(str, cmd))
            if cmd[0] != 'dpkg-deb':
                self.assertEqual(cmd[:2], ['go', 'build'])
                return
            self.assertIn('-Zxz', cmd)  # Portable DEB inspection, including Python 3.10 on Windows.
            if real_dpkg:
                return real_run(cmd, **kwargs)
            stage, output = Path(cmd[-2]), Path(cmd[-1])
            files = {path.relative_to(stage).as_posix(): path.read_bytes()
                     for path in stage.rglob('*') if path.is_file()
                     and not path.relative_to(stage).as_posix().startswith('DEBIAN/')}
            if tamper == 'deb':
                files[prefix + '/data/flutter_assets/assets/l10n/en.json'] = b'stale DEB translation'
            output.write_bytes(deb_bytes(files))
            if tamper == 'source':
                self.put(app / 'assets/l10n/en.json', b'changed source')

        def verify(path, expected):
            calls.append(path)
            if tamper == 'tar' and str(path).endswith('.tar.gz.part'):
                stale = dict(payload, **{'l10n/en.json': b'stale tar translation'})
                root = 'XIO' if flavor == 'full' else 'XIOClient'
                path.write_bytes(tar_bytes({root + '/data/flutter_assets/assets/' + name: data
                                           for name, data in stale.items()}))
            return gate.verify_package(path, expected)

        # Windows fixture host may lack symlink privilege; the installer link is
        # not a payload asset. Debian real-dpkg test uses the genuine symlink.
        import contextlib
        symlink = (patch.object(module.os, 'symlink', side_effect=lambda src, dst: Path(dst).write_text(src))
                   if sys.platform == 'win32' and flavor == 'full' else contextlib.nullcontext())
        with patch.object(module.subprocess, 'run', side_effect=run), \
             patch.object(module, 'verify_package', side_effect=verify), symlink:
            result = module.package(self.root) if flavor == 'full' else module.build(
                argparse.Namespace(prepared=True, go='go'), self.root)
        self.assertEqual(len(calls), 2)
        for path in result:
            self.assertTrue(path.is_file())
            self.assertIn('9.9.9', path.name)
        if flavor == 'client':
            self.assertIn('Version: 9.9.9\n', (self.root / '.build-support/client-linux/deb/DEBIAN/control').read_text())
        return result

    def test_full_and_client_packagers_gate_both_real_containers(self):
        for flavor in ('full', 'client'):
            with self.subTest(flavor=flavor):
                self.run_packager(flavor)

    def test_full_and_client_final_deb_or_tar_tampering_fails_closed(self):
        for flavor in ('full', 'client'):
            for tamper in ('deb', 'tar'):
                with self.subTest(flavor=flavor, tamper=tamper), self.assertRaises(gate.ProvenanceError):
                    self.run_packager(flavor, tamper)
                out = self.root / ('releases' if flavor == 'full' else 'releases/client-9.9.9')
                self.assertEqual(list(out.glob('*.deb')), [])
                self.assertEqual(list(out.glob('*.tar.gz')), [])

    def test_packager_rejects_source_mutation_during_packaging(self):
        with self.assertRaisesRegex(gate.ProvenanceError, 'changed since'):
            self.run_packager('full', 'source')

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell release-hook regression requires pwsh')
    def test_actual_release_assert_function_accepts_good_and_rejects_stale_payloads(self):
        import os
        import subprocess
        shutil.copy2(HERE / 'linux_provenance.py', self.put(
            self.root / 'tooling/cross-platform/linux_provenance.py', b''))
        expected = self.put(self.root / 'expected.json', json.dumps(self.expected).encode())
        script = self.put(self.root / 'assert-fixtures.ps1', b'''$ErrorActionPreference='Stop'
$RepoRoot=$env:XIO_TEST_LINUX_ROOT
$script:Tools=@{Python=$env:XIO_TEST_PYTHON}
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:XIO_TEST_RELEASE_SCRIPT,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'release PowerShell syntax error' }
foreach($name in @('Assert-DebAndTar','Read-FileHead','Invoke-Native')) {
 $node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
 if(-not $node) { throw "missing function $name" }
 Invoke-Expression $node.Extent.Text
}
Assert-DebAndTar -Deb (Join-Path $RepoRoot 'same-release-name.deb') -Tar (Join-Path $RepoRoot 'same-release-name.tar') -Expected (Join-Path $RepoRoot 'expected.json')
''')
        random = os.urandom(1100000)  # Existing release sanity gate requires >1 MB.
        for bad_container in (None, 'deb', 'tar'):
            for container in ('deb', 'tar'):
                info = tarfile.TarInfo(('opt/xio' if container == 'deb' else 'XIO') + '/XIO')
                info.size = len(random)
                payload = self.payload if container != bad_container else full_payload(27)
                self.package(payload, container, extra=(info, random))
            env = dict(os.environ, XIO_TEST_LINUX_ROOT=str(self.root), XIO_TEST_PYTHON=sys.executable,
                       XIO_TEST_RELEASE_SCRIPT=str(HERE.parents[1] / 'tools/release/build-all.ps1'))
            result = subprocess.run(['pwsh', '-NoProfile', '-File', str(script)],
                                    env=env, capture_output=True, text=True)
            with self.subTest(stale=bad_container):
                if bad_container is None:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('Linux artifact provenance failed', result.stderr)

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'real dpkg-deb requires Linux; fixture builds only')
    def test_real_dpkg_full_and_client_fixture_packages(self):
        self.run_packager('full', real_dpkg=True)
        self.run_packager('client', real_dpkg=True)


if __name__ == '__main__':
    unittest.main()
