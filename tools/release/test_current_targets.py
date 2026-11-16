"""Structured contract/parser/security regressions; no apps/devices/signing keys used."""
from pathlib import Path
import base64
from contextlib import ExitStack
import copy
import importlib.util
import json
import tempfile
from types import SimpleNamespace
import struct
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci = load('current_targets')
signing = load('ci_signing_material')
SHA = 'a' * 40


class CurrentTargetsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lock = {'sourceSha': SHA, 'version': '9.9.9+999', 'nativeSourceFresh': True,
                     'nativeAarMatchesMetadata': True, 'stagedServerSourceFresh': True,
                     'assets': {'schema': 1, 'flavor': 'full', 'appVersion': '9.9.9+999', 'recipeVersion': None,
                                'files': {'l10n/en.json': ci.assets.digest(b'{}')}}}

    def packages(self, target):
        expected = ci.contract(target, '9.9.9')
        for name in expected:
            (self.root / name).write_bytes(b'not a real package - orchestration fixture')
        return expected

    def archive(self, rows):
        path = self.root / 'fixture.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in rows:
                archive.writestr(name, data)
        return path

    def test_reviewed_matrix_keeps_both_phone_arm_targets_and_no_x86_32(self):
        expected = ci.contract('android', '9.9.9')
        self.assertEqual(len(expected), 5)  # Published reviewed Full2 + Client3, not invented four each.
        for flavor in ['Full', 'Client']:
            for abi in ['arm64-v8a', 'armeabi-v7a']:
                self.assertIn(f'XIO-{flavor}-9.9.9-android-{abi}.apk', expected)
        self.assertFalse(any('-x86.apk' in name or '-x86_64.apk' in name for name in expected))
        self.assertEqual(len(ci.contract('ubuntu', '9.9.9')), 4)
        self.assertEqual(len(ci.contract('windows', '9.9.9')), 2)

    def test_empty_missing_and_wrong_version_cannot_pass_any_target(self):
        for target in ['android', 'ubuntu', 'windows']:
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir=self.root) as directory:
                folder = Path(directory)
                expected = ci.contract(target, '9.9.9')
                with self.assertRaisesRegex(RuntimeError, 'Artifact set mismatch'):
                    ci.artifact_set(folder, target, expected)
                for name in expected:
                    (folder / name).write_bytes(b'fixture')
                first = next(iter(expected))
                # Rename only known owned fixture after checking the exact source/destination.
                original, other = folder / first, folder / first.replace('9.9.9', '0.0.1')
                self.assertEqual(original.parent, folder)
                original.rename(other)
                with self.assertRaisesRegex(RuntimeError, 'Artifact set mismatch'):
                    ci.artifact_set(folder, target, expected)

    def test_duplicate_artifact_name_in_other_directory_rejected(self):
        expected = self.packages('android')
        extra = self.root / 'other'
        extra.mkdir()
        (extra / next(iter(expected))).write_bytes(b'fixture')
        with self.assertRaisesRegex(RuntimeError, 'duplicate artifact'):
            ci.artifact_set(self.root, 'android', expected)

    def test_orchestration_invokes_every_content_verifier_not_just_names(self):
        for target in ['android', 'ubuntu', 'windows']:
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir=self.root) as directory:
                folder = Path(directory)
                expected = ci.contract(target, '9.9.9')
                for name in expected:
                    (folder / name).write_bytes(b'orchestration fixture, content verifier mocked')
                with ExitStack() as stack:
                    stack.enter_context(patch.object(ci, 'capture', return_value=self.lock))
                    validators = [stack.enter_context(patch.object(ci, name, return_value={}))
                                  for name in ['android', 'windows', 'linux_identity']]
                    payload_gate = stack.enter_context(patch.object(ci.assets, 'verify_package'))
                    receipt = ci.verify(self.root, self.lock, folder, target, SHA, folder, folder)
                    self.assertTrue(receipt['candidateArtifactsAccepted'])
                    self.assertFalse(receipt['physicalDeviceAccepted'])
                    self.assertEqual(len(receipt['artifacts']), len(expected))
                    active = validators[['android', 'windows', 'linux_identity'].index(
                        {'android': 'android', 'windows': 'windows', 'ubuntu': 'linux_identity'}[target])]
                    self.assertEqual(active.call_count, len(expected))
                    self.assertEqual(payload_gate.call_count, 4 if target == 'ubuntu' else 0)

    def test_native_or_staged_source_not_ready_and_mutated_source_fail(self):
        for field in ['nativeSourceFresh', 'nativeAarMatchesMetadata', 'stagedServerSourceFresh']:
            bad = copy.deepcopy(self.lock)
            bad[field] = False
            with self.subTest(field=field), patch.object(ci, 'capture', return_value=bad):
                with self.assertRaisesRegex(RuntimeError, 'NOT_READY'):
                    ci.verify(self.root, bad, self.root, 'android', SHA, self.root)
        with patch.object(ci, 'capture', return_value={'other': 'source'}):
            with self.assertRaisesRegex(RuntimeError, 'changed after capture'):
                ci.verify(self.root, self.lock, self.root, 'android', SHA, self.root)

    def test_sdk_cannot_be_omitted_and_content_failures_propagate(self):
        self.packages('android')
        with patch.object(ci, 'capture', return_value=self.lock):
            with self.assertRaisesRegex(RuntimeError, 'no signature/native-verification bypass'):
                ci.verify(self.root, self.lock, self.root, 'android', SHA)
            with patch.object(ci, 'android', side_effect=RuntimeError('actual content mismatch')):
                with self.assertRaisesRegex(RuntimeError, 'actual content mismatch'):
                    ci.verify(self.root, self.lock, self.root, 'android', SHA, self.root)

    def test_exact_apk_identity_version_and_client_policy(self):
        good = "package: name='app.xio.client' versionCode='999' versionName='9.9.9'\napplication-label:'XIO Client'\nsdkVersion:'26'\ntargetSdkVersion:'36'"
        ci.android_identity(good, 'client', '9.9.9', '999')
        for bad in [good.replace('app.xio.client', 'app.xio.xio'), good.replace("versionCode='999'", "versionCode='998'"),
                    good + '\nandroid.permission.REQUEST_INSTALL_PACKAGES', good.replace('XIO Client', 'XIO')]:
            with self.assertRaises(RuntimeError):
                ci.android_identity(bad, 'client', '9.9.9', '999')

    def test_wrong_or_missing_certificate_rejected_before_native_checks(self):
        good = "package: name='app.xio.client' versionCode='999' versionName='9.9.9'\napplication-label:'XIO Client'\nsdkVersion:'26'\ntargetSdkVersion:'36'"
        for signature in ['Verified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate SHA-256 digest: ' + 'b'*64,
                          'Verified using v2 scheme (APK Signature Scheme v2): true']:
            with patch.object(ci, 'sdk_tool', side_effect=lambda sdk, name: Path(name)), \
                 patch.object(ci, 'run', side_effect=[good, signature]):
                with self.assertRaisesRegex(RuntimeError, 'signing certificate'):
                    ci.android(self.root / 'absent.apk', 'client', 'arm64-v8a', self.lock, self.root)

    def test_actual_zip_asset_bytes_and_client_exclusions(self):
        snapshot = ci.client_snapshot(self.lock)
        prefix = 'assets/flutter_assets/assets/'
        good = [(prefix + 'l10n/en.json', b'{}')]
        ci.zip_payload(self.archive(good), prefix, snapshot)
        for bad in [[(good[0][0], b'{"stale":true}')], good + [(prefix + 'l10n/extra.json', b'{}')],
                    good + [('foreign/xio-server.tar.gz', b'old server')], good + [('../escape', b'bad')],
                    good + [(prefix + 'L10N/EN.JSON', b'{}')]]:
            with self.subTest(members=bad), self.assertRaises((RuntimeError, ci.assets.ProvenanceError)):
                ci.zip_payload(self.archive(bad), prefix, snapshot)

    def test_compile_proof_requires_both_outputs_and_never_claims_release(self):
        with patch.object(ci, 'capture', return_value=self.lock):
            with self.assertRaisesRegex(RuntimeError, 'Missing required'):
                ci.compile_proof(self.root, self.lock, SHA, 'windows', self.root/'missing', self.root/'missing2')
        full, client = self.root/'full', self.root/'client'
        full.mkdir(); client.mkdir()
        (full/'XIO.exe').write_bytes(b'MZ compile fixture')
        (client/'XIOClient.exe').write_bytes(b'MZ compile fixture')
        with patch.object(ci, 'capture', return_value=self.lock), patch.object(ci.assets, 'verify_bundle'):
            result = ci.compile_proof(self.root, self.lock, SHA, 'windows', full, client)
            self.assertTrue(result['compileOnly'])
            self.assertFalse(result['candidateArtifactsAccepted'])
            self.assertEqual(len(result['compiledOutputs']), 2)

    def test_pe_identity_rejects_stale_fixed_strings_and_full_identity_in_client(self):
        path = self.root / 'resource-parser-mock.exe'
        raw = bytearray(72)
        raw[:2] = b'MZ'
        struct.pack_into('<I', raw, 0x3c, 64)
        struct.pack_into('<H', raw, 68, 0x8664)
        path.write_bytes(raw)
        values = {'fileVersion': '9.9.9.999', 'productVersion': '9.9.9.999',
                  'FileVersion': '9.9.9+999', 'ProductVersion': '9.9.9+999'}
        block = SimpleNamespace(children=[SimpleNamespace(key='ProductName', text='XIOClient'),
                                          SimpleNamespace(key='OriginalFilename', text='XIOClient.exe')])
        module = SimpleNamespace(read_version=lambda _: values, version_parts=lambda _: (9,9,9,999),
            read_sections=lambda _: [], find_version_leaf=lambda *args: SimpleNamespace(rva=0, size=72),
            rva_to_offset=lambda *args: 0, parse_node=lambda *args: SimpleNamespace(child=lambda _: SimpleNamespace(children=[block])))
        with patch.object(ci, 'pe_module', return_value=module):
            ci.pe_identity(path, 'client', '9.9.9+999')
            for field in list(values):
                original = values[field]
                values[field] = '0.0.1'
                with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'Stale PE'):
                    ci.pe_identity(path, 'client', '9.9.9+999')
                values[field] = original
            block.children[0].text = 'XIO'
            with self.assertRaisesRegex(RuntimeError, 'product identity'):
                ci.pe_identity(path, 'client', '9.9.9+999')

    def test_receipt_check_rejects_partial_wrong_mode_and_postverify_missing_packages(self):
        expected = self.packages('android')
        receipt = {'sourceSha': SHA, 'target': 'android', 'candidateArtifactsAccepted': True,
                   'sourceLockSha256': ci.assets.digest(json.dumps(self.lock, sort_keys=True).encode()),
                   'physicalDeviceAccepted': False, 'realDriverGuiAccepted': False, 'published': False,
                   'artifacts': [{'file': name, 'bytes': (self.root/name).stat().st_size,
                                  'sha256': ci.sha(self.root/name)} for name in expected]}
        ci.receipt_check(self.lock, receipt, 'android', SHA, self.root, True)
        partial = copy.deepcopy(receipt)
        partial['artifacts'].pop()
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            ci.receipt_check(self.lock, partial, 'android', SHA, self.root, True)
        with self.assertRaisesRegex(RuntimeError, 'acceptance mode'):
            ci.receipt_check(self.lock, receipt, 'android', SHA, self.root, False)
        first = self.root / next(iter(expected))
        self.assertEqual(first.parent, self.root)
        first.write_bytes(b'tampered after verify')
        with self.assertRaisesRegex(RuntimeError, 'changed/missing'):
            ci.receipt_check(self.lock, receipt, 'android', SHA, self.root, True)
        first.unlink()
        with self.assertRaisesRegex(RuntimeError, 'Artifact set mismatch'):
            ci.receipt_check(self.lock, receipt, 'android', SHA, self.root, True)

    def test_cli_requires_receipt_even_if_source_json_exists_for_uploader(self):
        lock = self.root/'source.json'
        lock.write_text(json.dumps(self.lock))
        with patch('sys.argv', ['current_targets.py', 'receipt-check', '--source-sha', SHA,
                               '--source-lock', str(lock), '--target', 'android', '--report', str(self.root/'absent.json')]):
            with self.assertRaisesRegex(RuntimeError, 'success receipt missing'):
                ci.main()

    def test_missing_named_secrets_never_generate_key_or_create_directory(self):
        with self.assertRaisesRegex(RuntimeError, 'missing named secrets'):
            signing.materialize(self.root, {})
        self.assertFalse((self.root/'.signing').exists())

    def test_temporary_material_is_owned_and_cleanup_preserves_foreign_directory(self):
        # Inert bytes are NOT a usable keystore and are never passed to a signing tool.
        env = dict(zip(signing.NAMES, [base64.b64encode(b'inert fixture').decode(), 'fixture password', 'alias', 'key password']))
        signing.materialize(self.root, env)
        self.assertEqual((self.root/'.signing/release.keystore').read_bytes(), b'inert fixture')
        signing.cleanup(self.root)
        self.assertFalse((self.root/'.signing').exists())
        (self.root/'.signing').mkdir()
        (self.root/'.signing/owner-file').write_bytes(b'preserve')
        with self.assertRaisesRegex(RuntimeError, 'non-owned'):
            signing.cleanup(self.root)
        with self.assertRaisesRegex(RuntimeError, 'existing signing directory'):
            signing.materialize(self.root, env)
        self.assertEqual((self.root/'.signing/owner-file').read_bytes(), b'preserve')


if __name__ == '__main__':
    unittest.main()
