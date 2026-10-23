import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import update


def archive(extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name in ['admin.py', 'stack.py', 'network_stack.py', 'mesh_stack.py',
                     'mesh-pins.json', 'rivet-setup.py', 'dualstack.py', 'client_api.py', *update.RUNTIMES]:
            content = b'# new runtime\n' if name.endswith('.py') else b'new-runtime'
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        if extra:
            tar.addfile(extra)
    raw = stream.getvalue()
    return raw, hashlib.sha256(raw).hexdigest()


class UpdateTests(unittest.TestCase):
    def test_archive_rejects_traversal_symlink_duplicates_and_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, kind in [('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE), ('admin.py', tarfile.REGTYPE)]:
                member = tarfile.TarInfo(name)
                member.type = kind
                raw, digest = archive(member)
                with self.assertRaises(RuntimeError):
                    update.unpack(raw, Path(directory), digest)
            raw, digest = archive()
            with self.assertRaises(RuntimeError):
                update.unpack(raw, Path(directory), '0' * 64)

    def exercise(self, failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lib = root / 'lib'
            lib.mkdir()
            (lib / '.owner').write_text(update.OWNER)
            (lib / 'admin.py').write_bytes(b'# old runtime\n')
            state = root / 'deployment.json'
            initial = {'owner': update.OWNER, 'id': 'server', 'phase': 'ready', 'recipeVersion': 16,
                       'users': {'alice': {'secret': 'test-only-fixture', 'monthBytes': 123}}, 'publicKeys': {'wg': 'fixture'}}
            state.write_text(json.dumps(initial))
            runtime = root / 'rivet'
            runtime.write_bytes(b'old-binary')
            events = []
            failed = False
            def command(*args, check=True):
                nonlocal failed
                events.append(args)
                if failure and args[:2] == ('systemctl', 'start') and not failed:
                    failed = True
                    raise RuntimeError('simulated start failure')
                return type('Result', (), {'returncode': 0})()
            raw, digest = archive()
            with patch.object(update, 'NETWORK_CONFIGS', ()), patch.object(update, 'DUAL_RECEIPT', root/'dual-receipt.json'), patch.object(update, 'WG_CONFIG', root/'wg.conf'), patch.object(update, 'STACK_CONFIG', root/'xray.json'), patch.object(update, 'LEGACY_UNITS', ()), patch.object(update, 'LIB', lib), patch.object(update, 'STATE', state), patch.object(update, 'RUNTIMES', {'rivet': str(runtime)}), patch.object(update, 'command', command), patch.object(update.os, 'geteuid', return_value=0):
                if failure:
                    with self.assertRaises(RuntimeError):
                        update.update(raw, digest, 'server')
                    self.assertEqual(state.read_text(), json.dumps(initial))
                    self.assertEqual(runtime.read_bytes(), b'old-binary')
                    self.assertEqual((lib / 'admin.py').read_bytes(), b'# old runtime\n')
                    self.assertFalse((lib / 'stack.py').exists())
                else:
                    self.assertTrue(update.update(raw, digest, 'server')['updated'])
                    installed = json.loads(state.read_text())
                    self.assertEqual(installed['users'], initial['users'])
                    self.assertEqual(installed['publicKeys'], initial['publicKeys'])
                    self.assertEqual(runtime.read_bytes(), b'new-runtime')
                    before = len(events)
                    self.assertFalse(update.update(raw, digest, 'server')['updated'])
                    self.assertEqual(len(events), before)
                    with self.assertRaises(RuntimeError):
                        update.update(raw, digest, 'another-server')
                    installed['recipeVersion'] = 99
                    state.write_text(json.dumps(installed))
                    with self.assertRaises(RuntimeError):
                        update.update(raw, digest, 'server')
    def test_update_preserves_users_keys_and_is_idempotent(self):
        self.exercise()
    def test_service_failure_restores_previous_runtime_and_receipt(self):
        self.exercise(failure=True)

if __name__ == '__main__':
    unittest.main()
