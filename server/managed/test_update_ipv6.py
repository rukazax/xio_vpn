"""Owned recipe-24 -> 25 fixtures; no Linux commands are executed."""
from contextlib import contextmanager, ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import update
from test_update import archive, NO_NETWORK


@contextmanager
def deployment(host='2001:db8::42'):
    with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
        root = Path(directory)
        lib = root / 'managed'; lib.mkdir()
        (lib / '.owner').write_text(update.OWNER)
        (lib / 'admin.py').write_bytes(b'# old admin\n')
        rivet = root / 'rivet-root'; rivet.mkdir()
        runtime = root / 'rivet-lib'; runtime.mkdir()
        setup = runtime / 'setup.py'; setup.write_bytes(b'# old setup\n')
        (runtime / 'rivet').write_bytes(b'old-rivet')
        public = {'endpoint': host + ':8443', 'serverName': host,
                  'outerCA': 'public-ca-fixture', 'innerCA': 'inner-ca-fixture',
                  'extraPublicField': {'keep': True}}
        (rivet / 'public.json').write_text(json.dumps(public, indent=2))
        (rivet / 'install-receipt.json').write_text(json.dumps(
            {'owner': 'xio-rivet-v1', 'phase': 'ready', 'serverName': host, 'binaryOwned': True}))
        for name in update.RIVET_PRIVATE_FILES:
            (rivet / name).write_bytes(('private-test-fixture-' + name).encode())
        state = root / 'deployment.json'
        data = {'owner': update.OWNER, 'id': 'server', 'phase': 'ready', 'recipeVersion': 24,
                'bundleSha256': 'a' * 64, 'rivet': public,
                'users': {'alice': {'secret': 'fixture', 'monthBytes': 123}},
                'publicKeys': {'wg': 'fixture'}, 'restrictedNetwork': True,
                'stack': {'protocols': ['xray', 'cloak']}, 'delegatedSsh': 'fixture'}
        state.write_text(json.dumps(data, indent=2))
        dual = root / 'dualstack-receipt.json'
        dual.write_text(json.dumps({'owner': 'xio-dualstack-v1', 'oldForward': '0', 'rules': [], 'addresses': []}))
        events = []
        def command(*args, **kwargs):
            events.append(args)
            return type('Result', (), {'returncode': 0})()
        for name, value in {'LIB': lib, 'STATE': state, 'RIVET_ROOT': rivet,
                            'RIVET_SETUP': setup, 'RUNTIMES': {'rivet': str(root / 'uninstalled-rivet')}, 'NETWORK_UNITS': (),
                            'NETWORK_CONFIGS': (), 'DUAL_RECEIPT': dual,
                            'WG_CONFIG': root / 'wg.conf', 'STACK_CONFIG': root / 'xray.json',
                            'LEGACY_UNITS': ()}.items():
            patches.enter_context(patch.object(update, name, value))
        patches.enter_context(patch.object(update.os, 'geteuid', return_value=0, create=True))
        patches.enter_context(patch.object(update, 'command', side_effect=command))
        patches.enter_context(patch.object(update, 'ipv6_transaction_module', return_value=NO_NETWORK))
        yield root, data, events


def files(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob('*') if p.is_file()}


class OwnedMetadataMigrationTests(unittest.TestCase):
    def test_recipe24_ipv6_migration_preserves_keys_receipts_and_users(self):
        for host in ['2001:db8::42', '::1', '::ffff:192.0.2.1', '2001:0db8:0000:0000:0000:0000:0000:0042']:
            with self.subTest(host=host), deployment(host) as (root, data, events):
                before = files(root)
                raw, digest = archive()
                self.assertEqual(update.update(raw, digest, 'server'), {'updated': True, 'recipeVersion': 25})
                installed = json.loads(update.STATE.read_bytes())
                public = json.loads((update.RIVET_ROOT / 'public.json').read_bytes())
                self.assertEqual(public, dict(data['rivet'], endpoint='[' + host + ']:8443'))
                self.assertEqual(installed['rivet'], public)
                self.assertEqual(installed['rivetPublicSha256'], hashlib.sha256((update.RIVET_ROOT / 'public.json').read_bytes()).hexdigest())
                for field in ('users', 'publicKeys', 'delegatedSsh', 'restrictedNetwork', 'stack'):
                    self.assertEqual(installed[field], data[field])
                for name in update.RIVET_PRIVATE_FILES + ('install-receipt.json',):
                    self.assertEqual((update.RIVET_ROOT / name).read_bytes(), before['rivet-root/' + name])
                self.assertEqual(update.DUAL_RECEIPT.read_bytes(), before['dualstack-receipt.json'])
                self.assertEqual(update.RIVET_SETUP.read_bytes(), b'# new runtime\n')
                self.assertFalse(any(e[0] == 'python3' for e in events))  # Do not replay recipe-24 network migration.
                self.assertFalse(any(e[:2] == ('systemctl', 'disable') for e in events))
                events.clear()
                self.assertFalse(update.update(raw, digest, 'server')['updated'])
                self.assertEqual(events, [])

    def test_ipv4_and_dns_keep_public_file_bytes_unchanged(self):
        for host in ['192.0.2.8', 'vpn.example.com', 'fr-host.fr', 'fr-host.fr.', 'xn--bcher-kva.example']:
            with self.subTest(host=host), deployment(host) as (root, data, events):
                before = (update.RIVET_ROOT / 'public.json').read_bytes()
                raw, digest = archive()
                update.update(raw, digest, 'server')
                self.assertEqual((update.RIVET_ROOT / 'public.json').read_bytes(), before)
                self.assertEqual(json.loads(update.STATE.read_bytes())['rivet'], data['rivet'])

    def test_failure_after_public_replace_or_commit_restores_both_and_all_runtimes(self):
        for point in ['public.json', 'deployment.json', 'service-start']:
            with self.subTest(point=point), deployment() as (root, data, events):
                before = files(root)
                raw, digest = archive()
                original_atomic = update.atomic
                failed = False
                def atomic(source, target, mode):
                    nonlocal failed
                    original_atomic(source, target, mode)
                    if Path(target).name == point and not failed:
                        failed = True
                        raise RuntimeError('simulated interruption after replace')
                def command(*args, **kwargs):
                    nonlocal failed
                    events.append(args)
                    if point == 'service-start' and args[:2] == ('systemctl', 'start') and not failed:
                        failed = True
                        raise RuntimeError('simulated start failure')
                    return type('Result', (), {'returncode': 0})()
                with patch.object(update, 'atomic', side_effect=atomic), patch.object(update, 'command', side_effect=command):
                    with self.assertRaises(RuntimeError):
                        update.update(raw, digest, 'server')
                self.assertTrue(failed)
                self.assertEqual(files(root), before)

    def test_same_recipe_conflicting_hash_is_still_rejected_before_effects(self):
        with deployment() as (root, data, events):
            raw, digest = archive()
            update.update(raw, digest, 'server')
            before = files(root); events.clear()
            with self.assertRaisesRegex(RuntimeError, 'Conflicting bundle at the same recipe'):
                update.update(raw, '0' * 64, 'server')
            self.assertEqual(files(root), before)
            self.assertEqual(events, [])

    def test_foreign_or_divergent_ownership_is_rejected_before_effects(self):
        cases = ['receipt-owner', 'receipt-phase', 'receipt-name', 'public-copy', 'endpoint',
                 'missing-key', 'public-hash', 'deployment-owner', 'lib-owner', 'dual-owner']
        for case in cases:
            with self.subTest(case=case), deployment() as (root, data, events):
                receipt_path = update.RIVET_ROOT / 'install-receipt.json'
                receipt = json.loads(receipt_path.read_bytes())
                if case.startswith('receipt-'):
                    receipt[{'receipt-owner':'owner','receipt-phase':'phase','receipt-name':'serverName'}[case]] = 'foreign'
                    receipt_path.write_text(json.dumps(receipt))
                elif case == 'public-copy':
                    (update.RIVET_ROOT / 'public.json').write_text('{}')
                elif case == 'endpoint':
                    data['rivet']['endpoint'] = 'foreign.example:9443'
                    (update.RIVET_ROOT / 'public.json').write_text(json.dumps(data['rivet']))
                    update.STATE.write_text(json.dumps(data))
                elif case == 'missing-key':
                    (update.RIVET_ROOT / 'seal.key').unlink()
                elif case == 'public-hash':
                    data['rivetPublicSha256'] = '0' * 64
                    update.STATE.write_text(json.dumps(data))
                elif case == 'deployment-owner':
                    data['owner'] = 'foreign'; update.STATE.write_text(json.dumps(data))
                elif case == 'lib-owner':
                    (update.LIB / '.owner').write_text('foreign')
                elif case == 'dual-owner':
                    update.DUAL_RECEIPT.write_text('{"owner":"foreign"}')
                before = files(root)
                raw, digest = archive()
                with self.assertRaises(RuntimeError), patch.object(update, 'atomic') as atomic:
                    update.update(raw, digest, 'server')
                atomic.assert_not_called()
                self.assertEqual(files(root), before)
                self.assertEqual(events, [])

    def test_linked_public_or_parent_is_rejected_without_requiring_symlink_privileges(self):
        for which in ['public', 'parent']:
            with self.subTest(which=which), deployment() as (root, data, events):
                original = Path.is_symlink
                bad = update.RIVET_ROOT / 'public.json' if which == 'public' else update.RIVET_ROOT
                with patch.object(Path, 'is_symlink', lambda path: path == bad or original(path)):
                    raw, digest = archive()
                    with self.assertRaisesRegex(RuntimeError, 'Symlink'), patch.object(update, 'atomic') as atomic:
                        update.update(raw, digest, 'server')
                    atomic.assert_not_called()
                self.assertEqual(events, [])

    def test_concurrent_public_change_is_detected_before_stopping_services(self):
        with deployment() as (root, data, events):
            initial_state = update.STATE.read_bytes()
            changed = False
            def command(*args, **kwargs):
                nonlocal changed
                events.append(args)
                if not changed:
                    changed = True
                    (update.RIVET_ROOT / 'public.json').write_text('{"changedByOtherWriter":true}')
                return type('Result', (), {'returncode': 0})()
            raw, digest = archive()
            with patch.object(update, 'command', side_effect=command), patch.object(update, 'atomic') as atomic:
                with self.assertRaisesRegex(RuntimeError, 'Owned file changed'):
                    update.update(raw, digest, 'server')
            atomic.assert_not_called()
            self.assertEqual(update.STATE.read_bytes(), initial_state)
            self.assertFalse(any(e[:2] == ('systemctl', 'stop') for e in events))

    def test_bad_rollback_hash_retains_recovery_backup_and_manifest(self):
        with deployment() as (root, data, events):
            raw, digest = archive()
            failed = False
            def command(*args, **kwargs):
                nonlocal failed
                if args[:2] == ('systemctl', 'start') and not failed:
                    failed = True
                    work = next(root.glob('.update-*'))
                    (work / 'backup-0').write_bytes(b'corrupt-backup')
                    raise RuntimeError('simulated service failure plus disk corruption')
                return type('Result', (), {'returncode': 0})()
            with patch.object(update, 'command', side_effect=command):
                with self.assertRaisesRegex(RuntimeError, 'backup retained'):
                    update.update(raw, digest, 'server')
            recovery = list(root.glob('.update-recovery-*'))
            self.assertEqual(len(recovery), 1)
            self.assertTrue((recovery[0] / 'backup/hashes-before.json').is_file())

    def test_owned_openvpn_hook_is_backed_up_and_foreign_unit_is_rejected_early(self):
        import network_stack
        for foreign in [False, True]:
            with self.subTest(foreign=foreign), deployment() as (root, data, events):
                unit = root / 'xio-openvpn-tcp.service'
                text = '[Unit]\nDescription=XIO managed xio-openvpn-tcp\n[Service]\nExecStart=/usr/sbin/openvpn --config ' + str(root / 'tcp.ovpn') + '\nProtectSystem=strict\n[Install]\nWantedBy=multi-user.target\n'
                if foreign: text = text.replace('Description=XIO managed', 'Description=FOREIGN')
                unit.write_text(text)
                (root / 'receipt.json').write_text('{"owner":"xio-stack-v1"}')
                raw, digest = archive()
                before = files(root)
                def command(*args, **kwargs):
                    events.append(args)
                    if args[-1:] == ('reconcile-ipv6-hooks',):
                        with patch.object(network_stack, 'ROOT', root), patch.object(network_stack, 'SYSTEMD', root):
                            network_stack.reconcile_ipv6_hooks()
                    return type('Result', (), {'returncode': 0})()
                with patch.object(update, 'NETWORK_UNITS', (unit,)), patch.object(update, 'command', side_effect=command):
                    if foreign:
                        with self.assertRaisesRegex(RuntimeError, 'Unowned OpenVPN service'):
                            update.update(raw, digest, 'server')
                        self.assertEqual(files(root), before)
                        self.assertEqual(events, [])
                    else:
                        update.update(raw, digest, 'server')
                        self.assertIn(network_stack.ipv6_hook('tcp'), unit.read_text())
                        self.assertIn('ProtectSystem=strict', unit.read_text())
                        self.assertIn(('systemctl', 'daemon-reload'), events)


if __name__ == '__main__':
    unittest.main()
