#!/usr/bin/env python3
"""Private file + mocked-systemd tests. NEVER contacts a live systemd manager."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from test_cascade_native import config, n, KEY

spec = importlib.util.spec_from_file_location('life', Path(__file__).with_name('cascade_native_lifecycle.py'))
l = importlib.util.module_from_spec(spec); spec.loader.exec_module(l)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-life-')
        self.base = Path(self.temp.name)
        self.root = self.base / 'receipt'; self.root.mkdir(mode=0o700)
        self.units = self.base / 'units'; self.units.mkdir()
        c = n.validate_config(config())
        self.state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='lifecycle-test', revision=1,
                          config=c, configHash=n.digest(c), phase='applied', proofs={})
        n.save(self.root, self.state)
        self.calls = []
        self.ctl = lambda *args: self.calls.append(args)

    def tearDown(self): self.temp.cleanup()
    def install(self): return l.install(self.state, root=self.root, unit_dir=self.units, ctl=self.ctl)

    def test_all_three_native_listeners_require_after_guard(self):
        plan = l.templates(self.state)
        self.assertEqual(l.NATIVE_UNITS, ('xio-managed-awg.service', 'xio-rivet-gateway.service', 'xio-rivet-entry.service'))
        for unit in l.NATIVE_UNITS:
            text = plan['files'][unit + '.d/' + l.DROPIN].decode()
            self.assertIn('Requires=' + l.GUARD, text)
            self.assertIn('After=' + l.GUARD, text)
            self.assertNotIn('Condition', text)
        text = plan['files'][l.GUARD].decode()
        self.assertIn('Before=' + ' '.join(l.NATIVE_UNITS), text)
        self.assertIn('guard-auto', text)
        self.assertNotIn('Condition', text)
        self.assertNotIn('ExecCondition', text)
        self.assertNotIn('cloak', str(plan))
        self.assertNotIn('openvpn', str(plan))

    def test_exit_has_boot_peer_service_not_native_bridge_dependencies(self):
        self.state['config']['role'] = 'exit'
        plan = l.templates(self.state)
        self.assertEqual(set(plan['files']), {l.GUARD})
        self.assertNotIn(l.TIMER, str(plan))
        self.assertNotIn('Before=', plan['files'][l.GUARD].decode())

    def test_periodic_unit_uses_safe_auto_stdin_and_sub_ttl_interval(self):
        plan = l.templates(self.state)
        verify, timer = plan['files'][l.VERIFY].decode(), plan['files'][l.TIMER].decode()
        self.assertIn('StandardInput=null', verify)
        self.assertIn(' verify-auto\n', verify)
        self.assertNotIn(' verify\n', verify)
        self.assertIn('Requires=' + l.GUARD, verify)
        self.assertIn('OnUnitActiveSec=30s', timer)
        self.assertIn('OnActiveSec=15s', timer)
        self.assertLess(30 + 25, n.PROOF_TTL)

    def test_install_idempotent_only_owned_symlinks_and_timer_activation(self):
        self.install(); before = {p: p.read_bytes() for p in self.units.rglob('*') if p.is_file() and not p.is_symlink()}
        self.install()
        self.assertEqual(before, {p: p.read_bytes() for p in self.units.rglob('*') if p.is_file() and not p.is_symlink()})
        self.assertEqual(self.calls, [('daemon-reload',), ('daemon-reload',)])
        l.activate(self.state, root=self.root, unit_dir=self.units, ctl=self.ctl)
        self.assertEqual(self.calls[-1], ('start', l.TIMER))
        self.assertTrue((self.units / 'multi-user.target.wants' / l.GUARD).is_symlink())
        self.assertTrue((self.units / 'timers.target.wants' / l.TIMER).is_symlink())
        self.assertNotIn(('start', l.GUARD), self.calls)  # no owner-lock deadlock

    def test_foreign_reserved_file_or_enable_link_refused_before_effects(self):
        path = self.units / l.GUARD; path.write_text('foreign')
        with self.assertRaises(RuntimeError): self.install()
        self.assertEqual(path.read_text(), 'foreign'); self.assertEqual(self.calls, [])
        path.unlink(); target = self.units / 'multi-user.target.wants' / l.GUARD
        target.parent.mkdir(); target.symlink_to('/foreign/guard.service')
        with self.assertRaises(RuntimeError): self.install()
        self.assertEqual(os.readlink(target), '/foreign/guard.service')
        self.assertFalse((self.units / l.GUARD).exists())

    def test_foreign_other_dropins_preserved_on_install_remove(self):
        foreign = self.units / (l.NATIVE_UNITS[0] + '.d') / '90-foreign.conf'
        foreign.parent.mkdir(); foreign.write_text('[Service]\nNice=1\n')
        self.install()
        l.remove(self.state, root=self.root, unit_dir=self.units, ctl=self.ctl)
        self.assertEqual(foreign.read_text(), '[Service]\nNice=1\n')
        self.assertEqual(l.read_receipt(self.root)['phase'], 'removed')
        self.assertFalse((self.units / l.GUARD).exists())
        self.assertFalse(os.path.lexists(self.units / 'multi-user.target.wants' / l.GUARD))
        self.assertLess(self.calls.index(('stop', l.TIMER)), self.calls.index(('stop', l.GUARD)))
        self.assertIn(('daemon-reload',), self.calls[:self.calls.index(('stop', l.GUARD))])

    def test_modified_owned_file_refuses_remove_and_boot_guard(self):
        self.install()
        path = self.units / (l.NATIVE_UNITS[1] + '.d') / l.DROPIN
        path.write_text('foreign edited this reserved file')
        calls = list(self.calls)
        with self.assertRaises(RuntimeError): l.remove(self.state, root=self.root, unit_dir=self.units, ctl=self.ctl)
        with self.assertRaises(RuntimeError): l.assert_installed(self.state, root=self.root, unit_dir=self.units)
        self.assertEqual(path.read_text(), 'foreign edited this reserved file')
        self.assertEqual(calls, self.calls)
        self.assertTrue((self.units / l.GUARD).exists())

    def test_failed_reload_rolls_back_only_new_unchanged_artifacts(self):
        def fail(*args): raise RuntimeError('mock reload failure')
        with self.assertRaises(RuntimeError): l.install(self.state, root=self.root, unit_dir=self.units, ctl=fail)
        self.assertFalse((self.units / l.GUARD).exists())
        self.assertFalse(os.path.lexists(self.units / 'multi-user.target.wants' / l.GUARD))
        self.assertEqual(l.read_receipt(self.root)['phase'], 'install_failed')
        self.install(); l.assert_installed(self.state, root=self.root, unit_dir=self.units)

    def test_foreign_concurrent_edit_preserved_during_install_rollback(self):
        path = self.units / l.GUARD
        def change_then_fail(*args):
            path.write_text('concurrent foreign edit'); raise RuntimeError('mock reload failure')
        with self.assertRaises(RuntimeError): l.install(self.state, root=self.root, unit_dir=self.units, ctl=change_then_fail)
        self.assertEqual(path.read_text(), 'concurrent foreign edit')
        with self.assertRaises(RuntimeError): self.install()

    def test_symlinked_dropin_parent_rejected(self):
        foreign = self.base / 'foreign'; foreign.mkdir()
        (self.units / (l.NATIVE_UNITS[0] + '.d')).symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(RuntimeError): self.install()
        self.assertEqual(list(foreign.iterdir()), [])

    def test_active_receipt_needs_all_boot_files_links_even_after_reboot(self):
        self.install(); l.assert_installed(self.state, root=self.root, unit_dir=self.units)
        (self.units / 'multi-user.target.wants' / l.GUARD).unlink()
        with self.assertRaises(RuntimeError): l.assert_installed(self.state, root=self.root, unit_dir=self.units)
        self.install(); l.assert_installed(self.state, root=self.root, unit_dir=self.units)

    def test_no_opt_in_legacy_does_not_create_lifecycle_or_probe(self):
        empty = self.base / 'missing'
        with patch.object(n, 'lifecycle_for', side_effect=AssertionError('legacy must not install')), patch.object(n, 'command', side_effect=AssertionError('no probe')):
            self.assertIsNone(n.reconcile_native(root=empty))
            self.assertIsNone(n.native_capabilities(root=empty))
            self.assertFalse(n.verify_auto(root=empty)['verified'])
        self.assertFalse(empty.exists())

    def test_guard_missing_or_disabled_receipt_is_failure_not_successful_skip(self):
        with self.assertRaises(RuntimeError): n.guard_auto(root=self.base / 'missing')
        self.state['enabled'] = False; n.save(self.root, self.state)
        with self.assertRaises(RuntimeError): n.guard_auto(root=self.root)

    def test_mock_boot_timeline_no_listener_before_successful_guard(self):
        self.install(); events = []
        life = Mock(spec=l)
        life.assert_installed.side_effect = lambda state, **kw: l.assert_installed(state, root=self.root, unit_dir=self.units)
        def apply(root, state): events.append('fences-installed-before-native-devices')
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, '_apply', side_effect=apply):
            # Model systemd Requires+After graph using the actual generated drop-ins.
            guard_active = False
            for unit in l.NATIVE_UNITS:
                dropin = (self.units / (unit + '.d') / l.DROPIN).read_text()
                self.assertIn('Requires=' + l.GUARD, dropin); self.assertIn('After=' + l.GUARD, dropin)
                if not guard_active: n.guard_auto(root=self.root); guard_active = True
                events.append('listen:' + unit)
        self.assertEqual(events[0], 'fences-installed-before-native-devices')
        self.assertEqual(len(events), 4)

    def test_mock_boot_guard_error_or_missing_helper_blocks_all_listeners(self):
        self.install()
        for failure in (RuntimeError('mock fence failure'), ImportError('missing signed lifecycle helper'), FileNotFoundError('missing connector program')):
            listeners = []
            with patch.object(n, 'lifecycle_for', side_effect=failure):
                try:
                    n.guard_auto(root=self.root)
                    listeners.extend(l.NATIVE_UNITS)
                except (RuntimeError, ImportError, FileNotFoundError): pass
            self.assertEqual(listeners, [])

    def test_guard_apply_failure_retains_opt_in_and_prevents_start(self):
        self.install()
        life = Mock(spec=l)
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, '_apply', side_effect=RuntimeError('mock kernel failure')):
            with self.assertRaises(RuntimeError): n.guard_auto(root=self.root)
        self.assertTrue(n.load(self.root)['enabled'])
        self.assertEqual(n.load(self.root)['phase'], 'apply_failed')
        self.assertEqual(n.load(self.root)['guardState'], 'unknown')

    def test_timer_cli_no_stdin_eof_or_unowned_probe(self):
        program = Path(n.__file__)
        p = subprocess.run([sys.executable, str(program), 'verify-auto', '--root', str(self.base / 'missing')], input='', text=True, capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertFalse(json.loads(p.stdout)['verified'])
        p = subprocess.run([sys.executable, str(program), 'guard-auto', '--root', str(self.base / 'missing')], input='', text=True, capture_output=True, timeout=5)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('JSONDecodeError', p.stdout)

    def test_production_configure_orders_lifecycle_before_apply_activation(self):
        events = []
        state_root = self.base / 'configure'
        life = Mock(spec=l)
        life.install.side_effect = lambda *a, **kw: events.append('install-boot-dependencies')
        life.activate.side_effect = lambda *a, **kw: events.append('activate-verifier')
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, 'owned_preflight'), patch.object(n, '_apply', side_effect=lambda *a: events.append('apply-fences-uplink')), patch.object(n, 'inspect', return_value={}):
            n.configure(config(), root=state_root)
        self.assertEqual(events, ['install-boot-dependencies', 'apply-fences-uplink', 'activate-verifier'])

    def test_lifecycle_install_failure_never_calls_apply(self):
        life = Mock(spec=l); life.install.side_effect = RuntimeError('foreign guard unit')
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, 'owned_preflight'), patch.object(n, '_apply') as apply:
            with self.assertRaises(RuntimeError): n.configure(config(), root=self.base / 'failed-configure')
        apply.assert_not_called()
        state = n.load(self.base / 'failed-configure')
        self.assertEqual(state['phase'], 'preparation_failed')
        self.assertEqual(state['guardState'], 'unknown')
        self.assertNotIn('fences retained', state['error'])

    def test_foreign_lifecycle_edit_blocks_core_remove_before_network_effects(self):
        life = Mock(spec=l); life.remove.side_effect = RuntimeError('foreign reserved drop-in')
        with patch.object(n, 'lifecycle_for', return_value=life), patch.object(n, 'assert_owned_chains'), patch.object(n, 'policy_snapshot', return_value={}), patch.object(n, 'command', side_effect=AssertionError('must retain live fences')):
            with self.assertRaises(RuntimeError): n.remove(root=self.root, confirm_direct=True)
        self.assertTrue(n.load(self.root)['enabled'])
        self.assertEqual(n.load(self.root)['phase'], 'applied')

    def test_systemd_analyze_verifies_generated_units_offline_without_manager(self):
        import shutil
        if not shutil.which('systemd-analyze'): self.skipTest('offline analyzer unavailable; no install attempted')
        self.install()
        for unit in l.NATIVE_UNITS:
            (self.units / unit).write_text('[Unit]\nDescription=Private native boot fixture\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/true\n')
        paths = [str(self.units / u) for u in (*l.NATIVE_UNITS, l.GUARD, l.VERIFY, l.TIMER)]
        env = dict(os.environ, SYSTEMD_UNIT_PATH=str(self.units) + ':/usr/lib/systemd/system:/lib/systemd/system')
        p = subprocess.run(['systemd-analyze', 'verify', '--man=no', '--generators=no', *paths], capture_output=True, text=True, env=env, timeout=15)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_custom_roots_cannot_bypass_production_lifecycle_in_host_namespace(self):
        with patch.object(n.os, 'readlink', return_value='same-host-namespace'):
            with self.assertRaises(RuntimeError): n.lifecycle_for(self.root)
        with patch.object(n.os, 'readlink', side_effect=lambda p: 'private' if '/self/' in p else 'host'):
            self.assertIsNone(n.lifecycle_for(self.root))
        with patch.object(n.os, 'readlink', return_value='same-host-namespace'):
            self.assertIsNotNone(n.lifecycle_for(n.DEFAULT_ROOT))

    def test_periodic_action_reconciles_then_only_explicit_source_bound_probe(self):
        events = []
        with patch.object(n, 'reconcile_native', side_effect=lambda **kw: events.append('reconcile')), patch.object(n, 'verify', side_effect=lambda **kw: events.append('verify-source-mark')):
            n.verify_auto(root=self.root)
        self.assertEqual(events, ['reconcile', 'verify-source-mark'])


if __name__ == '__main__': unittest.main(verbosity=2)
