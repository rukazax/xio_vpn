"""Independent desired-invariant regressions, all actual production functions."""
import hashlib
import os
from pathlib import Path
import sys
import types
import unittest

BASE = Path(__file__).resolve().parent
TEST = BASE / 'test_ownership.py'
raw = TEST.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'eeb44ebb4b1ea22815b790bc4426fc44d33cee6f5c7049d5b0f17f742bb5674b'
assert hashlib.sha256((BASE/'xio-mtproto-setup.sh').read_bytes()).hexdigest() == 'fda86965e827652e0df86e76a4f1562f4a602a578c598c0c3b6443e1d1836ff3'
old = '/srv/archives/agent-mtproto-ownership-fix-20261106'
new = '/srv/archives/agent-mtproto-ownership-review-20261106'
os.environ['XIO_TEST_ROOT'] = new
text = raw.decode()
assert text.count(old) == 2
t = types.ModuleType('review_fixture')
t.__file__ = str(TEST)
sys.modules[t.__name__] = t
exec(compile(text.replace(old,new), str(TEST), 'exec'), t.__dict__)

class IndependentRegressions(unittest.TestCase):
    def fixture(self):
        fx = t.Fixture()
        self.addCleanup(fx.cleanup)
        return fx

    def installed(self):
        fx = self.fixture()
        result = fx.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        fx.clear()
        return fx

    def removed_unit(self):
        fx = self.installed()
        fx.flag('userdel')
        result = fx.run('main --uninstall')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fx.unit.exists())
        self.assertIn('xio-mtproto:', fx.passwd.read_text())
        fx.unflag('userdel')
        fx.clear()
        return fx

    def test_original_counterexample_now_requires_live_stop_before_removal(self):
        fx = self.fixture()
        # Same independent runtime-marker boundary as the original RED proof.
        fx.header = fx.header.replace('systemctl() {', 'systemctl_base() {')
        fx.header += r'''
systemctl() {
  if [ "$1" = show ] && [ "${3:-}" = --property=ActiveState ]; then
    if [ -f "$FX/active-now" ]; then printf 'active\n'; else printf 'inactive\n'; fi
    return 0
  fi
  if [ "$1" = stop ]; then
    systemctl_base "$@" || return $?
    /bin/rm -f -- "$FX/active-now"
    return 0
  fi
  systemctl_base "$@"
}
'''
        result = fx.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        count = int((fx.root/'journal-count').read_text())
        (fx.root/'journal-stop-at').write_text(str(count+3)+'\n')
        fx.flag('after-journal')
        result = fx.run('main --uninstall')
        self.assertEqual(result.returncode, 88, result.stderr)
        self.assertEqual(fx.receipt.read_text().splitlines()[4], 'done')
        self.assertTrue(fx.link.is_symlink())
        self.assertTrue(fx.unit.exists())
        fx.unflag('after-journal')
        fx.clear()
        active = fx.root/'active-now'
        active.touch()
        result = fx.run('main --uninstall')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(active.exists(), 'runtime must be stopped, not merely historically stopped')
        self.assertEqual(fx.phase(), 'uninstalled')
        trace = fx.trace()
        self.assertLess(trace.index('systemctl stop'), trace.index('rm fixture'))
        print('original-counterexample DESIRED invariant: PASS (re-stop before removal)', flush=True)

    def test_vendor_alias_before_effects_absolute_and_relative(self):
        for relative in (False, True):
            with self.subTest(relative=relative):
                fx = self.fixture()
                vendor = fx.root/'usr/lib/systemd/system'
                vendor.mkdir(parents=True)
                alias = vendor/'unrequested-foreign.service'
                target = os.path.relpath(fx.unit, vendor) if relative else str(fx.unit)
                alias.symlink_to(target)
                result = fx.run()
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(fx.trace(),'')
                self.assertEqual(os.readlink(alias),target)
                self.assertFalse(fx.receipt.exists())

    def test_absent_unit_foreign_loaded_inactive_or_unknown_refuses_without_effects(self):
        fx = self.removed_unit()
        receipt = fx.receipt.read_bytes()
        passwd = fx.passwd.read_bytes()
        for state in ('inactive','unknown','active'):
            with self.subTest(state=state):
                (fx.root/'active-state').write_text(state+'\n')
                (fx.root/'unit-overrides').write_text('load=loaded\nfragment=/synthetic/foreign.service\nstate=disabled\n')
                fx.clear()
                result=fx.run('main --uninstall')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(fx.trace(),'')
                self.assertEqual(fx.receipt.read_bytes(),receipt)
                self.assertEqual(fx.passwd.read_bytes(),passwd)

    def test_absent_unit_unknown_runtime_state_never_authorizes_cleanup(self):
        fx = self.removed_unit()
        for state in ('active','activating','deactivating','failed','unknown',''):
            with self.subTest(state=state):
                (fx.root/'active-state').write_text(state+'\n')
                fx.clear()
                result=fx.run('main --uninstall')
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(fx.trace(),'')
                self.assertIn('xio-mtproto:',fx.passwd.read_text())

    def test_stale_inactive_loaded_former_fragment_must_disappear_after_reload(self):
        fx = self.removed_unit()
        (fx.root/'unit-overrides').write_text(f'load=loaded\nfragment={fx.unit}\nstate=disabled\n')
        (fx.root/'active-state').write_text('inactive\n')
        fx.clear()
        result=fx.run('main --uninstall')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(fx.trace(),'systemctl daemon-reload\n')
        self.assertIn('xio-mtproto:',fx.passwd.read_text())

    def test_tombstone_active_runtime_does_not_report_already_uninstalled(self):
        fx = self.installed()
        result=fx.run('main --uninstall')
        self.assertEqual(result.returncode,0,result.stderr)
        (fx.root/'active-state').write_text('active\n')
        fx.clear()
        result=fx.run('main --uninstall')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(fx.trace(),'')
        self.assertNotIn('already uninstalled',result.stdout)

if __name__ == '__main__':
    print('commit=5801b32da95a8e86b9949dec03dca430374b92e4',flush=True)
    print('source_sha256='+hashlib.sha256((BASE/'xio-mtproto-setup.sh').read_bytes()).hexdigest(),flush=True)
    unittest.main(verbosity=2)
