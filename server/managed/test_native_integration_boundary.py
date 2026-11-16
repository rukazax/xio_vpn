"""Combined A/RPC/metadata regressions; private files and mocked effects only."""
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import cascade_native_rpc as rpc
import dualstack as net
from test_cascade_native import config, n
from test_cascade_native_rpc import status


PHASES = ('prepared', 'applying', 'guarded', 'applied', 'preparation_failed',
          'apply_failed', 'fail_closed', 'removing', 'removed')


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat().replace('+00:00', 'Z')


def caps(observed=999, expires=1030):
    return dict(schema=1, enabled=True, connectorId='c0a910d7-ff36-4b31-8f5c-839432834328', revision=1,
                observedAt=stamp(observed), expiresAt=stamp(expires),
                awg=dict(ipv4=True, ipv6=True), rivet=dict(ipv4=True, ipv6=True))


class RecoveryProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-boundary-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'owner'

    def observe(self):
        # Inspect must not repair, verify, remove, or launch any process/probe.
        with ExitStack() as stack:
            stack.enter_context(patch.object(n, 'infrastructure', return_value=['uplink_missing']))
            for name in ('command', '_apply', 'remove', 'verify', 'probe'):
                if hasattr(n, name):
                    stack.enter_context(patch.object(n, name, side_effect=AssertionError('passive inspect: ' + name)))
            raw = n.inspect(root=self.root)
            clean = rpc.sanitize(raw)
        return raw, clean

    def test_actual_failed_configure_then_inspect_and_rpc_sanitize(self):
        for stage, phase, guard in [('preparation', 'preparation_failed', 'unknown'),
                                    ('partial', 'apply_failed', 'unknown'),
                                    ('backend', 'fail_closed', 'last_installed')]:
            self.root = Path(self.temp.name) / stage
            life = Mock()
            if stage == 'preparation': life.install.side_effect = RuntimeError('private diagnostic /secret/path')
            with ExitStack() as stack:
                stack.enter_context(patch.object(n, 'lifecycle_for', return_value=life))
                stack.enter_context(patch.object(n, 'owned_preflight'))
                policy = stack.enter_context(patch.object(n, 'policy_sync'))
                firewall = stack.enter_context(patch.object(n, 'firewall_sync'))
                backend = stack.enter_context(patch.object(n, 'start_backend'))
                stack.enter_context(patch.object(n, 'set_peer', side_effect=AssertionError('not reached')))
                stack.enter_context(patch.object(n, 'command', side_effect=AssertionError('no real commands')))
                if stage == 'partial': firewall.side_effect = RuntimeError('partial private effect')
                if stage == 'backend': backend.side_effect = RuntimeError('backend private effect')
                with self.assertRaises(RuntimeError): n.configure(config(), root=self.root)
                self.assertEqual(policy.call_count, 0 if stage == 'preparation' else 1)
                self.assertEqual(backend.call_count, 1 if stage == 'backend' else 0)
            raw, clean = self.observe()
            for result in (raw, clean):
                self.assertEqual((result['phase'], result['guardState']), (phase, guard))
                self.assertFalse(result['infrastructureReady'])
                self.assertTrue(all(not result['capabilities'][p][f] for p in ('awg', 'rivet') for f in ('ipv4', 'ipv6')))
                self.assertNotIn('private diagnostic', json.dumps(result))
                self.assertNotIn('/secret/path', json.dumps(result))
            self.assertEqual(n.load(self.root)['proofs'], {})

    def save_state(self, phase='applied', **fields):
        self.root.mkdir(mode=0o700, exist_ok=True)
        c = n.validate_config(config())
        state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='boundary', revision=1,
                     phase=phase, config=c, configHash=n.digest(c), proofs={}, **fields)
        n.save(self.root, state)

    def test_all_documented_phases_and_guard_provenance_remain_observable(self):
        for phase in PHASES:
            for guard in ('unknown', 'last_installed'):
                self.save_state(phase, guardState=guard)
                raw, clean = self.observe()
                self.assertEqual((clean['phase'], clean['guardState']), (phase, guard))
                self.assertFalse(clean['capabilities']['awg']['ipv4'])

    def test_actual_apply_transients_are_inspectable_without_mutation(self):
        self.save_state('prepared')
        state = n.load(self.root)
        observed = []
        def sample(*args):
            raw, clean = self.observe()
            observed.append((clean['phase'], clean['guardState']))
        # observe() deliberately patches _apply as a no-effect sentinel; invoke
        # the saved real function, with each external effect replaced separately.
        apply = n._apply
        with patch.object(n, 'policy_sync', side_effect=sample), patch.object(n, 'firewall_sync'), \
                patch.object(n, 'start_backend', side_effect=sample), patch.object(n, 'set_peer', return_value=False):
            apply(self.root, state)
        self.assertEqual(observed, [('applying', 'unknown'), ('guarded', 'last_installed')])
        self.assertEqual(n.load(self.root)['phase'], 'applied')

    def test_legacy_absence_never_infers_guard_from_phase(self):
        self.save_state('applied')
        raw, clean = self.observe()
        self.assertEqual(raw['guardState'], 'unknown')
        legacy = dict(raw); legacy.pop('guardState')
        self.assertNotIn('guardState', rpc.sanitize(legacy))

    def test_unknown_receipt_guard_projects_unknown_without_echo(self):
        for value in ('/secret/path private diagnostic', None, [], True):
            self.save_state(guardState=value)
            raw, clean = self.observe()
            self.assertEqual(raw['guardState'], 'unknown')
            self.assertEqual(clean['guardState'], 'unknown')

    def test_invalid_phase_or_rpc_guard_is_typed_redacted_failure(self):
        for field in ('phase', 'guardState'):
            for invalid in ('/secret/path diagnostic', None, [], True):
                value = dict(status(), **{field: invalid})
                with self.assertRaises(rpc.NativeCascadeRPCError) as caught: rpc.sanitize(value)
                self.assertEqual(caught.exception.errorCode, 'INVALID_RESULT')
                self.assertNotIn('/secret/path', str(caught.exception))
                self.assertNotIn('diagnostic', str(caught.exception))

    def test_historical_guard_cannot_promote_readiness(self):
        for phase in PHASES:
            value = dict(status(), phase=phase, guardState='last_installed')
            if phase == 'applied': value['infrastructureReady'] = False
            clean = rpc.sanitize(value)
            self.assertFalse(clean['capabilities']['awg']['ipv4'])
            self.assertFalse(clean['capabilities']['rivet']['ipv6'])


class FreshnessBoundaryTests(unittest.TestCase):
    def parse(self, value, now=1000):
        module = SimpleNamespace(native_capabilities=Mock(return_value=value))
        with patch.object(net, '_native_module', return_value=module), patch.object(net.time, 'time', return_value=now) as clock:
            result = net.native_capabilities()
            clock.assert_called_once_with()
        with patch.object(rpc.time, 'time', return_value=now) as clock:
            sanitized = rpc._capabilities(value)
            clock.assert_called_once_with()
        return result, sanitized

    def test_old_far_future_long_ttl_age_and_expiry_boundaries(self):
        for observed, expires, ready in [
                (1000 - 86400, 1000 + 31536000, False), (999, 1060, False),
                (999, 1059, True), (940, 1000, False), (939.999, 1000.001, False),
                (940.001, 1000.001, True), (1000, 1060, True), (1000, 1060.001, False),
                (1005, 1065, True), (1005.001, 1065.001, False),
                (999, 1000, False), (1000, 1000, False), (1001, 1000, False)]:
            with self.subTest(observed=observed, expires=expires):
                original = caps(observed, expires)
                for result in self.parse(original):
                    for protocol in ('awg', 'rivet'):
                        for family in ('ipv4', 'ipv6'): self.assertEqual(result[protocol][family], ready)
                self.assertTrue(original['awg']['ipv4'])

    def test_strict_utc_wrong_types_and_invalid_calendar_never_positive(self):
        for invalid in (True, 1000, None, '1970-01-01T00:16:39', '1970-01-01T01:16:39+01:00',
                        '1970-02-31T00:16:39Z', '1970-01-01T24:16:39Z'):
            value = caps(); value['observedAt'] = invalid
            module = SimpleNamespace(native_capabilities=lambda **kw: value)
            with patch.object(net, '_native_module', return_value=module), patch.object(net.time, 'time', return_value=1000):
                self.assertFalse(net.native_capabilities()['awg']['ipv4'])
            with self.assertRaises(rpc.NativeCascadeRPCError): rpc._capabilities(value)

    def test_utc_suffix_and_existing_revision_compatibility_unchanged(self):
        for revision in (0, 1, 'opaque-revision'):
            value = caps(); value['revision'] = revision
            value['observedAt'] = value['observedAt'].replace('Z', '+00:00')
            for result in self.parse(value): self.assertTrue(result['awg']['ipv4'])

    def test_actual_producer_positive_and_no_proof_contracts(self):
        with tempfile.TemporaryDirectory(prefix='native-producer-') as directory:
            root = Path(directory); c = n.validate_config(config())
            state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='c0a910d7-ff36-4b31-8f5c-839432834328',
                         revision=1, phase='applied', config=c, configHash=n.digest(c), proofs={})
            for success in (False, True):
                if success:
                    state['proofs'] = {p + '.' + f: dict(success=True, observedAt=997, configHash=state['configHash'])
                                       for p in ('awg', 'rivet') for f in ('ipv4', 'ipv6')}
                n.save(root, state)
                with patch.object(n.time, 'time', return_value=1000), patch.object(n, 'infrastructure', return_value=[]):
                    actual = n.native_capabilities(root=root)
                if not success: self.assertEqual(actual['observedAt'], actual['expiresAt'])
                for result in self.parse(actual): self.assertEqual(result['awg']['ipv4'], success)


if __name__ == '__main__': unittest.main()
