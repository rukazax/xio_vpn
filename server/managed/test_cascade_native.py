#!/usr/bin/env python3
"""Pure/mocked native connector tests. No host routes/firewall/services are applied."""
import base64
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('native', Path(__file__).with_name('cascade_native.py'))
n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(n)
KEY = base64.b64encode(bytes(range(32))).decode()


def config(role='bridge', mode='hop-snat', families=None):
    value = dict(enabled=True, ownerOptIn=True, role=role, backend='userspace', interface='xiocascade0',
                 sourceMode=mode, innerFamilies=families or ['ipv4', 'ipv6'], privateKey=KEY,
                 localAddresses={'ipv4': '10.203.0.2', 'ipv6': 'fd42:203::2'},
                 peerAddresses={'ipv4': '10.203.0.1', 'ipv6': 'fd42:203::1'},
                 peer={'host': '203.0.113.7', 'port': 9443, 'publicKey': KEY})
    if role == 'exit': value['exitInterfaces'] = {'ipv4': 'eth0', 'ipv6': 'eth0'}
    return value


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-unit-')
        self.root = Path(self.temp.name) / 'state'

    def tearDown(self): self.temp.cleanup()

    def state(self, request=None):
        self.root.mkdir(mode=0o700, exist_ok=True)
        c = n.validate_config(request or config())
        state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='owned-test', revision=7,
                     config=c, configHash=n.digest(c), phase='applied', proofs={})
        n.save(self.root, state)
        return state

    def test_validation_and_plan_are_pure_and_secret_free(self):
        request = config()
        with patch.object(n, 'command', side_effect=AssertionError('not pure')):
            result = n.plan(request)
        self.assertNotIn('privateKey', json.dumps(result))
        self.assertNotIn(KEY, json.dumps(result).replace(request['peer']['publicKey'], 'public'))
        self.assertEqual(result['config']['peer']['host'], '203.0.113.7')
        self.assertFalse(self.root.exists())

    def test_literal_and_control_rejection_before_effects(self):
        bad = ['1.2.3.999', '010.1.2.3', '2001:::1', '[2001:db8::1]', 'https://example.com',
               'fe80::1%eth0', '2001:db8::1/64', '::', '::1', 'ff02::1',
               '1.2.3.4; touch /tmp/evil', '2001:db8::1\nPostUp=evil']
        with patch.object(n, 'command', side_effect=AssertionError('side effect')):
            for value in bad:
                c = config(); c['peer']['host'] = value
                with self.subTest(value=value), self.assertRaises(ValueError): n.configure(c, self.root)
            for field, value in [('ownerOptIn', False), ('enabled', False), ('interface', 'wg0'),
                                 ('backend', 'download'), ('sourceMode', 'guess'), ('innerFamilies', [])]:
                c = config(); c[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError): n.configure(c, self.root)
        self.assertFalse(self.root.exists())

    def test_non_authoritative_ingress_maps_rejected_before_all_effects(self):
        cases = [None, [], 'root', {}, {'awg': copy.deepcopy(n.NATIVE_MAP['awg'])}]
        extra = copy.deepcopy(n.NATIVE_MAP); extra['root'] = copy.deepcopy(extra['awg']); cases.append(extra)
        for proto, field, value in [
            ('awg', 'interface', 'eth0'), ('rivet', 'interface', 'lo'),
            ('awg', 'ipv4', '0.0.0.0/0'), ('awg', 'ipv4', '172.16.0.0/12'),
            ('rivet', 'ipv4', '192.168.0.0/16'), ('awg', 'ipv6', '::/0'),
            ('awg', 'ipv6', 'fd78:2::/64'), ('rivet', 'ipv6', '2001:db8:79::/64'),
            ('awg', 'ipv4', 'fd78:1::/64'), ('awg', 'ipv6', '10.78.0.0/24'),
            ('awg', 'ipv4', None), ('rivet', 'ipv6', 0),
        ]:
            changed = copy.deepcopy(n.NATIVE_MAP); changed[proto][field] = value; cases.append(changed)
        broad = copy.deepcopy(n.NATIVE_MAP); broad['awg'].update(interface='eth0', ipv4='0.0.0.0/0'); cases.append(broad)
        root_scope = copy.deepcopy(n.NATIVE_MAP); root_scope['awg'].update(interface='eth0', ipv4='192.0.0.0/8'); cases.append(root_scope)
        for value in (None, [], 'root'):
            changed = copy.deepcopy(n.NATIVE_MAP); changed['awg'] = value; cases.append(changed)
        missing = copy.deepcopy(n.NATIVE_MAP); del missing['rivet']['ipv6']; cases.append(missing)
        extra = copy.deepcopy(n.NATIVE_MAP); extra['awg']['uid'] = 0; cases.append(extra)
        roots = [n.DEFAULT_ROOT, self.root, Path(self.temp.name) / 'alternate-private-root']
        effects = ('command', 'atomic', 'save', 'load', 'locked', 'lifecycle_for', 'owned_preflight', '_apply')
        with ExitStack() as stack:
            for name in effects:
                stack.enter_context(patch.object(n, name, side_effect=AssertionError('effect before map rejection: ' + name)))
            for role in ('bridge', 'exit'):
                for families in (['ipv4', 'ipv6'], ['ipv4'], ['ipv6']):
                    for root in roots:
                        for native_map in cases:
                            request = config(role, families=families); request['ingresses'] = native_map
                            with self.subTest(role=role, families=families, root=str(root), native_map=native_map):
                                with self.assertRaises(ValueError): n.configure(request, root=root)
                                with self.assertRaises(ValueError): n.plan(request)
        self.assertFalse(self.root.exists())
        self.assertFalse(roots[-1].exists())

    def test_default_and_normalized_authoritative_map_have_identical_plan(self):
        default = config()
        explicit = config(); explicit['ingresses'] = copy.deepcopy(n.NATIVE_MAP)
        normalized = config(); normalized['ingresses'] = {
            'rivet': {'ipv6': 'FD79:0001:0000:0000::/64', 'ipv4': '10.79.0.0/255.255.255.0', 'interface': 'xiorivet'},
            'awg': {'ipv6': 'FD78:0001:0000:0000::/64', 'ipv4': '10.78.0.0/255.255.255.0', 'interface': 'xioawg0'},
        }
        with patch.object(n, 'command', side_effect=AssertionError('must stay pure')):
            self.assertEqual(n.validate_config(default)['ingresses'], n.NATIVE_MAP)
            self.assertEqual(n.validate_config(explicit), n.validate_config(default))
            self.assertEqual(n.validate_config(normalized), n.validate_config(default))
            self.assertEqual(n.plan(normalized), n.plan(default))

    def test_hop_snat_and_preserve_exact_return_contract(self):
        for mode in ('hop-snat', 'preserve'):
            c = n.validate_config(config(mode=mode))
            spec = n.plan(c)
            for family in ('ipv4', 'ipv6'):
                for rule in spec['firewall'][family]['chains']['XIO_CNN']:
                    self.assertIn(n.MARK, rule)
                    self.assertIn(c['interface'], rule)
                    self.assertNotIn('-i', rule)  # invalid at POSTROUTING
                    self.assertIn('SNAT' if mode == 'hop-snat' else 'ACCEPT', rule)
                sources = n.source_networks(c, family)
                self.assertEqual(len(sources), 1 if mode == 'hop-snat' else 3)
                self.assertTrue(sources[0].endswith('/32' if family == 'ipv4' else '/128'))
            exit_plan = n.plan(config('exit', mode))
            for family in ('ipv4', 'ipv6'):
                self.assertTrue(all('MASQUERADE' in r for r in exit_plan['firewall'][family]['chains']['XIO_CNN']))

    def test_unrequested_family_is_prohibited_not_direct(self):
        spec = n.plan(config(families=['ipv4']))
        rules6 = spec['policy']['ipv6']
        for item in n.NATIVE_MAP.values():
            applicable = [r for r in rules6 if item['interface'] in r]
            self.assertEqual(len(applicable), 1)
            self.assertEqual(applicable[0][-1], 'prohibit')
        self.assertEqual(spec['firewall']['ipv6']['chains']['XIO_CNP'], [])
        self.assertTrue(all(r[-1] == 'DROP' for r in spec['firewall']['ipv6']['chains']['XIO_CNK']))
        self.assertEqual(spec['firewall']['ipv6']['chains']['XIO_CNN'], [])

    def test_terminal_fences_and_no_management_output_policy(self):
        spec = n.plan(config())
        text = json.dumps(spec)
        self.assertNotIn('OUTPUT', text)
        self.assertNotIn('uid', text)
        self.assertNotIn('main', text)
        for family in ('ipv4', 'ipv6'):
            for item in n.NATIVE_MAP.values():
                rules = [r for r in spec['policy'][family] if item['interface'] in r]
                self.assertEqual(len(rules), 2)
                self.assertIn(item[family], rules[0])
                self.assertEqual(rules[1][-1], 'prohibit')
                self.assertEqual(int(rules[1][1]), int(rules[0][1]) + 1)

    def test_linux_policy_json_normalization(self):
        row = {'priority': 12043, 'src': '10.78.0.0', 'srclen': 24, 'iif': 'xioawg0', 'table': '20792'}
        rule = ['priority', '12043', 'iif', 'xioawg0', 'from', '10.78.0.0/24', 'lookup', '20792']
        self.assertTrue(n.policy_matches(row, rule))
        row['table'] = 'main'; self.assertFalse(n.policy_matches(row, rule))

    def test_none_no_opt_in_or_exit_scope_and_no_side_effects(self):
        with patch.object(n, 'command', side_effect=AssertionError('unexpected process')):
            self.assertIsNone(n.native_capabilities(root=self.root))
            self.assertIsNone(n.desired_native_families(root=self.root))
            self.assertIsNone(n.reconcile_native(root=self.root))
            self.assertFalse(self.root.exists())
            self.state(config('exit'))
            self.assertIsNone(n.native_capabilities(root=self.root))
            self.assertIsNone(n.desired_native_families(root=self.root))

    def test_desired_families_are_not_capabilities(self):
        self.state(config(families=['ipv6']))
        desired = n.desired_native_families(root=self.root)
        self.assertEqual(desired, {p: {'ipv4': False, 'ipv6': True} for p in n.NATIVE_MAP})
        with patch.object(n, 'infrastructure', return_value=[]):
            caps = n.native_capabilities(root=self.root)
        for proto in n.NATIVE_MAP:
            self.assertFalse(caps[proto]['ipv4']); self.assertFalse(caps[proto]['ipv6'])
            self.assertEqual(caps[proto]['reason4'], 'family_not_selected_no_direct_fallback')

    def test_capability_requires_fresh_matching_proof_and_live_state(self):
        state = self.state()
        now = int(time.time())
        for proto in n.NATIVE_MAP:
            for family in ('ipv4', 'ipv6'):
                state['proofs'][proto + '.' + family] = dict(success=True, observedAt=now - (3 if family == 'ipv4' else 8), configHash=state['configHash'])
        n.save(self.root, state)
        with patch.object(n, 'infrastructure', return_value=[]):
            caps = n.native_capabilities(root=self.root)
        self.assertTrue(all(caps[p][f] for p in n.NATIVE_MAP for f in ('ipv4', 'ipv6')))
        self.assertTrue(caps['observedAt'].endswith('Z'))
        expected = n.datetime.datetime.fromtimestamp(now - 8 + n.PROOF_TTL, n.datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
        self.assertEqual(caps['expiresAt'], expected)
        with patch.object(n, 'infrastructure', return_value=['uplink_missing']):
            self.assertFalse(n.native_capabilities(root=self.root)['awg']['ipv4'])
        state['phase'] = 'fail_closed'; n.save(self.root, state)
        with patch.object(n, 'infrastructure', return_value=[]):
            self.assertFalse(n.native_capabilities(root=self.root)['awg']['ipv4'])
        state['phase'] = 'applied'
        for proof in state['proofs'].values(): proof['observedAt'] = now - 61
        n.save(self.root, state)
        with patch.object(n, 'infrastructure', return_value=[]):
            self.assertFalse(n.native_capabilities(root=self.root)['rivet']['ipv6'])
        for proof in state['proofs'].values(): proof.update(observedAt=now, configHash='foreign')
        n.save(self.root, state)
        with patch.object(n, 'infrastructure', return_value=[]):
            self.assertFalse(n.native_capabilities(root=self.root)['awg']['ipv4'])

    def test_receipt_ownership_and_hash_rejection(self):
        state = self.state()
        state['config']['peer']['host'] = '203.0.113.8'
        n.save(self.root, state)
        with self.assertRaises(RuntimeError): n.load(self.root)
        state['owner'] = 'foreign'; n.save(self.root, state)
        with self.assertRaises(RuntimeError): n.load(self.root)

    def test_apply_failure_retains_intent_without_unproved_guard_claim(self):
        with patch.object(n, 'owned_preflight'), patch.object(n, 'lifecycle_for', return_value=None), patch.object(n, '_apply', side_effect=RuntimeError('injected')):
            with self.assertRaises(RuntimeError): n.configure(config(), self.root)
        state = n.load(self.root)
        self.assertTrue(state['enabled'])
        self.assertEqual(state['phase'], 'apply_failed')
        self.assertEqual(state['guardState'], 'unknown')
        self.assertEqual(state['proofs'], {})
        self.assertEqual((self.root / 'private.key').stat().st_mode & 0o777, 0o600)

    def test_runtime_pin_no_unpinned_fallback(self):
        binary = Path(self.temp.name) / 'untrusted-runtime'
        binary.write_bytes(b'not signed AWG'); binary.chmod(0o700)
        with patch.object(n, 'AWG_PATHS', [str(binary)]):
            with self.assertRaises(RuntimeError): n.runtime_binary()
        self.assertFalse(self.root.exists())

    def test_reconcile_does_not_reset_unchanged_peer_handshake(self):
        self.state()
        n.atomic(self.root / 'private.key', KEY)
        c = n.validate_config(config())
        peer = {'publicKey': KEY, 'allowedIPs': ['0.0.0.0/0', '::/0'], 'endpoint': '203.0.113.7:9443', 'handshake': int(time.time())}
        with patch.object(n, 'peer_snapshot', return_value=peer), patch.object(n, 'uapi', side_effect=AssertionError('must not replace unchanged peer')), patch.object(n, 'command'):
            self.assertFalse(n.set_peer(self.root, c))

    def test_preserve_collision_rejected_but_explicit_hop_mode_coexists(self):
        def observe(*args):
            if args[:2] == ('addr', 'show'):
                return [{'addr_info': [{'family': 'inet', 'local': '198.18.0.1'}, {'family': 'inet6', 'local': 'fd00:ee::1'}]}]
            if 'get' in args: return [{'dev': 'eth0'}]
            return [{'dst': '10.78.0.0/24', 'dev': 'exitnative'}, {'dst': 'fd78:1::/64', 'dev': 'exitnative'}] if '-4' not in args else [{'dst': '10.78.0.0/24', 'dev': 'exitnative'}]
        with patch.object(n, 'exists_link', return_value=False), patch.object(n, 'chain_rules', return_value=None), patch.object(n, 'ipjson', side_effect=observe):
            with self.assertRaises(RuntimeError): n.owned_preflight(n.plan(config('exit', 'preserve')))
            # Supply family-correct existing local native routes per query.
            def correct(*args):
                if args[:2] == ('addr', 'show') or 'get' in args: return observe(*args)
                return [{'dst': '10.78.0.0/24', 'dev': 'exitnative'}] if '-4' in args else [{'dst': 'fd78:1::/64', 'dev': 'exitnative'}]
            with patch.object(n, 'ipjson', side_effect=correct): n.owned_preflight(n.plan(config('exit', 'hop-snat')))

    def test_dedicated_hops_cannot_steal_management_addresses_or_routes(self):
        def observe(*args):
            if args[:2] == ('addr', 'show'): return [{'addr_info': [{'local': '10.203.0.2'}]}]
            return []
        with patch.object(n, 'exists_link', return_value=False), patch.object(n, 'ipjson', side_effect=observe), patch.object(n, 'chain_rules', side_effect=AssertionError('reject before firewall')):
            with self.assertRaises(RuntimeError): n.owned_preflight(n.plan(config()))
        def foreign_route(*args):
            if args[:2] == ('addr', 'show'): return []
            return [{'dst': '10.203.0.0/24', 'dev': 'management0'}]
        with patch.object(n, 'exists_link', return_value=False), patch.object(n, 'ipjson', side_effect=foreign_route), patch.object(n, 'chain_rules', side_effect=AssertionError('reject before firewall')):
            with self.assertRaises(RuntimeError): n.owned_preflight(n.plan(config()))

    def test_remove_requires_explicit_restore_direct_confirmation(self):
        with self.assertRaises(ValueError): n.remove(root=self.root)
        self.assertFalse(self.root.exists())

    def test_foreign_rule_inside_owned_chain_not_flushed(self):
        spec = n.plan(config())
        with patch.object(n, 'chain_rules', return_value=[['-s', '192.0.2.0/24', '-j', 'ACCEPT']]), patch.object(n, 'command', side_effect=AssertionError('must not mutate')):
            with self.assertRaises(RuntimeError): n.firewall_sync(spec)


if __name__ == '__main__': unittest.main(verbosity=2)
