"""Pure actual-function boundary tests: no admin import-time or host effects."""
import ast
import base64
import copy
import importlib.util
import json
import os
import re
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent

def key(n):
    return base64.b64encode(bytes([n]) * 32).decode()

def alias(value):
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return value[:-2] + chars[chars.index(value[-2]) + 1] + '='

def functions(path, namespace):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    body = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), namespace)

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.d = dict(id='fixture', host='192.0.2.1', protocols=['awg'],
                      restrictedNetwork=True, publicKeys={'awg': key(90)}, awg={}, users={})
        self.events = []
        self.ns = dict(base64=base64, json=json, os=os, re=re, time=time, sys=sys, Path=Path)
        functions(HERE / 'admin.py', self.ns)
        self.ns.update(load=lambda: self.d, save=lambda d: self.events.append('save'),
                       render=lambda d: self.events.append('render'),
                       awg_uapi=lambda lines: self.events.append('uapi'), public=lambda d: {},
                       stats=lambda d: self.events.append('stats'))
        spec = importlib.util.spec_from_file_location('contract_dualstack', HERE / 'dualstack.py')
        self.ds = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ds)
        self.provider = types.SimpleNamespace(native_capabilities=lambda **kw: self.native,
                                               desired_native_families=lambda **kw: self.desired)
        self.native = None
        self.desired = None
        self.observations = []
        def module(*args):
            self.observations.append('native')
            return self.provider
        self.ds._native_module = module
        self.ds.cascade_status = lambda: {'alive': False}
        self.modules = patch.dict(sys.modules, dualstack=self.ds)
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def request(self, action='add', **extra):
        req = dict(action=action, serverId='fixture', id='2'*32, name='new')
        req.update({'publicKeys': {'awg': key(2)}} if action == 'add' else {'publicKey': key(2)})
        req.update(extra)
        return req

    def existing(self, value, uid='1'*32, revoked=False, protocol='awg'):
        keys = {protocol: value}
        if protocol == 'wireguard': keys['awg'] = key(4)
        self.d['users'][uid] = dict(name='old', slot=2, keys=keys, revoked=revoked)

    def reject(self, req, actor=None):
        before = copy.deepcopy(self.d)
        try:
            with self.assertRaises((AssertionError, RuntimeError, ValueError)):
                self.ns['dispatch'](req, actor)
            self.assertEqual(self.events, [], 'no persistence/render/UAPI before admission')
            self.assertEqual(self.d, before, 'do not normalize or repair foreign registry')
        finally:
            self.d = before
            self.events.clear()

    def readiness(self, v4=False, v6=True):
        stamp = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()
        self.native = dict(schema=1, enabled=True, connectorId='fixture-connector', revision=1,
                           observedAt=stamp(time.time()-1), expiresAt=stamp(time.time()+40),
                           awg=dict(ipv4=v4, ipv6=v6), rivet=dict(ipv4=v4, ipv6=v6))
        self.desired = {p: dict(ipv4=v4, ipv6=v6) for p in ('awg', 'rivet')}

    def test_equivalent_existing_including_revoked_and_cross_protocol(self):
        for action in ('add', 'add-awg'):
            for revoked in (False, True):
                for protocol in ('awg', 'wireguard'):
                    with self.subTest(action=action, revoked=revoked, protocol=protocol):
                        self.existing(alias(key(2)), revoked=revoked, protocol=protocol)
                        self.reject(self.request(action))

    def test_incoming_alias_of_existing(self):
        self.existing(key(2))
        self.reject(self.request(publicKeys={'awg': alias(key(2))}))

    def test_zero_and_server_aliases(self):
        for action in ('add', 'add-awg'):
            for value in (key(0), alias(key(0)), key(90), alias(key(90))):
                with self.subTest(action=action, case='zero' if value in (key(0), alias(key(0))) else 'server'):
                    field = {'publicKeys': {'awg': value}} if action == 'add' else {'publicKey': value}
                    self.reject(self.request(action, **field))

    def test_within_request_duplicate(self):
        self.d['protocols'] = ['wireguard', 'awg']
        self.d['publicKeys']['wireguard'] = key(91)
        self.reject(self.request(publicKeys={'awg': key(2), 'wireguard': alias(key(2))}))

    def test_ambiguous_or_malformed_existing_registry(self):
        for action in ('add', 'add-awg', 'revoke'):
            for value in (alias(key(3)), key(0), 'bad'):
                with self.subTest(action=action, malformed=value == 'bad'):
                    self.existing(key(3))
                    self.existing(value, uid='3'*32, revoked=True)
                    self.reject(self.request(action, id=('1' if action == 'revoke' else '2')*32))

    def test_normal_legacy_distinct_wg_awg_remains_valid(self):
        self.d['protocols'] = ['wireguard', 'awg']
        self.d['publicKeys']['wireguard'] = key(91)
        self.existing(alias(key(3)), protocol='wireguard')
        self.d['users']['1'*32]['keys']['awg'] = key(4)
        old = copy.deepcopy(self.d['users']['1'*32])
        self.ns['dispatch'](self.request(publicKeys={'wireguard': key(5), 'awg': key(6)}))
        self.assertEqual(self.d['users']['1'*32], old)
        self.assertIn('uapi', self.events)

    def test_incoming_noncanonical_is_canonicalized_or_rejected(self):
        req = self.request(publicKeys={'awg': alias(key(2))})
        try:
            self.ns['dispatch'](req)
        except (AssertionError, RuntimeError, ValueError):
            self.assertEqual(self.events, [])
        else:
            self.assertEqual(self.d['users']['2'*32]['keys']['awg'], key(2))

    def test_ordinary_revoke_and_repeat_remain_valid(self):
        self.existing(key(3))
        req = dict(action='revoke', serverId='fixture', id='1'*32)
        for _ in range(2):
            result = self.ns['dispatch'](req)
            self.assertEqual(result, {'revoked': '1'*32})
            self.assertTrue(self.d['users']['1'*32]['revoked'])

    def test_auth_and_identity_before_observations(self):
        self.reject(self.request('add-awg', serverId='wrong'))
        self.reject(self.request('add-awg'), actor='missing')
        self.assertEqual(self.observations, [])

    def test_native_selected_families_dns_and_both_captures(self):
        for v4, v6, dns in ((True, False, '9.9.9.9'), (False, True, '2620:fe::fe'),
                            (True, True, '9.9.9.9, 2620:fe::fe')):
            with self.subTest(v4=v4, v6=v6):
                self.d['users'].clear()
                self.readiness(v4, v6)
                result = self.ns['dispatch'](self.request('add-awg'))
                self.assertIn('DNS = '+dns+'\n', result['config'])
                allowed=', '.join(value for family,value in
                                 (('ipv4','0.0.0.0/0'),('ipv6','::/0'))
                                 if (v4 if family=='ipv4' else v6))
                self.assertIn('AllowedIPs = '+allowed+'\n', result['config'])

    def test_native_stale_down_malformed_and_changed_identity_pre_effects(self):
        for case in ('stale', 'down', 'malformed', 'identity', 'missing-intent', 'bad-intent', 'empty-intent', 'changed'):
            with self.subTest(case=case):
                self.readiness()
                if case == 'stale': self.native['expiresAt'] = '2000-01-01T00:00:00Z'
                if case == 'down': self.native['awg']['ipv6'] = False
                if case == 'malformed': self.native['awg']['ipv6'] = 'true'
                if case == 'identity': self.native['connectorId'] = ''
                if case == 'missing-intent': self.desired = None
                if case == 'bad-intent': self.desired['awg']['ipv6'] = 'true'
                if case == 'empty-intent': self.desired['awg']['ipv6'] = False
                if case == 'changed':
                    def changing(**kw):
                        self.native['revision'] += 1
                        return copy.deepcopy(self.native)
                    self.provider.native_capabilities = changing
                self.reject(self.request('add-awg'))

    def test_native_ipv6_only_cannot_remove_ipv4_capture(self):
        self.readiness(False, True)
        self.reject(self.request('add-awg', ipv6Only=True))

    def test_native_partial_selected_readiness_rejected(self):
        self.readiness(True, True)
        self.native['awg']['ipv4'] = False
        self.reject(self.request('add-awg'))

    def test_legacy_ipv6_only_requires_ipv6_and_no_v4_dns(self):
        self.reject(self.request('add-awg', ipv6Only=True))
        self.ds.cascade_status = lambda: {'alive': True}
        result = self.ns['dispatch'](self.request('add-awg', ipv6Only=True))
        self.assertIn('DNS = 2620:fe::fe\n', result['config'])
        self.assertIn('AllowedIPs = ::/0\n', result['config'])

    def test_observation_failure_before_effects_and_no_reobserve(self):
        def fail(): raise RuntimeError('observation failed')
        self.ds.cascade_status = fail
        self.reject(self.request('add-awg'))
        def once():
            self.assertEqual(self.events, [])
            self.ds.cascade_status = fail
            return {'alive': False}
        self.ds.cascade_status = once
        result = self.ns['dispatch'](self.request('add-awg'))
        self.assertIn('DNS = 9.9.9.9\n', result['config'])
        self.assertIn('uapi', self.events)

if __name__ == '__main__':
    unittest.main()
