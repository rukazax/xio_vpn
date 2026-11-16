"""Pure actual-source boundaries. Never import WebUI globals or execute admin main."""
import ast
import base64
import copy
import datetime
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
UID = 'a' * 32
SID = 'fixture-server'

def source_namespace(path):
    ns = dict(globals())
    ns.update(__name__='fixture_only', __file__=str(path))
    tree = ast.parse(path.read_text(encoding='utf-8'))
    # Definitions and literal constants only; no TokenStore(), imports or main.
    nodes = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            nodes.append(node)
        elif isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                if isinstance(node.value, ast.BinOp) and all(isinstance(n, (ast.BinOp, ast.Constant, ast.Mult)) for n in ast.walk(node.value)):
                    value = eval(compile(ast.Expression(node.value), '<constant>', 'eval'), {'__builtins__': {}})
                else:
                    continue
            for target in node.targets:
                if isinstance(target, ast.Name): ns[target.id] = value
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)
    return ns


def web():
    ns = source_namespace(HERE / 'xio-webui.py')
    # Windows Python may omit SIGKILL; POSIX branches below use a mocked os
    # namespace/killpg, never an actual signal. Do not alter the real module.
    if not hasattr(signal, 'SIGKILL'):
        ns['signal'] = types.SimpleNamespace(SIGKILL=9)
    ns.update(USER_RE=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$'), ADMIN_PY='/fixture/admin.py', SYSTEMCTL='/fixture/systemctl',
              TOKENS=types.SimpleNamespace(csrf='fixture-csrf'),
              log=Mock(), cert_fingerprint=lambda: 'fixture', _read_uptime=lambda: 1,
              unit_states=lambda: [], STATE_LOCK=threading.Lock())
    return ns


def issue_key(number, size=32):
    return base64.b64encode(bytes([number]) * size).decode('ascii')


def issue_material(uid=UID):
    return {
        'id': uid,
        'private': {'wireguard': issue_key(11), 'awg': issue_key(12)},
        'public': {'wireguard': issue_key(21), 'awg': issue_key(22)},
        'rivet': {'secret': issue_key(31), 'entryToken': issue_key(32)},
    }


def issue_server(native=None, with_rivet=True):
    result = {
        'id': SID, 'host': 'vpn.example', 'publicKeys': {'awg': issue_key(90)},
        'awg': {'Jc': 4, 'Jmin': 40, 'Jmax': 70, 'H1': 100000},
    }
    if with_rivet:
        result['rivet'] = {'serverName': 'vpn.example', 'pin': issue_key(91),
                           'gatewayId': issue_key(92, 16), 'ipv6': True}
    if native is not None:
        result['nativeProfileReadiness'] = native
    return result


def issue_xray():
    return json.dumps({'protocol': 'xray', 'outbound': {
        'protocol': 'vless',
        'settings': {'vnext': [{'address': 'vpn.example', 'port': 4443, 'users': [{
            'id': 'b3b2eb49-e41f-41df-9761-0956785a236b',
            'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]},
        'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'serverName': 'cdn.example', 'fingerprint': 'chrome',
            'publicKey': base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('='),
            'shortId': 'abcdef12'}}}})


def issue_reply(native=None, with_rivet=True):
    user = {'id': UID, 'name': 'Alice', 'slot': 4, 'revoked': False, 'role': 'user'}
    if with_rivet:
        user['rivet'] = True
    return {'ok': True, 'user': user, 'server': issue_server(native, with_rivet),
            'phase': 'ready', 'configs': {'xray': issue_xray(), 'cloak': 'DO-NOT-EXPORT'}}


def ready_metadata(v4=True, v6=True, awg_selected=True):
    stamp = lambda timestamp: datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
    now = time.time()
    return {'schema': 1, 'enabled': True, 'connectorId': 'fixture-connector', 'revision': 1,
            'observedAt': stamp(now - 1), 'expiresAt': stamp(now + 40),
            'awg': {'ipv4': v4, 'ipv6': v6}, 'rivet': {'ipv4': v4, 'ipv6': v6},
            'requiredFamilies': {
                'awg': {'ipv4': v4 and awg_selected, 'ipv6': v6 and awg_selected},
                'rivet': {'ipv4': v4, 'ipv6': v6}}}


def bundle_decode(profile):
    assert profile.startswith('xio://')
    encoded = profile[6:]
    return json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.w = web()
        self.commands = []
        self.reply = {'ok': True, 'server': {'id': SID}, 'phase': 'ready'}
        self.rc = 0
        def command(argv, body, timeout):
            self.commands.append((argv, json.loads(body)))
            return dict(rc=self.rc, out=json.dumps(self.reply), err='DO-NOT-LEAK', timeout=False, started=True)
        self.w['run_command'] = command  # legacy RED boundary
        self.w['run_admin_command'] = command
        self.isfile = patch.object(os.path, 'isfile', return_value=True)
        self.isfile.start()
        self.addCleanup(self.isfile.stop)

    def test_actual_owner_argv_and_json_action(self):
        result = self.w['admin_call']('inspect', {})
        self.assertTrue(result['ok'])
        self.assertEqual(self.commands[0][0], [sys.executable, '/fixture/admin.py'])
        self.assertEqual(self.commands[0][1], {'action': 'inspect'})

    def test_false_envelope_never_succeeds(self):
        self.reply = {'ok': False, 'error': 'DO-NOT-LEAK'}
        result = self.w['admin_call']('inspect', {})
        self.assertFalse(result['ok'])
        self.assertNotIn('DO-NOT-LEAK', json.dumps(result))

    def test_action_override_rejected_without_command(self):
        result = self.w['admin_call']('inspect', {'action': 'remove'})
        self.assertFalse(result['ok'])
        self.assertEqual(self.commands, [])

    def test_revoke_uses_uid_and_rendered_identity(self):
        handler = object.__new__(self.w['Handler'])
        self.reply = {'ok': True, 'revoked': UID}
        result = handler._do_user_revoke({'expectedServerId': SID, 'id': UID})
        self.assertTrue(result['ok'])
        self.assertEqual(self.commands[0][1], {'action': 'revoke', 'serverId': SID, 'id': UID})

    def test_generic_nonzero_mutation_is_unknown(self):
        self.reply = {'ok': False, 'error': 'DO-NOT-LEAK'}
        self.rc = 1
        result = self.w['admin_call']('revoke', {'serverId': SID, 'id': UID})
        self.assertTrue(result.get('outcomeUnknown'))
        self.assertNotIn('DO-NOT-LEAK', json.dumps(result))

    def test_unknown_uid_rejected_before_stats(self):
        ns = source_namespace(HERE.parent / 'managed/admin.py')
        effects = []
        ns.update(load=lambda: {'id': SID, 'users': {}}, peer_key_admission=lambda *a: {},
                  stats=lambda *a: effects.append('stats'))
        with self.assertRaises((AssertionError, ValueError)):
            ns['dispatch']({'action': 'revoke', 'serverId': SID, 'id': UID})
        self.assertEqual(effects, [])




class ExtendedTests(unittest.TestCase):
    setUp = ContractTests.setUp

    def test_bad_envelopes(self):
        for reply in ([], None, 'x', 1, {}, {'ok': 1}, {'ok': 'true'}, {'data': {'ok': True}}):
            with self.subTest(reply=reply):
                self.reply = reply
                self.assertFalse(self.w['admin_call']('inspect', {})['ok'])

    def test_invalid_and_nonzero_success_are_unknown(self):
        for rc, raw in ((0, '{'), (0, '{"ok":true,"ok":false}'), (0, '{"ok":NaN}'),
                        (0, '{"ok":true} garbage'), (1, json.dumps({'ok': True, 'revoked': UID})),
                        (-9, '')):
            self.w['run_admin_command'] = lambda *a: dict(rc=rc, out=raw, timeout=False, started=True)
            result = self.w['admin_call']('revoke', {'serverId': SID, 'id': UID})
            self.assertFalse(result['ok']); self.assertTrue(result['outcomeUnknown'])
            self.assertNotIn('data', result)

    def test_timeout_and_not_started(self):
        for started in (True, False):
            self.w['run_admin_command'] = lambda *a: dict(rc=124, out='', timeout=True, started=started)
            result = self.w['admin_call']('revoke', {'serverId': SID, 'id': UID})
            self.assertEqual(result['outcomeUnknown'], started)
            self.assertEqual(result['code'], 504)

    def test_exact_revoke_reply(self):
        self.reply = {'ok': True, 'revoked': 'b'*32}
        result = self.w['admin_call']('revoke', {'serverId': SID, 'id': UID})
        self.assertFalse(result['ok']); self.assertTrue(result['outcomeUnknown'])

    def test_large_status_projection_and_names(self):
        self.reply = {'ok': True, 'server': {'id': SID, 'rivet': {'secret': 'SECRET'}},
                      'sampledAt': 1000, 'users': [dict(id=('%032x' % n), name='same', revoked=(n == 1),
                      role='user', keys={'awg': 'SECRET'}, stats={'awg': {'rx': 10, 'tx': 20}},
                      ignored='SECRET'*100) for n in range(10)]}
        self.assertGreater(len(json.dumps(self.reply)), 4000)
        result = self.w['admin_call']('status', {'serverId': SID})
        self.assertTrue(result['ok']); data = result['data']
        self.assertEqual(len(data['users']), 10)
        self.assertTrue(data['users'][1]['revoked'])
        self.assertEqual(data['traffic'], {'rx': 100, 'tx': 200})
        self.assertNotIn('SECRET', json.dumps(result))
        self.reply['users'][0]['stats'] = {'awg': {'rx': float('nan'), 'tx': -1}}
        self.assertFalse(self.w['admin_call']('status', {'serverId': SID})['ok'])

    def test_status_identity_mismatch(self):
        self.reply = {'ok': True, 'server': {'id': 'new'}, 'users': [], 'sampledAt': 1000}
        self.assertFalse(self.w['admin_call']('status', {'serverId': SID})['ok'])

    def test_state_order_reinit_and_no_fallback(self):
        calls = []
        def run(argv, body, timeout):
            req = json.loads(body); calls.append(req)
            if req['action'] == 'inspect':
                reply = {'ok': True, 'server': {'id': SID}, 'phase': 'ready'}
            else:
                reply = {'ok': False, 'error': 'Server identity changed; reopen setup'}
            return dict(rc=0 if reply['ok'] else 1, out=json.dumps(reply), started=True)
        self.w['run_admin_command'] = run
        state = self.w['build_state']()
        self.assertEqual([x['action'] for x in calls], ['inspect', 'status'])
        self.assertEqual(calls[1]['serverId'], SID)
        self.assertFalse(state['managedAvailable']); self.assertIsNone(state['users'])
        self.assertIsNone(state['server']['id']); self.assertIsNone(state['traffic']['rx'])

    def test_native_mixed_identity_discards_whole_context(self):
        calls = []
        def run(argv, body, timeout):
            req = json.loads(body); calls.append(req)
            reply = {'ok': True, 'server': {'id': SID}, 'phase': 'ready'}
            if req['action'] == 'status': reply.update(users=[], sampledAt=int(time.time()))
            if req['action'] == 'cascade-native':
                reply.update(server={'id': 'different-server'}, nativeCascade={'schema': 1, 'enabled': False})
            return dict(rc=0, out=json.dumps(reply), started=True)
        self.w['run_admin_command'] = run
        state = self.w['build_state']()
        self.assertFalse(state['managedAvailable']); self.assertIsNone(state['server']['id'])
        self.assertIsNone(state['users']); self.assertIsNone(state['traffic']['rx'])
        self.assertFalse(state['nativeCascade']['available'])
        self.assertEqual([r['action'] for r in calls], ['inspect', 'status', 'cascade-native'])
        # Same optional native failure, without evidence of another identity,
        # must not erase a successfully observed managed status.
        previous = run
        def unavailable(argv, body, timeout):
            if json.loads(body)['action'] == 'cascade-native':
                return dict(rc=1, out=json.dumps({'ok': False, 'errorCode': 'MODULE_UNAVAILABLE', 'outcomeUnknown': False}), started=True)
            return previous(argv, body, timeout)
        self.w['run_admin_command'] = unavailable
        state = self.w['build_state']()
        self.assertTrue(state['managedAvailable']); self.assertEqual(state['server']['id'], SID)
        self.assertFalse(state['nativeCascade']['available'])

    def test_empty_status_is_known_zero(self):
        def run(argv, body, timeout):
            req = json.loads(body)
            result = {'ok': True, 'server': {'id': SID}}
            if req['action'] == 'inspect': result['phase'] = 'ready'
            elif req['action'] == 'status': result.update(users=[], sampledAt=1000)
            else:
                self.assertEqual(req, {'action': 'cascade-native', 'serverId': SID, 'operation': 'inspect'})
                result['nativeCascade'] = {'schema': 1, 'enabled': False}
            return dict(rc=0, out=json.dumps(result))
        self.w['run_admin_command'] = run
        state = self.w['build_state']()
        self.assertTrue(state['managedAvailable']); self.assertEqual(state['users'], [])
        self.assertEqual(state['traffic'], {'rx': 0, 'tx': 0})
        self.assertFalse(state['nativeCascade']['enabled'])
        self.assertEqual(state['cascade']['state'], 'unknown')

    def test_add_rejects_malformed_payloads_without_effects(self):
        h = object.__new__(self.w['Handler']); h.headers = {'X-XIO-Unit': 'xio-stack'}
        for payload in ({}, {'name': 'only'}, {'action': 'add', 'privateKey': 'SECRET'}):
            result = h._do_user_add(payload)
            self.assertEqual(result['errorCode'], 'INVALID_REQUEST')
        for payload in ({'name': 'name'}, {'expectedServerId': SID, 'id': UID, 'action': 'remove'},
                        {'expectedServerId': SID, 'id': True}, {'expectedServerId': True, 'id': UID}):
            self.assertFalse(h._do_user_revoke(payload)['ok'])
        self.assertEqual(self.commands, [])

    def test_native_no_mutations_and_finite_errors(self):
        for operation in ('verify', 'configure', 'remove', 'reconcile', 'preflight'):
            self.assertFalse(self.w['admin_call']('cascade-native', {'serverId': SID, 'operation': operation})['ok'])
        self.assertEqual(self.commands, [])
        self.rc = 1
        self.reply = {'ok': False, 'errorCode': 'IO_FAILURE', 'outcomeUnknown': True, 'error': 'SECRET'}
        result = self.w['admin_call']('cascade-native', {'serverId': SID, 'operation': 'inspect'})
        self.assertEqual(result['errorCode'], 'IO_FAILURE'); self.assertTrue(result['outcomeUnknown'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_native_stale_does_not_become_gateway_health(self):
        value = dict(schema=1, enabled=True, phase='applied', connectorId='c', revision=1,
                     infrastructureReady=True, guardState='last_installed', config={'innerFamilies': ['ipv6']},
                     capabilities=dict(schema=1, enabled=True, connectorId='c', revision=1, observedAt='2000-01-01T00:00:00Z',
                     expiresAt='2000-01-01T00:00:30Z', awg={'ipv4': True, 'ipv6': True},
                     rivet={'ipv4': True, 'ipv6': True}), secret='SECRET')
        projected = self.w['project_native'](value)
        self.assertTrue(projected['enabled']); self.assertFalse(projected['fresh'])
        self.assertFalse(projected['readiness']['awg']['ipv6'])
        self.assertNotIn('SECRET', json.dumps(projected))


class IssuanceTests(ContractTests):
    def setUp(self):
        super().setUp()
        self.material = issue_material()
        # Production clears the one-time material after building the response.
        # Each mocked call must receive its own copy while expected values stay.
        self.w['generate_issuance_material'] = Mock(
            side_effect=lambda: copy.deepcopy(self.material))
        self.reply = issue_reply()

    def add(self, name='Alice'):
        handler = object.__new__(self.w['Handler'])
        return handler._do_user_add({'expectedServerId': SID, 'name': name})

    def test_real_add_and_android_bundle_only_in_single_response(self):
        result = self.add('  Alice  ')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['outcomeUnknown'], False)
        self.assertEqual(set(result['data']), {'uid', 'profile'})
        self.assertEqual(result['data']['uid'], UID)
        request = self.commands[0][1]
        self.assertEqual(request, {
            'action': 'add', 'serverId': SID, 'id': UID, 'name': 'Alice',
            'publicKeys': self.material['public'], 'rivet': self.material['rivet'],
            'admin': False, 'userLimit': 0})
        command_text = json.dumps(self.commands)
        self.assertNotIn(issue_key(11), command_text)
        self.assertNotIn(issue_key(12), command_text)

        bundle = bundle_decode(result['data']['profile'])
        self.assertEqual(bundle, {
            'schema': 1, 'name': 'Alice', 'userId': UID, 'serverId': SID,
            'configs': bundle['configs']})
        self.assertEqual(set(bundle['configs']), {'awg', 'rivet-h3', 'rivet-s1', 'xray'})
        awg = bundle['configs']['awg']
        self.assertIn('PrivateKey = '+issue_key(12)+'\n', awg)
        self.assertNotIn(issue_key(11), awg)
        self.assertIn('Address = 10.78.0.4/32, fd78:1::4/128\n', awg)
        self.assertIn('DNS = 9.9.9.9, 2620:fe::fe\n', awg)
        self.assertIn('PublicKey = '+issue_key(90)+'\n', awg)
        self.assertIn('Endpoint = vpn.example:51821\n', awg)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0\n', awg)
        for protocol in ('rivet-h3', 'rivet-s1'):
            rivet = json.loads(bundle['configs'][protocol])
            self.assertEqual(rivet, {
                'protocol': protocol, 'endpoint': 'vpn.example:8443',
                'serverName': 'vpn.example', 'pin': issue_key(91),
                'gatewayId': issue_key(92, 16), 'id': UID,
                'secret': issue_key(31), 'entryToken': issue_key(32),
                'ip': '10.79.0.4', 'ip6': 'fd79:1::4'})
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(bundle))
        self.assertNotIn('adminAccess', bundle)
        self.assertNotIn('clientAccess', bundle)

        # State and logs never replay the one-time response or private inputs.
        add_result = json.dumps(result)
        previous = self.w['run_admin_command']
        def state_command(argv, body, timeout):
            req = json.loads(body)
            response = {'ok': True, 'server': {'id': SID}}
            if req['action'] == 'inspect':
                response['phase'] = 'ready'
            elif req['action'] == 'status':
                response.update(users=[], sampledAt=int(time.time()))
            else:
                response['nativeCascade'] = {'schema': 1, 'enabled': False}
            return dict(rc=0, out=json.dumps(response), started=True)
        self.w['run_admin_command'] = state_command
        state = self.w['build_state']()
        state_text = json.dumps(state)
        for forbidden in (result['data']['profile'], issue_key(11), issue_key(12),
                          issue_key(31), issue_key(32), 'DO-NOT-EXPORT'):
            self.assertNotIn(forbidden, state_text)
            self.assertNotIn(forbidden, json.dumps(self.w['log'].call_args_list))
        self.assertTrue(add_result.startswith('{'))

    def test_frontend_payload_has_no_keys_or_admin_fields(self):
        for payload in ({}, {'expectedServerId': SID}, {'name': 'Alice'},
                        {'expectedServerId': SID, 'name': ''},
                        {'expectedServerId': SID, 'name': ' '},
                        {'expectedServerId': SID, 'name': 'x'*81},
                        {'expectedServerId': True, 'name': 'Alice'},
                        {'expectedServerId': SID, 'name': 'Alice', 'privateKey': issue_key(1)},
                        {'expectedServerId': SID, 'name': 'Alice', 'admin': True}):
            with self.subTest(payload=payload):
                # Exercise the submitted identity; add() intentionally injects
                # the correct fixture ID and cannot test a stale/typed server.
                result = object.__new__(self.w['Handler'])._do_user_add(payload)
                self.assertFalse(result['ok'])
                self.assertEqual(result['errorCode'], 'INVALID_REQUEST')
        self.assertEqual(self.commands, [])
        self.w['generate_issuance_material'].assert_not_called()

    def test_direct_add_requires_exact_public_material(self):
        request = {'serverId': SID, 'id': UID, 'name': 'Alice',
                   'publicKeys': self.material['public'], 'rivet': self.material['rivet'],
                   'admin': False, 'userLimit': 0}
        self.assertTrue(self.w['admin_call']('add', request)['ok'])
        self.assertEqual(len(self.commands), 1)
        self.commands.clear()
        for changed in ({'privateKey': issue_key(1)}, {'admin': True}, {'userLimit': True},
                        {'id': 'not-a-uid'}, {'name': ''},
                        {'publicKeys': {'awg': issue_key(1)}},
                        {'rivet': {'secret': issue_key(0), 'entryToken': issue_key(2)}}):
            with self.subTest(changed=changed):
                self.assertFalse(self.w['admin_call']('add', dict(request, **changed))['ok'])
        self.assertEqual(self.commands, [])

    def test_pinned_wg_adapter_generates_private_on_stdin_only(self):
        w = web()
        w['_pinned_wg'] = lambda: '/usr/bin/wg'
        outputs = iter([issue_key(11), issue_key(21), issue_key(12), issue_key(22)])
        calls = []
        def command(argv, body, timeout):
            calls.append((argv, body))
            return dict(rc=0, out=next(outputs), started=True, timeout=False)
        w['run_admin_command'] = command
        material = w['generate_issuance_material']()
        self.assertEqual(material['private'], {'wireguard': issue_key(11), 'awg': issue_key(12)})
        self.assertEqual(material['public'], {'wireguard': issue_key(21), 'awg': issue_key(22)})
        self.assertEqual([call[0] for call in calls], [
            ['/usr/bin/wg', 'genkey'], ['/usr/bin/wg', 'pubkey'],
            ['/usr/bin/wg', 'genkey'], ['/usr/bin/wg', 'pubkey']])
        for argv, body in calls:
            self.assertNotIn(issue_key(11), argv)
            self.assertNotIn(issue_key(12), argv)
        self.assertEqual(calls[1][1], (issue_key(11)+'\n').encode())
        self.assertEqual(calls[3][1], (issue_key(12)+'\n').encode())

    def test_missing_or_bad_key_utility_has_no_admin_effects(self):
        self.w['generate_issuance_material'] = Mock(side_effect=self.w['KeyUtilityUnavailable'])
        result = self.add()
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 503)
        self.assertEqual(result['errorCode'], 'KEY_UNAVAILABLE')
        self.assertFalse(result['outcomeUnknown'])
        self.assertEqual(self.commands, [])
        w = web(); w['_pinned_wg'] = lambda: None
        with self.assertRaises(w['KeyUtilityUnavailable']):
            w['generate_peer_key']()

    def test_add_timeout_is_unknown_without_blanket_revoke(self):
        self.w['run_admin_command'] = lambda argv, body, timeout: dict(
            rc=124, out='', timeout=True, started=True)
        result = self.add()
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 504)
        self.assertTrue(result['outcomeUnknown'])
        self.assertNotIn('data', result)
        self.assertEqual(self.commands, [])

    def test_success_envelope_with_bad_profile_metadata_is_not_false_success(self):
        for mutate in ('host', 'stale', 'missing-rivet', 'bad-xray', 'slot'):
            with self.subTest(mutate=mutate):
                self.setUp()
                if mutate == 'host': self.reply['server']['host'] = '[127.0.0.1]'
                if mutate == 'stale':
                    self.reply['server']['nativeProfileReadiness'] = ready_metadata()
                    self.reply['server']['nativeProfileReadiness']['expiresAt'] = '2000-01-01T00:00:00Z'
                if mutate == 'missing-rivet':
                    self.reply['server'].pop('rivet')
                    self.reply['server']['nativeProfileReadiness'] = ready_metadata()
                if mutate == 'bad-xray':
                    self.reply['configs']['xray'] = issue_xray().replace('"chrome"', '"chrome", "allowInsecure": true')
                if mutate == 'slot': self.reply['user']['slot'] = 1
                result = self.add()
                self.assertFalse(result['ok'])
                self.assertTrue(result['outcomeUnknown'])
                self.assertNotIn('data', result)
                self.assertEqual(len(self.commands), 1)
                self.assertEqual(self.commands[0][1]['action'], 'add')

    def test_native_rivet_only_profile_ignores_removed_proxy_transports(self):
        self.reply = issue_reply(native=ready_metadata(v4=False, v6=True, awg_selected=False))
        result = self.add()
        self.assertTrue(result['ok'], result)
        bundle = bundle_decode(result['data']['profile'])
        self.assertEqual(set(bundle['configs']), {'rivet-h3', 'rivet-s1'})
        for protocol in ('rivet-h3', 'rivet-s1'):
            rivet = json.loads(bundle['configs'][protocol])
            self.assertEqual(rivet['ip'], '10.79.0.4')
            self.assertEqual(rivet['ip6'], 'fd79:1::4')
        self.assertNotIn('DO-NOT-EXPORT', json.dumps(bundle))

    def test_legacy_without_rivet_still_exports_actual_awg_and_xray(self):
        self.reply = issue_reply(with_rivet=False)
        result = self.add()
        self.assertTrue(result['ok'], result)
        bundle = bundle_decode(result['data']['profile'])
        self.assertEqual(set(bundle['configs']), {'awg', 'xray'})
        self.assertIn('DNS = 9.9.9.9\n', bundle['configs']['awg'])
        self.assertNotIn('2620:fe::fe', bundle['configs']['awg'])


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.ns = source_namespace(HERE.parent/'managed/admin.py')
        self.effects = []
        self.d = {'id': SID, 'users': {UID: dict(name='same', revoked=False, role='admin'),
                   'b'*32: dict(name='same', revoked=False, role='user', createdBy=UID)}}
        self.ns.update(load=lambda: self.d, run=lambda *a: self.effects.append(a),
                       stats=lambda *a: self.effects.append('stats'), peer_key_admission=lambda *a: {},
                       save=lambda *a: self.effects.append('save'), apply=lambda *a: self.effects.append('apply'),
                       delegation_key=lambda *a: self.effects.append('delegation'))

    def test_owner_service_exact_command(self):
        req = dict(action='service', serverId=SID, verb='restart', unit='xio-stack')
        with patch.dict(os.environ, {}, clear=True):
            result = self.ns['dispatch'](req)
        self.assertEqual(self.effects, [('systemctl', 'restart', 'xio-stack')])
        self.assertEqual(result['service'], {k: req[k] for k in ('serverId', 'unit', 'verb')})

    def test_service_rejects_before_effects(self):
        req = dict(action='service', serverId=SID, verb='start', unit='xio-stack')
        for change in ({'serverId': 'other'}, {'unit': 'ssh'}, {'verb': 'enable'}, {'argv': ['id']}, {'actor': None}):
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(AssertionError):
                self.ns['dispatch'](dict(req, **change))
        for actor in (UID, False, ''):
            with self.assertRaises(AssertionError): self.ns['dispatch'](req, actor)
        with patch.dict(os.environ, {'SSH_ORIGINAL_COMMAND': ''}), self.assertRaises(AssertionError):
            self.ns['dispatch'](req)
        self.assertEqual(self.effects, [])

    def test_actual_cli_admission_is_inside_lock(self):
        tree = ast.parse((HERE.parent/'managed/admin.py').read_text(encoding='utf-8'))
        main = next(n for n in tree.body if isinstance(n, ast.If) and '__name__' in ast.unparse(n.test))
        lock = next(n for n in ast.walk(main) if isinstance(n, ast.With))
        self.assertIn('xio-managed.lock', ast.unparse(lock.items[0]))
        self.assertIn('dispatch(json.loads(raw), actor)', ast.unparse(lock))
        # Execute the real CLI admission/envelope branch, with IO/dispatch faked;
        # not the root check, flock or module initialization.
        branch = next(n for n in ast.walk(lock) if isinstance(n, ast.If) and ast.unparse(n.test) == "sys.argv[1:] == ['sample']")
        output = []
        ns = dict(self.ns, sys=types.SimpleNamespace(argv=['admin.py'], stdin=types.SimpleNamespace(buffer=io.BytesIO(b'{"action":"inspect"}'))),
                  print=lambda raw: output.append(json.loads(raw)), dispatch=lambda req, actor: {'phase': 'ready'})
        exec(compile(ast.Module(body=[branch], type_ignores=[]), '<actual-cli-branch>', 'exec'), ns)
        self.assertEqual(output, [{'ok': True, 'phase': 'ready'}])
        ns['sys'].argv = ['admin.py', 'inspect']
        with self.assertRaises(AssertionError): exec(compile(ast.Module(body=[branch], type_ignores=[]), '<actual-cli-branch>', 'exec'), ns)

    def test_partial_apply_failure_registry_is_not_success(self):
        self.d['stack'] = True
        self.ns['stack'] = types.SimpleNamespace(network=types.SimpleNamespace(revoke=lambda *a: self.effects.append('network')),
                                                apply=Mock(side_effect=RuntimeError('SECRET')))
        w = web(); commands = []
        def command(argv, body, timeout):
            commands.append(json.loads(body))
            try: result = {'ok': True, **self.ns['dispatch'](commands[-1])}; rc = 0
            except Exception as e: result = {'ok': False, 'error': str(e)}; rc = 1
            return dict(rc=rc, out=json.dumps(result), started=True)
        w['run_admin_command'] = command
        with patch.object(os.path, 'isfile', return_value=True):
            result = w['admin_call']('revoke', {'serverId': SID, 'id': UID})
        self.assertTrue(self.d['users'][UID]['revoked'])
        self.assertTrue(self.d['users']['b'*32]['revoked'])
        self.assertFalse(result['ok']); self.assertTrue(result['outcomeUnknown'])
        self.assertEqual(len(commands), 1); self.assertNotIn('SECRET', json.dumps(result))

    def test_wrong_identity_before_stats_or_runtime(self):
        with self.assertRaises(AssertionError): self.ns['dispatch']({'action':'revoke','serverId':'wrong','id':UID})
        self.assertEqual(self.effects, [])

    def test_unit_keeps_sandbox_and_narrow_optional_paths(self):
        text = (HERE/'xio-webui.service').read_text(encoding='utf-8')
        for directive in ('ProtectSystem=full', 'ProtectHome=read-only', 'ProtectKernelTunables=yes',
                          'ProtectKernelModules=yes', 'ProtectControlGroups=yes', 'RestrictSUIDSGID=yes'):
            self.assertIn(directive, text)
        paths = [p for line in text.splitlines() if line.startswith('ReadWritePaths=') for p in line.split('=',1)[1].split()]
        for path in ('/etc/xio-stack','/etc/xio-rivet','/etc/wireguard','/etc/xio-mesh','/root/.ssh'):
            self.assertIn('-'+path, paths)
        self.assertFalse(set(paths) & {'/etc', '-/etc', '/root', '-/root', '/home', '-/home'})
        installer = (HERE/'install-webui.sh').read_text(encoding='utf-8')
        self.assertIn('for file in xio-webui.py index.html xio-webui.service README.md;', installer)


class CaptureTests(unittest.TestCase):
    def test_intact_bounded_reader(self):
        for content, limit, wanted in ((b'x'*5000, 10000, 5000), (b'x'*10001, 10000, 0), (b'\xff', 10000, 0)):
            w = web(); w['MAX_ADMIN_OUTPUT'] = limit
            proc = types.SimpleNamespace(stdin=io.BytesIO(), stdout=io.BufferedReader(io.BytesIO(content)),
                                         returncode=0, pid=123, wait=Mock(return_value=0), kill=Mock())
            with patch.object(subprocess, 'Popen', return_value=proc), patch.object(os, 'killpg', create=True) as kill:
                result = w['run_admin_command'](['fixture'], b'{}', 1)
            self.assertEqual(len(result['out']), wanted)
            self.assertTrue(result['started'])

    def test_spawn_failure_known_no_effect(self):
        with patch.object(subprocess, 'Popen', side_effect=OSError('SECRET')):
            result = web()['run_admin_command'](['fixture'], b'{}', 1)
        self.assertFalse(result['started']); self.assertNotIn('SECRET', json.dumps(result))


    def test_deadline_kills_mocked_session_without_retry(self):
        w = web(); release = threading.Event()
        class Pipe:
            def read1(self, size):
                release.wait(1)
                return b''
            def close(self): pass
        proc = types.SimpleNamespace(stdin=io.BytesIO(), stdout=Pipe(), returncode=-9, pid=123,
                                     wait=Mock(return_value=-9), kill=Mock(side_effect=release.set))
        with patch.object(subprocess, 'Popen', return_value=proc) as spawn, patch.object(os, 'killpg', side_effect=lambda *a: release.set(), create=True):
            result = w['run_admin_command'](['fixture'], b'{}', 0.01)
        self.assertTrue(result['timeout']); self.assertEqual(spawn.call_count, 1)
        self.assertEqual(result['out'], '')

    def test_posix_capture_namespace_and_mocked_group_kill(self):
        # Exercise both branches on Windows too; never send a real signal.
        for mode in ('oversize', 'timeout'):
            with self.subTest(mode=mode):
                w = web(); w['MAX_ADMIN_OUTPUT'] = 1
                release = threading.Event()
                killed = Mock(side_effect=lambda *args: release.set())
                w['os'] = types.SimpleNamespace(name='posix', killpg=killed)
                class SlowPipe:
                    def read1(self, size):
                        release.wait(1)
                        return b''
                    def close(self): pass
                stdout = io.BufferedReader(io.BytesIO(b'xx')) if mode == 'oversize' else SlowPipe()
                proc = types.SimpleNamespace(stdin=io.BytesIO(), stdout=stdout, returncode=-9, pid=123,
                                             wait=Mock(return_value=-9), kill=Mock())
                with patch.object(subprocess, 'Popen', return_value=proc) as spawn:
                    result = w['run_admin_command'](['fixture'], b'{}', .01)
                self.assertEqual(result['out'], '')
                killed.assert_called_once_with(123, w['signal'].SIGKILL)
                self.assertEqual(result['timeout'], mode == 'timeout')
                self.assertEqual(spawn.call_count, 1); proc.kill.assert_not_called()

    def test_strict_json_complexity_nonfinite_and_duplicate(self):
        decode = web()['strict_json']
        for raw in ('{"x":1e400}', '{"x":-Infinity}', '{"ok":true,"ok":false}', '['*34+'0'+']'*34):
            with self.assertRaises(ValueError): decode(raw)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.w = web(); self.commands = []
        self.w['TOKENS'] = types.SimpleNamespace(csrf='csrf', check=lambda value: value == 'token', check_csrf=lambda value: value == 'csrf')
        self.w['SESSIONS'] = self.w['Sessions']()
        self.w['LIMITER'] = self.w['RateLimiter']()
        def command(argv, body, timeout):
            req = json.loads(body); self.commands.append(req)
            return dict(rc=0, out=json.dumps({'ok': True, 'revoked': req.get('id')}), started=True)
        self.w['run_admin_command'] = command
        self.pathpatch = patch.object(os.path, 'isfile', return_value=True); self.pathpatch.start(); self.addCleanup(self.pathpatch.stop)

    def request(self, path='/api/user/revoke', method='POST', payload=None, headers=None, raw=None):
        if payload is None: payload = {'expectedServerId': SID, 'id': UID}
        body = json.dumps(payload).encode() if raw is None else raw
        fields = {'Host': 'fixture', 'Content-Type': 'application/json', 'Content-Length': str(len(body)),
                  'Authorization': 'Bearer token', 'X-XIO-CSRF': 'csrf'}
        fields.update(headers or {})
        req = (method+' '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in fields.items())+'\r\n').encode()+body
        h = object.__new__(self.w['Handler']); h.rfile=io.BytesIO(req); h.wfile=io.BytesIO()
        h.client_address=('fixture', 1); h.server=types.SimpleNamespace()
        h.close_connection=True
        h.handle_one_request()
        response = h.wfile.getvalue(); head, _, data = response.partition(b'\r\n\r\n')
        return int(head.split()[1]), json.loads(data) if data else {}, head.decode()

    def test_handler_to_actual_adapter(self):
        code, data, headers = self.request()
        self.assertEqual(code, 200); self.assertTrue(data['ok'])
        self.assertEqual(data['data'], {'revoked': UID, 'serverId': SID})
        self.assertEqual(self.commands, [{'action':'revoke','serverId':SID,'id':UID}])
        for name in ('Cache-Control: no-store', 'X-Content-Type-Options: nosniff', 'X-Frame-Options: DENY', 'Content-Length:'):
            self.assertIn(name, headers)

    def test_auth_csrf_cookie_and_no_effects(self):
        for headers, expected in (({'Authorization':''},401), ({'X-XIO-CSRF':''},403), ({'X-XIO-CSRF':'bad'},403)):
            self.assertEqual(self.request(headers=headers)[0], expected)
        sid = self.w['SESSIONS'].create()
        self.assertEqual(self.request(headers={'Authorization':'','Cookie':'xio_sid='+sid,'X-XIO-CSRF':''})[0],403)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.request(headers={'Authorization':'','Cookie':'xio_sid='+sid})[0],200)
        self.w['SESSIONS']._data[sid] = 0
        self.assertEqual(self.request(headers={'Authorization':'','Cookie':'xio_sid='+sid})[0],401)

    def test_methods_and_input_admission(self):
        cases = [dict(method='GET'),dict(method='HEAD'),dict(method='PUT'),dict(method='DELETE')]
        for case in cases: self.assertEqual(self.request(**case)[0],405)
        for raw in (b'[1]', b'{', b'{"x":NaN}', b'{"id":1,"id":2}'):
            self.assertEqual(self.request(raw=raw)[0],400)
        self.assertEqual(self.request(headers={'Content-Type':'text/plain'})[0],415)
        self.assertEqual(self.request(headers={'Content-Length':'-1'})[0],413)
        self.assertEqual(self.request(path='/api/user/add')[1]['errorCode'],'INVALID_REQUEST')
        self.assertEqual(self.commands, [])

    def test_rate_limit(self):
        for n in range(5):
            code = self.request(headers={'Authorization':'invalid'})[0]
        self.assertEqual(code,429); self.assertEqual(self.request()[0],429)
        self.assertEqual(self.commands, [])

if __name__ == '__main__':
    unittest.main()
