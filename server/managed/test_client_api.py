import copy
import fcntl
import hashlib
import importlib.util
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('account_api', Path(__file__).with_name('client_api.py'))
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
spec = importlib.util.spec_from_file_location('managed_policy', Path(__file__).with_name('admin.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class FakeAdmin:
    authority = staticmethod(policy.authority)
    def __init__(self, root):
        self.root = Path(root)
        self.calls = 0
        self.save({'id': 'server', 'users': {
            'parent': {'role': 'admin', 'userLimit': 1, 'name': 'Parent',
                       'clientApiTokenHash': hashlib.sha256(('a' * 64).encode()).hexdigest()},
            'other': {'createdBy': 'somebody-else', 'name': 'Other'},
        }})
    def load(self):
        return json.loads((self.root / 'state').read_text())
    def save(self, value):
        (self.root / 'state').write_text(json.dumps(value))
    def dispatch(self, req, actor):
        self.calls += 1
        d = self.load()
        self.authority(d, actor, req['action'], req)
        if req['action'] == 'revoke':
            d['users'][req['id']]['revoked'] = True
            self.save(d)
            return {'revoked': req['id']}
        assert req['admin'] is False and req['userLimit'] == 0
        d['users'][req['id']] = {'name': req['name'], 'createdBy': actor, 'slot': 4}
        self.save(d)
        return {'user': {'id': req['id'], 'slot': 4, 'private': 'MUST_NOT_LEAK'},
                'server': {'id': 'server', 'host': 'example.org', 'publicKeys': {}, 'awg': {},
                           'rootPrivateKey': 'MUST_NOT_LEAK', 'users': d['users']}, 'configs': {}}
    def request(self, request, token='a' * 64):
        with (self.root / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            return api.account_request(self, {'token': token, 'request': request})


def create(uid='b' * 32):
    return {'action': 'add', 'serverId': 'server', 'id': uid, 'name': 'Child',
            'publicKeys': {}, 'rivet': {}}


class ClientApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.admin = FakeAdmin(self.temp.name)
    def test_wrong_token_revoked_role_and_unapproved_actions(self):
        for action in ['init', 'inspect', 'remove', 'client-grant', 'shell']:
            with self.assertRaises(AssertionError):
                self.admin.request({'action': action, 'serverId': 'server'})
        with self.assertRaises(AssertionError):
            self.admin.request({'action': 'status', 'serverId': 'server'}, token='f' * 64)
        d = self.admin.load()
        d['users']['parent']['revoked'] = True
        self.admin.save(d)
        with self.assertRaises(AssertionError):
            self.admin.request({'action': 'status', 'serverId': 'server'})
    def test_client_cannot_set_admin_or_quota(self):
        for key, value in [('admin', True), ('userLimit', 250), ('adminAccess', {})]:
            with self.assertRaises(AssertionError):
                self.admin.request(dict(create(), **{key: value}))
        self.assertEqual(self.admin.calls, 0)
    def test_live_quota_concurrent_create_and_exact_replay(self):
        def attempt(uid):
            try:
                return self.admin.request(create(uid))
            except AssertionError:
                return None
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(attempt, ['b' * 32, 'c' * 32]))
        self.assertEqual(sum(r is not None for r in results), 1)
        result = next(r for r in results if r is not None)
        uid = result['user']['id']
        self.assertEqual(self.admin.request(create(uid)), result)
        self.assertEqual(self.admin.calls, 1)
        self.assertNotIn('MUST_NOT_LEAK', json.dumps(result))
        self.assertNotIn('clientApiTokenHash', json.dumps(result))
        with self.assertRaises(AssertionError):
            self.admin.request(dict(create(uid), name='Changed'))
    def test_crash_pending_is_never_repeated_and_revoke_is_scoped(self):
        req = create()
        d = self.admin.load()
        d['clientApiOperations'] = {'parent:' + req['id']: {
            'state': 'pending', 'requestSha256': hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()}}
        self.admin.save(d)
        with self.assertRaisesRegex(AssertionError, 'outcome unknown'):
            self.admin.request(req)
        self.assertEqual(self.admin.calls, 0)
        with self.assertRaises(AssertionError):
            self.admin.request({'action': 'revoke', 'serverId': 'server', 'id': 'other'})
    def test_status_no_foreign_users_or_secrets_and_quota_released(self):
        self.admin.request(create())
        self.admin.request({'action': 'revoke', 'serverId': 'server', 'id': 'b' * 32})
        result = self.admin.request({'action': 'status', 'serverId': 'server'})
        self.assertEqual(result['remaining'], 1)
        self.assertEqual(result['used'], 0)
        self.assertEqual([r['id'] for r in result['children']], ['b' * 32])
        self.assertNotIn('clientApiTokenHash', json.dumps(result))
        self.admin.request(create('c' * 32))
    def test_cached_creation_does_not_restore_revoked_child(self):
        self.admin.request(create())
        self.admin.request({'action': 'revoke', 'serverId': 'server', 'id': 'b' * 32})
        with self.assertRaisesRegex(AssertionError, 'revoked'):
            self.admin.request(create())


if __name__ == '__main__':
    unittest.main()

class ClientTransportTests(unittest.TestCase):
    def test_json_charset_and_fixed_length_cross_the_unix_boundary(self):
        import http.client
        import socketserver
        import threading
        from http.server import HTTPServer
        from unittest.mock import patch
        captured = []
        class Dispatcher(socketserver.BaseRequestHandler):
            def handle(self):
                data = bytearray()
                while part := self.request.recv(8192):
                    data.extend(part)
                captured.append(json.loads(data))
                self.request.sendall(b'{"ok":true,"remaining":1}')
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'api.sock')
            with socketserver.UnixStreamServer(path, Dispatcher) as backend, HTTPServer(('127.0.0.1', 0), api.Handler) as frontend, patch.object(api, 'SOCKET', path):
                workers = [threading.Thread(target=s.serve_forever, daemon=True) for s in [backend, frontend]]
                for worker in workers:
                    worker.start()
                try:
                    connection = http.client.HTTPConnection(*frontend.server_address, timeout=5)
                    payload = json.dumps({'action': 'status', 'serverId': 'server'}).encode()
                    connection.request('POST', api.PATH, body=payload, headers={
                        'Content-Type': 'application/json; charset=utf-8',
                        'Authorization': 'Bearer ' + 'a' * 64})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertTrue(json.loads(response.read())['ok'])
                    connection.close()
                    self.assertEqual(captured, [{'token': 'a' * 64, 'request': json.loads(payload)}])
                    for headers in [{'Transfer-Encoding': 'chunked'}, {'Content-Length': '9000'}, {'Content-Type': 'text/plain'}]:
                        connection = http.client.HTTPConnection(*frontend.server_address, timeout=5)
                        connection.request('POST', api.PATH, body=payload, headers={
                            'Content-Type': 'application/json', 'Authorization': 'Bearer ' + 'a' * 64, **headers})
                        response = connection.getresponse()
                        self.assertEqual(response.status, 400)
                        response.read()
                        connection.close()
                    self.assertEqual(len(captured), 1)
                finally:
                    frontend.shutdown()
                    backend.shutdown()
                    for worker in workers:
                        worker.join(timeout=3)
