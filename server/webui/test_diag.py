"""Diagnostic-log ingest API (/api/diag) over real Handler byte streams.

The harness mirrors test_webui.py/test_issuance_unit.py: the actual source is
copied into a temporary directory and imported there, so the token/diag files
created on import never touch the live installation. Requests are fed through
Handler.handle_one_request, so request parsing, status codes and response
headers are the real ones; only the TCP/TLS layer is skipped.
"""
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import types
import unittest

HEADER = 'X-XIO-Diag-Token'
DIR_MODE = 0o700
FILE_MODE = 0o600


def _load_module():
    workspace = tempfile.TemporaryDirectory(prefix='xio-webui-diag-')
    source = Path(__file__).with_name('xio-webui.py')
    copied = Path(workspace.name) / source.name
    shutil.copyfile(source, copied)
    spec = importlib.util.spec_from_file_location('xio_webui_diag_test', copied)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return workspace, module


class DiagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace, cls.module = _load_module()
        cls.saved = {name: getattr(cls.module, name) for name in
                     ('DIAG_DIR', 'DIAG_MAX_BYTES', 'DIAG_UPLOADS_PER_HOUR',
                      'DIAG_UPLOADS', 'DIAG_READY')}
        cls.token = cls.module.DIAG_TOKENS.token

    @classmethod
    def tearDownClass(cls):
        for name, value in cls.saved.items():
            setattr(cls.module, name, value)
        cls.workspace.cleanup()

    def setUp(self):
        # Свежий каталог и лимиты на каждый тест: состояние не протекает.
        self.dir = Path(tempfile.mkdtemp(prefix='diag-store-', dir=self.workspace.name))
        self.module.DIAG_DIR = self.dir
        self.module.DIAG_MAX_BYTES = 200 * 1024 * 1024
        self.module.DIAG_UPLOADS_PER_HOUR = 30
        self.module.DIAG_UPLOADS = self.module.DiagLimiter()
        self.assertTrue(self.module.ensure_diag_dir())

    # --- транспорт ---------------------------------------------------------

    def request(self, method='GET', path='/api/diag', headers=None, body=b''):
        fields = {'Host': 'fixture'}
        if body or method in ('POST', 'PUT'):
            fields['Content-Length'] = str(len(body))
        fields.update(headers or {})
        request = "%s %s HTTP/1.1\r\n" % (method, path)
        request += ''.join("%s: %s\r\n" % item for item in fields.items()) + "\r\n"
        handler = object.__new__(self.module.Handler)
        handler.rfile = io.BytesIO(request.encode() + body)
        handler.wfile = io.BytesIO()
        handler.client_address = ('127.0.0.1', 4321)
        handler.server = types.SimpleNamespace()
        handler.close_connection = True
        handler.handle_one_request()
        response = handler.wfile.getvalue()
        head, _, data = response.partition(b'\r\n\r\n')
        lines = head.split(b'\r\n')
        status = int(lines[0].split()[1])
        parsed = {}
        for line in lines[1:]:
            key, _, value = line.partition(b':')
            parsed[key.strip().lower().decode()] = value.strip().decode()
        return status, parsed, data

    def auth(self, **extra):
        headers = {HEADER: self.token}
        headers.update(extra)
        return headers

    def upload(self, body, ctype='application/gzip', headers=None):
        fields = self.auth(**({'Content-Type': ctype} if ctype else {}))
        fields.update(headers or {})
        return self.request('POST', '/api/diag', headers=fields, body=body)

    def ids(self, data):
        return [item['id'] for item in json.loads(data)]

    # --- токен -------------------------------------------------------------

    def test_diag_token_is_separate_0600_secret(self):
        path = self.module.DIAG_TOKEN_FILE
        self.assertTrue(path.exists())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), FILE_MODE)
        self.assertGreaterEqual(len(self.module.DIAG_TOKENS.token), 32)
        self.assertNotEqual(self.module.DIAG_TOKENS.token, self.module.TOKENS.token)

    def test_token_required_and_bearer_does_not_replace_it(self):
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request(headers={HEADER: 'wrong'})[0], 401)
        bearer = {'Authorization': 'Bearer ' + self.module.TOKENS.token}
        self.assertEqual(self.request(headers=bearer)[0], 401)
        self.assertEqual(self.request(headers=dict(bearer, **self.auth()))[0], 200)

    def test_gzip_upload_download_and_mode(self):
        payload = gzip.compress(b'{"log": "hello"}\n' * 100)
        code, _headers, data = self.upload(payload)
        self.assertEqual(code, 200, data)
        answer = json.loads(data)
        self.assertTrue(answer['ok'])
        name = answer['id']
        self.assertRegex(name, self.module.DIAG_ID_RE.pattern)
        stored = self.dir / name
        self.assertEqual(stored.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(stored.stat().st_mode), FILE_MODE)
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), DIR_MODE)

        code, headers, body = self.request('GET', '/api/diag/' + name, headers=self.auth())
        self.assertEqual(code, 200)
        self.assertEqual(headers['content-type'], 'application/gzip')
        self.assertEqual(headers['content-disposition'], 'attachment; filename="%s"' % name)
        self.assertEqual(body, payload)

        code, headers, body = self.request('HEAD', '/api/diag/' + name, headers=self.auth())
        self.assertEqual(code, 200)
        self.assertEqual(body, b'')
        self.assertEqual(headers['content-length'], str(len(payload)))

    def test_json_and_plain_are_stored_verbatim(self):
        for ctype, payload in (('application/json', b'{"a":1}'),
                               ('text/plain', b'line one\nline two\n')):
            with self.subTest(ctype=ctype):
                code, _headers, data = self.upload(payload, ctype=ctype)
                self.assertEqual(code, 200, data)
                name = json.loads(data)['id']
                self.assertEqual((self.dir / name).read_bytes(), payload)

    # --- отказы ------------------------------------------------------------

    def test_body_size_and_type_are_bounded(self):
        over = self.module.DIAG_MAX_BODY + 1
        code, _headers, _data = self.request(
            'POST', '/api/diag', headers=self.auth(**{'Content-Type': 'application/gzip',
                                                      'Content-Length': str(over)}))
        self.assertEqual(code, 413)
        code, _headers, _data = self.request(
            'POST', '/api/diag', headers=self.auth(**{'Content-Type': 'application/gzip',
                                                      'Content-Length': '0'}))
        self.assertEqual(code, 413)
        code, _headers, _data = self.request(
            'POST', '/api/diag', headers=self.auth(**{'Content-Type': 'application/gzip',
                                                      'Content-Length': 'nonsense'}))
        self.assertEqual(code, 413)

        payload = gzip.compress(b'x')
        self.assertEqual(self.upload(payload, ctype='application/x-www-form-urlencoded')[0], 415)
        self.assertEqual(self.upload(b'not gzip at all')[0], 400)
        self.assertEqual(self.upload(b'', ctype='application/gzip')[0], 413)
        self.assertEqual(self.upload(payload, headers={'Transfer-Encoding': 'chunked'})[0], 413)
        self.assertEqual(list(self.dir.iterdir()), [], 'rejected uploads must not leave files')

    def test_traversal_and_invalid_ids_are_rejected(self):
        outside = self.dir.parent / '00000000T000000-00000000.json.gz'
        outside.write_bytes(b'secret')
        for path in ('/api/diag/../../etc/passwd',
                     '/api/diag/..%2F..%2Fetc%2Fpasswd',
                     '/api/diag/..',
                     '/api/diag/',
                     '/api/diag/00000000T000000-00000000.json.gz/../../' + outside.name):
            with self.subTest(path=path):
                code, _headers, _data = self.request('GET', path, headers=self.auth())
                self.assertEqual(code, 400, path)
        # Соседний файл с валидным именем не читается: id разрешается только в DIAG_DIR.
        code, _headers, _data = self.request('GET', '/api/diag/' + outside.name,
                                             headers=self.auth())
        self.assertEqual(code, 404)
        self.assertEqual(outside.read_bytes(), b'secret')
        # Синтаксически верный, но отсутствующий id — 404, а не 400.
        code, _headers, _data = self.request(
            'GET', '/api/diag/20000101T000000-abcdef12.json.gz', headers=self.auth())
        self.assertEqual(code, 404)

    # --- список ------------------------------------------------------------

    def test_list_is_newest_first_with_size_and_mtime(self):
        uploaded = []
        for index in range(3):
            payload = gzip.compress(('payload-%d' % index).encode() * 10)
            code, _headers, data = self.upload(payload)
            self.assertEqual(code, 200)
            name = json.loads(data)['id']
            os.utime(str(self.dir / name), (1000 + index, 1000 + index))
            uploaded.append((name, len(payload)))
        code, _headers, data = self.request(headers=self.auth())
        self.assertEqual(code, 200)
        items = json.loads(data)
        self.assertEqual([item['id'] for item in items],
                         [name for name, _size in reversed(uploaded)])
        self.assertEqual([item['size'] for item in items],
                         [size for _name, size in reversed(uploaded)])
        self.assertEqual([item['mtime'] for item in items], [1002, 1001, 1000])
        for item in items:
            self.assertEqual(set(item), {'id', 'size', 'mtime'})

    def test_list_is_capped_at_fifty(self):
        self.module.DIAG_UPLOADS_PER_HOUR = 100
        names = []
        for index in range(55):
            payload = gzip.compress(b'entry-%03d' % index)
            code, _headers, data = self.upload(payload)
            self.assertEqual(code, 200)
            names.append(json.loads(data)['id'])
            os.utime(str(self.dir / names[-1]), (2000 + index,) * 2)
        code, _headers, data = self.request(headers=self.auth())
        self.assertEqual(code, 200)
        listed = [item['id'] for item in json.loads(data)]
        self.assertEqual(len(listed), 50)
        self.assertEqual(listed, list(reversed(names))[:50])

    # --- лимиты ------------------------------------------------------------

    def test_rate_limit_blocks_only_uploads(self):
        self.module.DIAG_UPLOADS_PER_HOUR = 2
        payload = gzip.compress(b'x')
        self.assertEqual(self.upload(payload)[0], 200)
        self.assertEqual(self.upload(payload)[0], 200)
        self.assertEqual(self.upload(payload)[0], 429)
        self.assertEqual(self.request(headers=self.auth())[0], 200)

    def test_disk_cap_prunes_oldest_uploads_first(self):
        names, sizes = [], {}
        for index, size in enumerate((4000, 3000)):
            payload = gzip.compress(os.urandom(size))
            code, _headers, data = self.upload(payload)
            self.assertEqual(code, 200)
            name = json.loads(data)['id']
            names.append(name)
            sizes[name] = len(payload)
            os.utime(str(self.dir / name), (1000 + index,) * 2)

        self.module.DIAG_MAX_BYTES = sizes[names[0]] + sizes[names[1]]
        payload = gzip.compress(os.urandom(2000))
        code, _headers, data = self.upload(payload)
        self.assertEqual(code, 200)
        newest = json.loads(data)['id']
        names.append(newest)
        sizes[newest] = len(payload)

        self.assertFalse((self.dir / names[0]).exists(), 'oldest upload must be pruned first')
        self.assertTrue((self.dir / names[1]).exists())
        self.assertTrue((self.dir / names[2]).exists())
        total = sum(path.stat().st_size for path in self.dir.iterdir())
        self.assertLessEqual(total, self.module.DIAG_MAX_BYTES)
        listed = self.ids(self.request(headers=self.auth())[2])
        self.assertEqual(listed, [newest, names[1]])

    def test_cap_below_one_bundle_keeps_the_accepted_file(self):
        self.module.DIAG_MAX_BYTES = 1
        code, _headers, data = self.upload(gzip.compress(b'only one'))
        self.assertEqual(code, 200)
        name = json.loads(data)['id']
        self.assertTrue((self.dir / name).exists(), 'the accepted upload is never deleted')

    def test_read_only_directory_disables_endpoint(self):
        blocker = self.dir.parent / 'not-a-directory'
        blocker.write_bytes(b'x')
        self.module.DIAG_DIR = blocker
        self.assertFalse(self.module.ensure_diag_dir())
        self.assertEqual(self.request(headers=self.auth())[0], 503)
        self.assertEqual(self.upload(gzip.compress(b'x'))[0], 503)
        self.module.DIAG_DIR = self.dir
        self.assertTrue(self.module.ensure_diag_dir())

    # --- маршрутизация -----------------------------------------------------

    def test_unknown_api_and_other_methods_stay_sane(self):
        self.assertEqual(self.request('GET', '/api/nope')[0], 404)
        self.assertEqual(self.request('GET', '/api/diagX', headers=self.auth())[0], 404)
        code, _headers, data = self.request('PUT', '/api/diag', headers=self.auth(), body=b'x')
        self.assertEqual(code, 405)
        self.assertFalse(json.loads(data)['ok'])
        name = json.loads(self.upload(gzip.compress(b'x'))[2])['id']
        self.assertEqual(self.request('DELETE', '/api/diag/' + name, headers=self.auth())[0], 405)
        self.assertTrue((self.dir / name).exists(), 'DELETE must not remove diagnostics')


if __name__ == '__main__':
    unittest.main()
