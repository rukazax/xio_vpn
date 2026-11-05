"""Real loopback TLS transport tests; never import token state on the live host."""
import importlib.util
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import time
import unittest


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix='xio-webui-test-')
        source = Path(__file__).with_name('xio-webui.py')
        copied = Path(cls.workspace.name) / source.name
        shutil.copyfile(source, copied)
        spec = importlib.util.spec_from_file_location('xio_webui_transport_test', copied)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        fixtures = source.resolve().parents[2] / 'app/test/fixtures/tls'
        cls.server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_tls.load_cert_chain(fixtures / 'localhost-cert.pem', fixtures / 'localhost-key.pem')
        cls.client_tls = ssl.create_default_context(cafile=str(fixtures / 'localhost-cert.pem'))

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        class FastServer(self.module.TLSServer):
            connection_limit = 2
            handshake_timeout = 3
            http_idle_timeout = 0.3
            request_deadline = 0.9
        self.server = FastServer(('127.0.0.1', 0), self.module.Handler, self.server_tls)
        self.clients = []
        self.worker = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.worker.start()

    def tearDown(self):
        for client in self.clients:
            client.close()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.assertFalse(self.worker.is_alive())
        self.wait_for(lambda: self.server._connection_slots._value == self.server.connection_limit)

    def wait_for(self, predicate, timeout=2):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() >= deadline:
                self.fail('transport worker did not reach the expected bounded state')
            time.sleep(0.01)

    def raw(self):
        client = socket.create_connection(self.server.server_address, timeout=2)
        self.clients.append(client)
        return client

    def tls(self):
        raw = self.raw()
        client = self.client_tls.wrap_socket(raw, server_hostname='localhost')
        client.settimeout(2)
        self.clients.append(client)
        return client

    def assert_health(self):
        client = self.tls()
        client.sendall(b'GET /api/health HTTP/1.0\r\nHost: localhost\r\n\r\n')
        body = b''
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            body += chunk
        self.assertIn(b'200 OK', body)
        self.assertIn(b'"ok": true', body)
        client.close()

    def test_stalled_tls_handshake_does_not_block_accept(self):
        self.raw()
        self.wait_for(lambda: self.server._connection_slots._value == 1)
        start = time.monotonic()
        self.assert_health()
        self.assertLess(time.monotonic() - start, 1.5)  # stalled handshake still has a 3 s budget

    def test_admission_limit_closes_excess_socket_and_recovers(self):
        first, second = self.raw(), self.raw()
        self.wait_for(lambda: self.server._connection_slots._value == 0)
        excess = self.raw()
        excess.settimeout(1)
        self.assertEqual(excess.recv(1), b'')
        first.close()
        second.close()
        self.wait_for(lambda: self.server._connection_slots._value == 2)
        self.assert_health()

    def test_tls_error_releases_admission_slot(self):
        client = self.raw()
        client.sendall(b'not a TLS request')
        try:
            while client.recv(1024):
                pass
        except ConnectionResetError:
            pass
        self.wait_for(lambda: self.server._connection_slots._value == 2)
        self.assert_health()

    def test_handshake_timeout_releases_admission_slot(self):
        self.server.handshake_timeout = 0.15
        client = self.raw()
        self.assertEqual(client.recv(1), b'')
        self.wait_for(lambda: self.server._connection_slots._value == 2)
        self.assert_health()

    def test_partial_headers_and_body_have_idle_timeout(self):
        for request in (
            b'GET /api/health HTTP/1.1\r\nHost: localhost\r\n',
            b'POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{',
        ):
            with self.subTest(request=request[:12]):
                client = self.tls()
                client.sendall(request)
                start = time.monotonic()
                try:
                    # Header timeouts may emit a bounded HTTP error before EOF.
                    while client.recv(4096):
                        pass
                except (ssl.SSLError, ConnectionResetError):
                    pass
                elapsed = time.monotonic() - start
                self.assertGreater(elapsed, 0.15)  # not a fast unrelated 4xx
                self.assertLess(elapsed, 1.5)
                self.wait_for(lambda: self.server._connection_slots._value == 2)

    def test_absolute_deadline_closes_trickled_headers(self):
        client = self.tls()
        client.sendall(b'GET /api/health HTTP/1.1\r\nHost: localhost\r\nX-Slow: ')
        stop = threading.Event()
        def trickle():
            while not stop.wait(0.08):
                try:
                    client.sendall(b'a')
                except OSError:
                    return
        sender = threading.Thread(target=trickle, daemon=True)
        start = time.monotonic()
        sender.start()
        try:
            while client.recv(4096):
                pass
        except (ssl.SSLError, ConnectionResetError):
            pass
        finally:
            stop.set()
            sender.join(timeout=1)
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 0.5)  # bytes kept the 0.3 s idle timer alive
        self.assertLess(elapsed, 1.8)
        self.assertFalse(sender.is_alive())
        self.wait_for(lambda: self.server._connection_slots._value == 2)
