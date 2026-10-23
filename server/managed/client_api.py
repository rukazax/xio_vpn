#!/usr/bin/env python3
"""Account-scoped HTTPS endpoint. No SSH/admin credential is returned to clients."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import threading
import os
import pwd
import shutil
import socketserver
import sys

PORT = 9444
PATH = '/v1/subclients'
LIMIT = 8192
UNIT = '/etc/systemd/system/xio-client-api.service'
BACKEND_UNIT = '/etc/systemd/system/xio-client-api-backend.service'
SERVICE_USER = 'xio-account-api'
TRANSPORT = Path('/etc/xio-account-api')
FRONTEND = Path('/usr/local/lib/xio-account-api')
SOCKET = '/run/xio-client-api.sock'


def firewall(admin, delete=False):
    for tool in ['iptables', 'ip6tables']:
        rule = ['INPUT', '-p', 'tcp', '--dport', str(PORT), '-m', 'comment',
                '--comment', 'xio-client-api-v1', '-j', 'ACCEPT']
        present = subprocess.run([tool, '-C', *rule], capture_output=True).returncode == 0
        if present and delete:
            admin.run(tool, '-D', *rule)
        elif not present and not delete:
            admin.run(tool, '-I', *rule)


def grant(admin, deployment, uid):
    user = deployment['users'].get(uid)
    assert user and not user.get('revoked') and user.get('role') == 'admin', 'Account not eligible'
    assert type(user.get('userLimit')) is int and 0 < user['userLimit'] <= 250, 'Account has no quota'
    directory = admin.ROOT / 'client-api'
    directory.mkdir(mode=0o700, exist_ok=True)
    certificate, key = directory / 'certificate.pem', directory / 'private.pem'
    if not certificate.exists() or not key.exists():
        admin.run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes',
                  '-days', '365', '-subj', '/CN=XIO account API',
                  '-keyout', str(key), '-out', str(certificate))
        key.chmod(0o600)
        certificate.chmod(0o600)
    assert subprocess.run(['openssl','x509','-checkend','0','-noout','-in',str(certificate)],capture_output=True).returncode==0, 'API certificate expired; owner renewal required'
    # Never pass the server's TLS private key, SSH key or administrative data.
    der = ssl.PEM_cert_to_DER_cert(certificate.read_text())
    token = secrets.token_hex(32)
    user['clientApiTokenHash'] = hashlib.sha256(token.encode()).hexdigest()
    admin.save(deployment)
    if not deployment.get('clientApiSystemUserOwned'):
        try:
            pwd.getpwnam(SERVICE_USER)
        except KeyError:
            shell = shutil.which('nologin')
            assert shell, 'nologin is required'
            admin.run('useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                      '--shell', shell, '--user-group', SERVICE_USER)
            deployment['clientApiSystemUserOwned'] = True
            admin.save(deployment)
        else:
            raise RuntimeError('API service username already exists; owner review required')
    account = pwd.getpwnam(SERVICE_USER)
    assert account.pw_uid != 0 and account.pw_shell.endswith('/nologin'), 'Invalid API service identity'
    TRANSPORT.mkdir(mode=0o750, exist_ok=True)
    os.chown(TRANSPORT, 0, account.pw_gid)
    TRANSPORT.chmod(0o750)
    for source in [certificate, key]:
        destination = TRANSPORT / source.name
        shutil.copyfile(source, destination)
        os.chown(destination, 0, account.pw_gid)
        destination.chmod(0o640)
    install_frontend()
    admin.write(BACKEND_UNIT, '[Unit]\nDescription=XIO bounded account dispatcher\n'
                '[Service]\nExecStart=/usr/bin/python3 /usr/local/lib/x1o-managed/client_api.py --backend\n'
                'Restart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n'
                '[Install]\nWantedBy=multi-user.target\n')
    admin.write(UNIT, '[Unit]\nDescription=XIO account HTTPS frontend\nAfter=network.target xio-client-api-backend.service\n'
                'Requires=xio-client-api-backend.service\n'
                '[Service]\nUser=xio-account-api\nGroup=xio-account-api\n'
                'ExecStart=/usr/bin/python3 /usr/local/lib/xio-account-api/frontend.py\n'
                'Restart=on-failure\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n'
                'ProtectSystem=strict\nProtectHome=true\nRestrictSUIDSGID=true\n'
                'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n'
                '[Install]\nWantedBy=multi-user.target\n')
    admin.run('systemctl', 'daemon-reload')
    admin.run('systemctl', 'enable', '--now', 'xio-client-api-backend.service', 'xio-client-api.service')
    admin.run('systemctl', 'restart', 'xio-client-api.service')
    admin.run('systemctl', 'is-active', 'xio-client-api.service')
    firewall(admin)
    host = deployment['host']
    if ':' in host:
        host = '[' + host + ']'
    return {'endpoint': f'https://{host}:{PORT}{PATH}', 'certificateSha256': hashlib.sha256(der).hexdigest(),
            'token': token, 'userId': uid, 'serverId': deployment['id']}


def install_frontend():
    # admin.py deliberately uses umask077. Public service code must still be
    # traversable by the separate unprivileged HTTPS service identity.
    FRONTEND.mkdir(mode=0o755, exist_ok=True)
    FRONTEND.chmod(0o755)
    shutil.copyfile(Path(__file__), FRONTEND / 'frontend.py')
    (FRONTEND / 'frontend.py').chmod(0o644)


def account_request(admin, envelope):
    """Called only inside admin.py's existing exclusive deployment lock."""
    assert set(envelope) == {'token', 'request'}, 'Invalid envelope'
    token = envelope['token']
    assert isinstance(token, str) and re.fullmatch('[a-f0-9]{64}', token), 'Access denied'
    deployment = admin.load()
    digest = hashlib.sha256(token.encode()).hexdigest()
    actor = next((uid for uid, user in deployment['users'].items()
                  if hmac.compare_digest(user.get('clientApiTokenHash', ''), digest)), None)
    assert actor, 'Access denied'
    req = envelope['request']
    assert isinstance(req, dict), 'Invalid request'
    action = req.get('action')
    assert action in ['status', 'add', 'revoke'], 'Operation not permitted'
    assert req.get('serverId') == deployment['id'], 'Server identity changed'
    admin.authority(deployment, actor, 'status', {})  # Revocation checked even for cached operations.
    if action == 'status':
        assert set(req) == {'action', 'serverId'}, 'Invalid request'
        children = [{'id': uid, 'name': user['name'], 'revoked': user.get('revoked', False)}
                    for uid, user in deployment['users'].items() if user.get('createdBy') == actor]
        limit = deployment['users'][actor]['userLimit']
        active = [child for child in children if not child['revoked']]
        revoked = [child for child in children if child['revoked']]
        used = len(active)
        visible = active + revoked[-20:]
        return {'userId': actor, 'serverId': deployment['id'], 'limit': limit,
                'used': used, 'remaining': max(0, limit - used), 'children': visible, 'historyTruncated': len(visible) < len(children)}
    if action == 'revoke':
        assert set(req) == {'action', 'serverId', 'id'}, 'Invalid request'
        return admin.dispatch(req, actor)
    assert set(req) == {'action', 'serverId', 'id', 'name', 'publicKeys', 'rivet'}, 'Invalid request'
    uid = req['id']
    assert isinstance(uid, str) and re.fullmatch('[a-f0-9]{32}', uid), 'Invalid user id'
    # A durable intent precedes effects; a lost response can retrieve the SAME
    # completed operation. A crash while pending never starts another creation.
    fingerprint = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
    operations = deployment.setdefault('clientApiOperations', {})
    opid = actor + ':' + uid
    previous = operations.get(opid)
    if previous:
        assert previous['requestSha256'] == fingerprint, 'Operation parameters changed'
        assert previous['state'] == 'complete', 'Operation outcome unknown; owner reconciliation required'
        child = deployment['users'].get(uid, {})
        assert child.get('createdBy') == actor and not child.get('revoked'), 'Client access revoked'
        return previous['response']
    admin.authority(deployment, actor, 'add', req)
    assert len(operations) < 10000, 'Operation history limit reached'
    operations[opid] = {'requestSha256': fingerprint, 'state': 'pending'}
    admin.save(deployment)
    result = admin.dispatch(dict(req, admin=False, userLimit=0), actor)
    # Whitelist the response. In particular, never serialise a deployment/user
    # dictionary, stored access hashes, adminAccess, SSH data or other accounts.
    response = {'user': {'id': uid, 'slot': result['user']['slot']},
                'server': {key: result['server'][key] for key in
                           ['id', 'host', 'publicKeys', 'awg', 'rivet'] if key in result['server']},
                'configs': result.get('configs', {})}
    deployment = admin.load()
    deployment['clientApiOperations'][opid].update(state='complete', response=response)
    admin.save(deployment)
    return response


class Handler(BaseHTTPRequestHandler):
    server_version = 'XIO'
    sys_version = ''
    def log_message(self, *args):
        pass  # Do not log tokens, requests, profiles or IP addresses.

    def do_POST(self):
        try:
            assert self.path == PATH and self.headers.get_content_type() == 'application/json'
            assert (self.headers.get_content_charset() or 'utf-8').lower() == 'utf-8'
            assert not self.headers.get('Transfer-Encoding')
            size = int(self.headers.get('Content-Length', '0'))
            assert 0 < size <= LIMIT
            auth = self.headers.get('Authorization', '')
            assert re.fullmatch('Bearer [a-f0-9]{64}', auth)
            self.connection.settimeout(10)
            payload = self.rfile.read(size)
            assert len(payload) == size
            request = json.loads(payload)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as backend:
                backend.settimeout(130)
                backend.connect(SOCKET)
                backend.sendall(json.dumps({'token': auth[7:], 'request': request}).encode())
                backend.shutdown(socket.SHUT_WR)
                answer = bytearray()
                while block := backend.recv(8192):
                    answer.extend(block)
                    assert len(answer) <= 200000
            data = json.loads(answer)
            raw = json.dumps(data).encode()
            self.send_response(200 if data.get('ok') else 403)
        except Exception:
            raw = b'{"ok":false,"error":"Account API request rejected"}'
            self.send_response(400)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(*args, **kwargs)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()
    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        # TLS handshake happens in a bounded worker, not the accept loop.
        return self.tls.wrap_socket(request, server_side=True, do_handshake_on_connect=False), address


class Backend(socketserver.UnixStreamServer):
    def server_bind(self):
        super().server_bind()
        account = pwd.getpwnam(SERVICE_USER)
        os.chown(SOCKET, 0, account.pw_gid)
        os.chmod(SOCKET, 0o660)


class BackendHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            raw = bytearray()
            while block := self.request.recv(8192):
                raw.extend(block)
                assert len(raw) <= 32768
            # This is the sole privileged operation. Auth, exact action allowlist,
            # quota and ownership are checked independently in admin.py's lock.
            result = subprocess.run(['/usr/bin/python3', '/usr/local/lib/x1o-managed/admin.py', '--client-api'],
                                    input=bytes(raw), capture_output=True, timeout=120)
            answer = result.stdout
            assert len(answer) <= 200000
            json.loads(answer)
        except Exception:
            answer = b'{"ok":false,"error":"Account dispatcher rejected request"}'
        self.request.sendall(answer)


def remove_transport(admin, deployment):
    for unit in ['xio-client-api.service', 'xio-client-api-backend.service']:
        subprocess.run(['systemctl', 'disable', '--now', unit], capture_output=True)
    firewall(admin, True)
    for name in [UNIT, BACKEND_UNIT]:
        Path(name).unlink(missing_ok=True)
    Path(SOCKET).unlink(missing_ok=True)
    shutil.rmtree(TRANSPORT, ignore_errors=True)
    shutil.rmtree(FRONTEND, ignore_errors=True)
    if deployment.get('clientApiSystemUserOwned'):
        admin.run('userdel', SERVICE_USER)


if __name__ == '__main__':
    if sys.argv[1:] == ['--backend']:
        Path(SOCKET).unlink(missing_ok=True)
        with Backend(SOCKET, BackendHandler) as backend:
            backend.serve_forever()
        sys.exit(0)
    assert not sys.argv[1:]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(TRANSPORT / 'certificate.pem', TRANSPORT / 'private.pem')
    class DualServer(Server):
        address_family = socket.AF_INET6
        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            super().server_bind()
    server = DualServer(('::', PORT), Handler)
    server.tls = tls
    server.serve_forever()
