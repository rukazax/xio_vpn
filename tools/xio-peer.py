#!/usr/bin/env python3
"""Issue a static AmneziaWG profile for a device without the XIO client.

Routers (Jeton AX3000 Pro) and phones with the AmneziaVPN app cannot run the XIO
client, so they get one fixed AWG peer instead of the usual transport rotation:
no protocol switching and no readiness watchdog on the device side, only the
server-side counters. Run this on the server that terminates AWG.

Exit codes: 0 ok, 2 admin call failed, 3 wireguard tools missing, 4 invalid input.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ADMIN = '/usr/local/lib/xio-managed/admin.py'


def run(*args, stdin=None):
    return subprocess.run(args, input=stdin, text=True, capture_output=True)


def keypair():
    if not shutil.which('wg'):
        raise SystemExit('wireguard tools are required: wg genkey')
    private = run('wg', 'genkey')
    if private.returncode:
        raise SystemExit('wg genkey failed')
    private = private.stdout.strip()
    public = run('wg', 'pubkey', stdin=private + '\n')
    if public.returncode:
        raise SystemExit('wg pubkey failed')
    return private, public.stdout.strip()


def server_id():
    data = json.loads(Path('/etc/xio-managed/deployment.json').read_text())
    return data['id']


def add_peer(server, name, public, uid):
    request = {'action': 'add-awg', 'serverId': server, 'name': name,
               'publicKey': public, 'id': uid}
    result = run('python3', ADMIN, stdin=json.dumps(request))
    try:
        answer = json.loads(result.stdout)
    except ValueError:
        raise SystemExit('admin.py returned no JSON: ' + result.stdout[:200])
    if not answer.get('ok'):
        raise SystemExit('admin.py refused: ' + str(answer.get('error')))
    return answer


def finish(config, private):
    # The server never sees the client private key, so the placeholder is filled here.
    return config.replace('<client-private-key>', private)


def qr(path):
    if not shutil.which('qrencode'):
        return False
    result = run('qrencode', '-t', 'ansiutf8', '-r', path)
    if result.returncode == 0:
        sys.stdout.write(result.stdout)
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description='Issue a static AmneziaWG profile')
    parser.add_argument('name', help='device name, e.g. router-jeton or iphone')
    parser.add_argument('--out', default='')
    parser.add_argument('--qr', action='store_true', help='print a terminal QR code')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9 ._-]{1,80}', args.name):
        raise SystemExit('invalid name')
    private, public = keypair()
    uid = os.urandom(16).hex()
    answer = add_peer(server_id(), args.name, public, uid)
    config = finish(answer['config'], private)
    target = Path(args.out or ('/root/%s.conf' % re.sub(r'[^A-Za-z0-9._-]', '-', args.name)))
    target.write_text(config)
    target.chmod(0o600)
    print(json.dumps({'ok': True, 'conf': str(target), 'user': answer['user'],
                      'endpoint': [line for line in config.splitlines() if line.startswith('Endpoint')][0].split(' = ')[1]}))
    if args.qr:
        qr(str(target))
    return 0


if __name__ == '__main__':
    sys.exit(main())
