#!/usr/bin/env python3
"""Render container-only cascade config. Never applies host networking."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def literal(value):
    if not re.fullmatch(r'[0-9A-Fa-f:.]+', value):
        raise ValueError('expected a bare IP literal (no zone, URL, brackets or CIDR)')
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or getattr(address, 'ipv4_mapped', None):
        raise ValueError('unusable exit address')
    return str(address)


def key(value):
    try:
        if len(value) != 44 or len(base64.b64decode(value, validate=True)) != 32:
            raise ValueError()
    except Exception:
        raise ValueError('expected 32-byte base64 WireGuard public key') from None
    return value


def port(value):
    if not re.fullmatch('[0-9]{1,5}', value) or not 1 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError('port must be 1..65535')
    return int(value)


def atomic(path, content):
    # Only our own mkstemp file is removed; never remove caller-owned *.tmp.
    fd, name = tempfile.mkstemp(prefix='.cascade-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            out.write(content)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def wg(*args, stdin=None, image='xio-cascade:local'):
    cmd = ['wg']
    if not shutil.which('wg'):
        runtime = next((x for x in ('docker', 'podman') if shutil.which(x)), None)
        if not runtime:
            raise ValueError('wg or an existing container runtime is required; nothing is installed automatically')
        cmd = [runtime, 'run', '--rm', '-i', '--network', 'none', '--entrypoint', 'wg', image]
    return subprocess.check_output(cmd + list(args), input=stdin, text=True).strip()


def firewall(role, routing, ipv4_egress):
    common = '''#!/bin/sh
# Container network namespace ONLY. Fail closed on rendering/application errors.
set -eu
case "${1:-up}" in
 down) nft delete table inet xio_cascade 2>/dev/null || true
'''
    if role == 'bridge':
        common += ''' ip rule del priority 12000 fwmark 1 lookup 200 2>/dev/null || true
 ip -6 rule del priority 12001 from fd42:201::/64 lookup 201 2>/dev/null || true
 ip route flush table 200 2>/dev/null || true
 ip -6 route flush table 201 2>/dev/null || true
'''
    common += ''' exit 0;;
 up) ;;
 *) exit 2;;
esac
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv6.conf.all.forwarding=1
nft list table inet xio_cascade >/dev/null 2>&1 || nft add table inet xio_cascade
# Atomic replacement of our own table, never a global ruleset flush.
nft -f - <<'NFT'
flush table inet xio_cascade
table inet xio_cascade {
'''
    if role == 'bridge':
        mark = 'meta nfproto ipv4' if routing == 'all' else 'ip daddr @xio_whitelist4'
        direct = '' if routing == 'all' else '    iifname "wg1" meta nfproto ipv4 accept\n'
        nat = '' if routing == 'all' else '    ip saddr 10.202.0.0/24 oifname != "wg0" masquerade\n'
        common += f''' set xio_whitelist4 {{ type ipv4_addr; flags interval; auto-merge; }}
 chain prerouting {{ type filter hook prerouting priority mangle; policy accept;
    iifname "wg1" {mark} meta mark set 1
 }}
 chain forward {{ type filter hook forward priority filter; policy accept;
    iifname "wg1" oifname "wg0" accept
    iifname "wg0" oifname "wg1" ct state established,related accept
{direct}    oifname "wg1" ct state established,related accept
    iifname "wg1" drop
    oifname "wg1" drop
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
{nat} }}
}}
NFT
ip rule del priority 12000 fwmark 1 lookup 200 2>/dev/null || true
ip rule add priority 12000 fwmark 1 lookup 200
ip route replace default dev wg0 table 200
ip -6 rule del priority 12001 from fd42:201::/64 lookup 201 2>/dev/null || true
ip -6 rule add priority 12001 from fd42:201::/64 lookup 201
ip -6 route replace default dev wg0 table 201
'''
    else:
        ipv4 = ('    ip saddr { 10.201.0.0/24, 10.202.0.0/24 } oifname != "wg0" masquerade\n'
                if ipv4_egress else '')
        reject4 = '    iifname "wg0" meta nfproto ipv4 drop\n' if not ipv4_egress else ''
        common += f''' chain forward {{ type filter hook forward priority filter; policy accept;
{reject4}    iifname "wg0" accept
    oifname "wg0" ct state established,related accept
    oifname "wg0" drop
 }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
{ipv4}    ip6 saddr {{ fd42:200::/64, fd42:201::/64 }} oifname != "wg0" masquerade
 }}
}}
NFT
'''
    return common


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--validate-host', help=argparse.SUPPRESS)
    p.add_argument('--role', choices=['exit', 'bridge'])
    p.add_argument('--exit-family', choices=['ipv4', 'ipv6'], default='ipv6')
    p.add_argument('--routing', choices=['all', 'split'], default='split')
    p.add_argument('--exit-host', default='')
    p.add_argument('--exit-pubkey', default='')
    p.add_argument('--exit-fingerprint', default='')
    p.add_argument('--data-dir')
    p.add_argument('--port', type=port, default=9443)
    p.add_argument('--client-port', type=port, default=51820)
    p.add_argument('--web-port', type=port, default=8443, help='legacy metadata only; no web server is installed')
    p.add_argument('--psk-file', '--token-file', dest='psk_file')
    p.add_argument('--add-peer', default='')
    p.add_argument('--remove-peer', default='')
    p.add_argument('--allowed-ips', default='10.201.0.2/32,10.202.0.0/24,fd42:200::2/128,fd42:201::/64')
    p.add_argument('--add-client', default='')
    p.add_argument('--remove-client', default='')
    p.add_argument('--client-ip', default='')
    p.add_argument('--client-ip6', default='')
    p.add_argument('--image', default='xio-cascade:local')
    p.add_argument('--allow-ula', action='store_true', help='test-only: allow non-global local exit source address')
    p.add_argument('--dry-run', action='store_true')
    a = p.parse_args()
    if a.validate_host is not None:
        print('ipv' + str(ipaddress.ip_address(literal(a.validate_host)).version))
        return
    if not a.role:
        p.error('--role required')
    # All untrusted values checked BEFORE directory creation, key generation or runtime calls.
    for name in ('exit_pubkey', 'add_peer', 'remove_peer', 'add_client', 'remove_client'):
        if getattr(a, name):
            key(getattr(a, name))
    host = literal(a.exit_host) if a.exit_host else ''
    if a.role == 'bridge' and (not host or not a.exit_pubkey):
        raise ValueError('bridge requires --exit-host and --exit-pubkey')
    if a.role == 'bridge' and a.port == a.client_port:
        raise ValueError('tunnel/client ports must differ')
    if a.exit_fingerprint:
        expected = 'sha256:' + hashlib.sha256(f'xio-cascade-exit-v1|{host}|{a.port}|{a.exit_pubkey}'.encode()).hexdigest()
        if a.exit_fingerprint != expected:
            raise ValueError('exit fingerprint mismatch')
    allowed = ', '.join(str(ipaddress.ip_network(x.strip(), strict=True)) for x in a.allowed_ips.split(','))
    client_ips = []
    if a.add_client:
        addr = ipaddress.ip_address(a.client_ip)
        if addr not in ipaddress.ip_network('10.202.0.0/24') or int(str(addr).split('.')[-1]) not in range(2, 255):
            raise ValueError('client IPv4 must be 10.202.0.2..254')
        client_ips.append(f'{addr}/32')
        if a.client_ip6:
            addr6 = ipaddress.ip_address(a.client_ip6)
            if addr6 not in ipaddress.ip_network('fd42:201::/64') or addr6 == ipaddress.ip_address('fd42:201::1'):
                raise ValueError('client IPv6 must be in fd42:201::/64, not gateway')
            client_ips.append(f'{addr6}/128')
    psk = ''
    if a.psk_file:
        raw = Path(a.psk_file).read_bytes().replace(b'\r', b'').replace(b'\n', b'')
        if not raw:
            raise ValueError('empty PSK file')
        try:
            psk = key(raw.decode('ascii'))
        except (ValueError, UnicodeError):
            psk = base64.b64encode(hashlib.sha256(raw).digest()).decode()
    data = Path(a.data_dir or f'/var/lib/xio-cascade/{a.role}').resolve()
    # Paths are JSON encoded, never interpolated into generated shell commands.
    if data == Path('/') or any(c in str(data) for c in '\r\n\x00'):
        raise ValueError('invalid/root data path')
    address = ''
    if a.role == 'exit':
        version = '4' if a.exit_family == 'ipv4' else '6'
        target = '1.1.1.1' if version == '4' else '2606:4700:4700::1111'
        result = json.loads(subprocess.check_output(['ip', '-j', '-' + version, 'route', 'get', target], text=True))
        address = literal(result[0].get('prefsrc', result[0].get('src', '')))
        if ipaddress.ip_address(address).version != int(version):
            raise ValueError('wrong exit source family')
        if not a.allow_ula and not ipaddress.ip_address(address).is_global:
            raise ValueError('exit requires a global source address of selected family')
    ipv4_egress = False
    if a.role == 'exit':
        try:
            route4 = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'get', '1.1.1.1'], text=True, stderr=subprocess.DEVNULL))
            source4 = literal(route4[0].get('prefsrc', route4[0].get('src', '')))
            ipv4_egress = ipaddress.ip_address(source4).version == 4
        except (ValueError, KeyError, IndexError, subprocess.CalledProcessError):
            pass
        if a.exit_family == 'ipv4' and not ipv4_egress:
            raise ValueError('IPv4 exit requires an IPv4 egress route/source')
        if not ipv4_egress and a.routing == 'all':
            raise ValueError('all-IPv4 routing requested but exit has no IPv4 egress; NAT46/CLAT is not supplied')
        if not ipv4_egress:
            print('cascade-config: IPv6-only exit: IPv4 Internet UNSUPPORTED (no NAT46/CLAT); all-IPv4 clients must use an IPv4-capable exit', file=__import__('sys').stderr)
    state = dict(role=a.role, ipv4_egress=ipv4_egress, ipv4_egress_status='route detected, NOT Internet proof' if ipv4_egress else 'unsupported', exit_family=a.exit_family if a.role == 'exit' else 'ipv' + str(ipaddress.ip_address(host).version),
                 routing=a.routing, host=address if a.role == 'exit' else host, port=a.port,
                 data_dir=str(data), dry_run=a.dry_run, integration='standalone-wireguard; native XIO profiles NOT attached',
                 peering='manual two-way public-key registration required')
    if a.dry_run:
        print(json.dumps(state, indent=2))
        return
    if os.geteuid() != 0:
        raise ValueError('root required')
    os.umask(0o077)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(data, 0o700)
    registry = data / ('peers' if a.role == 'exit' else 'clients')
    registry.mkdir(exist_ok=True, mode=0o700)
    private = data / 'private.key'
    public = data / 'public.key'
    if private.exists():
        priv = key(private.read_text().strip())
        pub = key(wg('pubkey', stdin=priv + '\n', image=a.image))
    else:
        priv = key(wg('genkey', image=a.image))
        pub = key(wg('pubkey', stdin=priv + '\n', image=a.image))
        atomic(private, priv + '\n')
    atomic(public, pub + '\n')
    if psk:
        atomic(data / 'preshared.key', psk + '\n')
    elif (data / 'preshared.key').exists():
        psk = key((data / 'preshared.key').read_text().strip())
    add = a.add_peer if a.role == 'exit' else a.add_client
    remove = a.remove_peer if a.role == 'exit' else a.remove_client
    # Hash filenames: base64 public keys may contain '/' and must never become paths.
    record_path = lambda k: registry / (hashlib.sha256(k.encode()).hexdigest() + '.json')
    if add:
        atomic(record_path(add), json.dumps(dict(key=add, ips=allowed if a.role == 'exit' else ', '.join(client_ips))))
    if remove:
        record_path(remove).unlink(missing_ok=True)
    peers = []
    for path in sorted(registry.glob('*.json')):
        record = json.loads(path.read_text())
        key(record['key'])
        record['ips'] = ', '.join(str(ipaddress.ip_network(x.strip(), strict=True)) for x in record['ips'].split(','))
        peers.append(record)
    psk_line = f'PresharedKey = {psk}\n' if psk else ''
    tunnel = '10.201.0.1/24, fd42:200::1/64' if a.role == 'exit' else '10.201.0.2/24, fd42:200::2/64'
    config = f'[Interface]\nAddress = {tunnel}\nPrivateKey = {priv}\nMTU = 1280\n'
    config += f'PostUp = /bin/sh /data/nft-{a.role}.sh up\nPostDown = /bin/sh /data/nft-{a.role}.sh down\n'
    if a.role == 'bridge':
        endpoint = f'[{host}]:{a.port}' if ':' in host else f'{host}:{a.port}'
        config += f'Table = off\n\n[Peer]\nPublicKey = {a.exit_pubkey}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n{psk_line}'
        clients = f'[Interface]\nAddress = 10.202.0.1/24, fd42:201::1/64\nPrivateKey = {priv}\nListenPort = {a.client_port}\nMTU = 1280\nTable = off\n'
        for peer in peers:
            clients += f'\n[Peer]\nPublicKey = {peer["key"]}\nAllowedIPs = {peer["ips"]}\n{psk_line}'
        atomic(data / 'wg1.conf', clients)
    else:
        config += f'ListenPort = {a.port}\n'
        for peer in peers:
            config += f'\n[Peer]\nPublicKey = {peer["key"]}\nAllowedIPs = {peer["ips"]}\n{psk_line}'
    atomic(data / 'wg0.conf', config)
    atomic(data / f'nft-{a.role}.sh', firewall(a.role, a.routing, ipv4_egress))
    state.update(pubkey=pub, peers=len(peers), ipv4=address if a.role == 'exit' and a.exit_family == 'ipv4' else '',
                 ipv6=address if a.role == 'exit' and a.exit_family == 'ipv6' else '')
    if a.role == 'exit':
        state['fingerprint'] = 'sha256:' + hashlib.sha256(f'xio-cascade-exit-v1|{address}|{a.port}|{pub}'.encode()).hexdigest()
    atomic(data / 'state.json', json.dumps(state, indent=2) + '\n')
    print(json.dumps(state, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as exc:
        raise SystemExit(f'cascade-config: {exc}') from None
