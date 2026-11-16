#!/usr/bin/env python3
"""Synthetic kernel WireGuard/NAT proof. MUST run in private unshare -m -n.
No external interfaces, host routes, host firewall or services are used.
All artifacts go beneath /srv/archives (set --artifacts to a private child).
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / 'deploy' / 'cascade'


def run(*cmd, capture=False, check=True):
    return subprocess.run(list(map(str, cmd)), check=check, text=True,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE if capture else None)


def ns(name, *cmd, **kw):
    return run('ip', 'netns', 'exec', name, *cmd, **kw)


def link(left, right, a, b, net4a, net4b, net6a=None, net6b=None):
    run('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
    run('ip', 'link', 'set', a, 'netns', left)
    run('ip', 'link', 'set', b, 'netns', right)
    for name, dev, addr4, addr6 in [(left, a, net4a, net6a), (right, b, net4b, net6b)]:
        ns(name, 'ip', 'addr', 'add', addr4, 'dev', dev)
        if addr6: ns(name, 'ip', '-6', 'addr', 'add', addr6, 'dev', dev, 'nodad')
        ns(name, 'ip', 'link', 'set', dev, 'up')


def apply(name, path, iface):
    ns(name, 'ip', 'link', 'add', iface, 'type', 'wireguard')
    raw = path.read_text().splitlines()
    conf = []
    for line in raw:
        if line.startswith(('Address', 'PostUp', 'PostDown', 'MTU', 'Table')): continue
        conf.append(line)
    stripped = path.with_name(iface + '.setconf')
    stripped.write_text('\n'.join(conf) + '\n')
    stripped.chmod(0o600)
    ns(name, 'wg', 'setconf', iface, stripped)
    for line in raw:
        if line.startswith('Address = '):
            for address in line.partition('=')[2].strip().split(', '):
                args = ['ip', '-6' if ':' in address else '-4', 'addr', 'add', address, 'dev', iface]
                if ':' in address: args.append('nodad')
                ns(name, *args)
    ns(name, 'ip', 'link', 'set', iface, 'mtu', '1280', 'up')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', default='/srv/archives/cascade-backend-20261105')
    a = p.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root required inside private namespaces')
    for kind in ('net', 'mnt'):
        if os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind):
            raise SystemExit('REFUSED: use unshare --mount --net --fork; host namespace detected')
    # Refuse an unexpected existing network even in a non-init namespace.
    interfaces = json.loads(run('ip', '-j', 'link', 'show', capture=True).stdout)
    if any(x['ifname'] != 'lo' for x in interfaces):
        raise SystemExit('REFUSED: private namespace must contain only loopback')
    artifacts = Path(a.artifacts).resolve()
    if Path('/srv/archives') not in artifacts.parents:
        raise SystemExit('artifacts must be a child of /srv/archives')
    artifacts.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    run('mount', '--make-rprivate', '/')
    # Never create named-netns mountpoints on the host filesystem.
    run('mount', '-t', 'tmpfs', '-o', 'mode=700', 'xio-private-run', '/run')
    run('ip', 'link', 'set', 'lo', 'up')
    results = []
    with tempfile.TemporaryDirectory(prefix='packet-proof-', dir=artifacts) as temp:
        root = Path(temp)
        for family in ('ipv4', 'ipv6'):
            for name in ('client', 'bridge', 'exit', 'world'):
                run('ip', 'netns', 'add', name)
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
            try:
                link('client', 'bridge', 'c0', 'b0', '192.0.2.2/24', '192.0.2.1/24')
                link('bridge', 'exit', 'b1', 'e0', '198.18.0.1/24', '198.18.0.2/24', 'fd00:be::1/64', 'fd00:be::2/64')
                link('exit', 'world', 'e1', 'w0', '198.19.0.1/24', '198.19.0.2/24', 'fd00:ee::1/64', 'fd00:ee::2/64')
                ns('exit', 'ip', 'route', 'add', 'default', 'via', '198.19.0.2')
                ns('exit', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:ee::2')
                ns('bridge', 'ip', 'route', 'add', 'default', 'via', '198.18.0.2')
                ns('bridge', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:be::2')
                host = '198.18.0.2' if family == 'ipv4' else 'fd00:be::2'
                exit_data = root / family / 'exit'
                bridge_data = root / family / 'bridge'
                ns('exit', 'bash', DEPLOY / 'cascade-exit-setup.sh', '--data-dir', exit_data,
                   '--exit-family', family, '--allow-ula')
                exit_pub = json.loads((exit_data / 'state.json').read_text())['pubkey']
                client_key = ns('client', 'wg', 'genkey', capture=True).stdout.strip()
                keyfile = root / ('client-' + family + '.key')
                keyfile.write_text(client_key + '\n')
                keyfile.chmod(0o600)
                client_pub = run('sh', '-c', 'wg pubkey < "$1"', 'proof', keyfile, capture=True).stdout.strip()
                ns('bridge', 'bash', DEPLOY / 'cascade-bridge-setup.sh', '--data-dir', bridge_data,
                   '--exit-host', host, '--exit-pubkey', exit_pub, '--routing', 'all',
                   '--add-client', client_pub, '--client-ip', '10.202.0.10', '--client-ip6', 'fd42:201::10')
                bridge_pub = json.loads((bridge_data / 'state.json').read_text())['pubkey']
                ns('exit', 'bash', DEPLOY / 'cascade-exit-setup.sh', '--data-dir', exit_data,
                   '--exit-family', family, '--allow-ula', '--add-peer', bridge_pub)
                apply('exit', exit_data / 'wg0.conf', 'wg0')
                apply('bridge', bridge_data / 'wg0.conf', 'wg0')
                apply('bridge', bridge_data / 'wg1.conf', 'wg1')
                ns('exit', 'ip', 'route', 'add', '10.202.0.0/24', 'dev', 'wg0')
                ns('exit', 'ip', '-6', 'route', 'add', 'fd42:201::/64', 'dev', 'wg0')
                ns('exit', 'sh', exit_data / 'nft-exit.sh', 'up')
                ns('bridge', 'sh', bridge_data / 'nft-bridge.sh', 'up')
                ns('client', 'ip', 'link', 'add', 'wgc', 'type', 'wireguard')
                ns('client', 'wg', 'set', 'wgc', 'private-key', keyfile, 'peer', bridge_pub,
                   'endpoint', '192.0.2.1:51820', 'allowed-ips', '0.0.0.0/0,::/0', 'persistent-keepalive', '1')
                ns('client', 'ip', 'addr', 'add', '10.202.0.10/24', 'dev', 'wgc')
                ns('client', 'ip', '-6', 'addr', 'add', 'fd42:201::10/64', 'dev', 'wgc', 'nodad')
                ns('client', 'ip', 'link', 'set', 'wgc', 'mtu', '1280', 'up')
                ns('client', 'ip', 'route', 'add', '198.19.0.0/24', 'dev', 'wgc')
                ns('client', 'ip', '-6', 'route', 'add', 'fd00:ee::/64', 'dev', 'wgc')
                r4 = ns('client', 'ping', '-4', '-n', '-c', '3', '-W', '2', '198.19.0.2', capture=True)
                r6 = ns('client', 'ping', '-6', '-n', '-c', '3', '-W', '2', 'fd00:ee::2', capture=True)
                assert '3 received' in r4.stdout and '3 received' in r6.stdout, 'expected zero loss in synthetic proof'
                # world has NO route to client subnets: bidirectional success requires exit NAT44/66.
                routes = ns('world', 'ip', '-j', 'route', 'show', capture=True).stdout
                if '10.202' in routes: raise AssertionError('world unexpectedly has client route')
                handshakes = ns('bridge', 'wg', 'show', 'wg0', 'latest-handshakes', capture=True).stdout
                assert any(int(x.split()[1]) > 0 for x in handshakes.splitlines()), 'real handshake absent'
                nft4 = ns('exit', 'nft', 'list', 'table', 'inet', 'xio_cascade', capture=True).stdout
                assert 'masquerade' in nft4 and 'ip saddr' in nft4 and 'ip6 saddr' in nft4
                # Break the tunnel; an unmarked fallback route exists but all mode MUST NOT leak.
                ns('bridge', 'ip', 'link', 'del', 'wg0')
                blocked = ns('client', 'ping', '-4', '-n', '-c', '1', '-W', '1', '198.19.0.2', capture=True, check=False)
                assert blocked.returncode != 0, 'all-mode leaked directly after tunnel removal'
                results.append(dict(transport=family, kernel_wireguard_handshake=True, ipv4_nat44_ping='3/3',
                                    ipv6_nat66_ping='3/3', all_mode_no_direct_fallback=True,
                                    evidence_scope='private synthetic namespaces ONLY, not Internet/VPS/native app'))
                print(r4.stdout.strip(), flush=True)
                print(r6.stdout.strip(), flush=True)
                print(json.dumps(results[-1]), flush=True)
            finally:
                for name in ('client', 'bridge', 'exit', 'world'):
                    run('ip', 'netns', 'del', name, check=False)
    output = artifacts / 'kernel-proof.json'
    output.write_text(json.dumps(results, indent=2) + '\n')
    print('PASS: two underlay families, real kernel WG and synthetic NAT44/NAT66; host unchanged')


if __name__ == '__main__':
    main()
