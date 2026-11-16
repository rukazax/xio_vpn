#!/usr/bin/env python3
"""Private synthetic native L3 proof. Run ONLY via unshare --mount --net --fork.
Uses existing digest-pinned AWG runtime, never installs/fetches packages/binaries.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / 'server/managed/cascade_native.py'


def run(*cmd, stdin=None, check=True):
    p = subprocess.run(list(map(str, cmd)), input=stdin, text=True, capture_output=True, timeout=30)
    if check and p.returncode:
        # Config JSON/private keys are NEVER included in the raised command.
        raise RuntimeError('proof command failed: ' + ' '.join(map(str, cmd)) + '\n' + p.stdout + p.stderr)
    return p


def ns(name, *cmd, **kw): return run('ip', 'netns', 'exec', name, *cmd, **kw)


def api(name, action, data, root, check=True):
    return ns(name, 'python3', MODULE, action, '--root', root, stdin=json.dumps(data), check=check)


def link(left, right, a, b, addr4a, addr4b, addr6a, addr6b):
    run('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
    run('ip', 'link', 'set', a, 'netns', left); run('ip', 'link', 'set', b, 'netns', right)
    for node, dev, a4, a6 in [(left, a, addr4a, addr6a), (right, b, addr4b, addr6b)]:
        ns(node, 'ip', 'addr', 'add', a4, 'dev', dev)
        ns(node, 'ip', '-6', 'addr', 'add', a6, 'dev', dev, 'nodad')
        ns(node, 'ip', 'link', 'set', dev, 'up')


def ping(node, family, target, source=None, check=True):
    cmd = ['ping', '-4' if family == 'ipv4' else '-6', '-n', '-c', '2', '-W', '2']
    if source: cmd += ['-I', source]
    return ns(node, *cmd, target, check=check)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', default='/srv/archives/native-connector-20261105')
    a = p.parse_args()
    for kind in ('mnt', 'net'):
        if os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind):
            raise SystemExit('REFUSED: host namespace, use unshare --mount --net --fork')
    if any(i['ifname'] != 'lo' for i in json.loads(run('ip', '-j', 'link').stdout)):
        raise SystemExit('REFUSED: outer private namespace not empty')
    artifacts = Path(a.artifacts).resolve()
    if Path('/srv/archives') not in artifacts.parents: raise SystemExit('artifacts must be beneath /srv/archives')
    artifacts.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', '-o', 'mode=700', 'native-proof-run', '/run')
    targets = {'ipv4': '1.1.1.1', 'ipv6': '2606:4700:4700::1111'}
    results = []
    with tempfile.TemporaryDirectory(prefix='native-proof-', dir=artifacts) as temp:
        root = Path(temp)
        cases = [('userspace', 'ipv4', 'hop-snat', ['ipv4', 'ipv6']), ('userspace', 'ipv6', 'hop-snat', ['ipv4', 'ipv6']),
                 ('userspace', 'ipv4', 'preserve', ['ipv4', 'ipv6']), ('kernel', 'ipv4', 'hop-snat', ['ipv4', 'ipv6']),
                 ('userspace', 'ipv4', 'hop-snat', ['ipv4']), ('userspace', 'ipv6', 'hop-snat', ['ipv6'])]
        for backend, transport, mode, families in cases:
            label = backend + '-' + transport + '-' + mode + '-' + '-'.join(families)
            print('CASE ' + label, flush=True)
            for node in ('awg', 'rivet', 'bridge', 'exit', 'world'):
                run('ip', 'netns', 'add', node)
                ns(node, 'ip', 'link', 'set', 'lo', 'up')
            b_root, e_root = root / label / 'bridge', root / label / 'exit'
            try:
                link('awg', 'bridge', 'a0', 'xioawg0', '10.78.0.2/24', '10.78.0.1/24', 'fd78:1::2/64', 'fd78:1::1/64')
                link('rivet', 'bridge', 'r0', 'xiorivet', '10.79.0.2/24', '10.79.0.1/24', 'fd79:1::2/64', 'fd79:1::1/64')
                link('bridge', 'exit', 'b0', 'e0', '198.18.0.1/24', '198.18.0.2/24', 'fd00:be::1/64', 'fd00:be::2/64')
                link('exit', 'world', 'e1', 'w0', '198.19.0.1/24', '198.19.0.2/24', 'fd00:ee::1/64', 'fd00:ee::2/64')
                for node in ('bridge', 'exit'):
                    ns(node, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
                    ns(node, 'sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1')
                for node, gateway4, gateway6 in [('awg', '10.78.0.1', 'fd78:1::1'), ('rivet', '10.79.0.1', 'fd79:1::1'),
                                                ('bridge', '198.18.0.2', 'fd00:be::2'), ('exit', '198.19.0.2', 'fd00:ee::2')]:
                    ns(node, 'ip', 'route', 'add', 'default', 'via', gateway4)
                    ns(node, 'ip', '-6', 'route', 'add', 'default', 'via', gateway6)
                ns('world', 'ip', 'route', 'add', '198.18.0.0/24', 'via', '198.19.0.1')
                ns('world', 'ip', '-6', 'route', 'add', 'fd00:be::/64', 'via', 'fd00:ee::1')
                ns('world', 'ip', 'addr', 'add', targets['ipv4'] + '/32', 'dev', 'lo')
                ns('world', 'ip', '-6', 'addr', 'add', targets['ipv6'] + '/128', 'dev', 'lo', 'nodad')
                # A full XIO exit owns the same native prefixes: hop-snat MUST coexist.
                if mode == 'hop-snat':
                    ns('exit', 'ip', 'link', 'add', 'exitnative', 'type', 'dummy')
                    for addr in ('10.78.0.1/24', '10.79.0.1/24'): ns('exit', 'ip', 'addr', 'add', addr, 'dev', 'exitnative')
                    for addr in ('fd78:1::1/64', 'fd79:1::1/64'): ns('exit', 'ip', '-6', 'addr', 'add', addr, 'dev', 'exitnative', 'nodad')
                    ns('exit', 'ip', 'link', 'set', 'exitnative', 'up')
                # Existing native base NAT and direct accepts/drops, deliberately broad SNAT.
                for tool, prefix in [('iptables', '10.'), ('ip6tables', 'fd')]:
                    for iface, subnet in [('xioawg0', '10.78.0.0/24' if tool == 'iptables' else 'fd78:1::/64'),
                                          ('xiorivet', '10.79.0.0/24' if tool == 'iptables' else 'fd79:1::/64')]:
                        ns('bridge', tool, '-A', 'FORWARD', '-i', iface, '-o', 'b0', '-j', 'ACCEPT')
                        ns('bridge', tool, '-A', 'FORWARD', '-i', iface, '-j', 'DROP')
                        ns('bridge', tool, '-t', 'nat', '-A', 'POSTROUTING', '-s', subnet, '-j', 'MASQUERADE')
                private_b = ns('bridge', 'wg', 'genkey').stdout.strip()
                private_e = ns('exit', 'wg', 'genkey').stdout.strip()
                pub_b = run('wg', 'pubkey', stdin=private_b + '\n').stdout.strip()
                pub_e = run('wg', 'pubkey', stdin=private_e + '\n').stdout.strip()
                common = dict(enabled=True, ownerOptIn=True, backend=backend, sourceMode=mode, innerFamilies=families)
                exit_cfg = dict(common, role='exit', interface='xiocexit0', privateKey=private_e, listenPort=9443,
                                localAddresses={'ipv4': '10.203.0.1', 'ipv6': 'fd42:203::1'},
                                peerAddresses={'ipv4': '10.203.0.2', 'ipv6': 'fd42:203::2'}, peer={'publicKey': pub_b},
                                exitInterfaces={'ipv4': 'e1', 'ipv6': 'e1'})
                bridge_cfg = dict(common, role='bridge', interface='xiocbridge0', privateKey=private_b,
                                  localAddresses={'ipv4': '10.203.0.2', 'ipv6': 'fd42:203::2'},
                                  peerAddresses={'ipv4': '10.203.0.1', 'ipv6': 'fd42:203::1'},
                                  peer={'publicKey': pub_e, 'host': '198.18.0.2' if transport == 'ipv4' else 'fd00:be::2', 'port': 9443})
                api('exit', 'configure', exit_cfg, e_root)
                api('bridge', 'configure', bridge_cfg, b_root)
                for node in ('awg', 'rivet'):
                    for family, target in targets.items():
                        answer = ping(node, family, target, check=family in families)
                        if family in families:
                            assert '2 received' in answer.stdout, label + ' native packet loss'
                            print(node + ' ' + family + ' 2/2 via native ingress -> dedicated ' + backend + ' uplink -> exit', flush=True)
                        else:
                            assert answer.returncode != 0, 'UNREQUESTED native family leaked direct'
                            print(node + ' ' + family + ' blocked (unrequested family)', flush=True)
                # Active capability proofs are explicit; read-only profile hooks do not probe.
                caps = json.loads(api('bridge', 'verify', {'targets': targets}, b_root).stdout)
                assert all(caps[p][f] == (f in families) for p in ('awg', 'rivet') for f in ('ipv4', 'ipv6')), caps
                assert json.loads(api('exit', 'inspect', {}, e_root).stdout)['capabilities'] is None
                assert caps['observedAt'].endswith('Z') and caps['expiresAt'].endswith('Z')
                for family, src in [('ipv4', '198.18.0.1'), ('ipv6', 'fd00:be::1')]:
                    route = ns('bridge', 'ip', '-4' if family == 'ipv4' else '-6', 'route', 'get', targets[family], 'from', src).stdout
                    assert 'dev b0' in route and 'xiocbridge0' not in route, 'management was rerouted'
                    assert '2 received' in ping('bridge', family, targets[family], src).stdout
                # Remove all owned table routes and mangle guards; terminal iif rules alone
                # must prevent direct fallback even when a base native ACCEPT is first.
                for tool, flag in [('iptables', '-4'), ('ip6tables', '-6')]:
                    ns('bridge', 'ip', flag, 'route', 'flush', 'table', '20792')
                    for chain in ('XIO_CNP', 'XIO_CNK'): ns('bridge', tool, '-t', 'mangle', '-F', chain)
                    ns('bridge', tool, '-I', 'FORWARD', '1', '-i', 'xioawg0', '-o', 'b0', '-j', 'ACCEPT')
                for node in ('awg', 'rivet'):
                    for family, target in targets.items():
                        assert ping(node, family, target, check=False).returncode != 0, 'terminal policy fence leaked'
                failed = json.loads(api('bridge', 'inspect', {}, b_root).stdout)
                assert not failed['infrastructureReady'] and not failed['capabilities']['awg']['ipv4']
                api('bridge', 'reconcile', {}, b_root)
                chosen = families[0]
                assert '2 received' in ping('awg', chosen, targets[chosen]).stdout
                ns('bridge', 'ip', 'link', 'delete', 'xiocbridge0')
                for node in ('awg', 'rivet'):
                    for family, target in targets.items():
                        assert ping(node, family, target, check=False).returncode != 0, 'tunnel deletion leaked'
                assert json.loads(api('bridge', 'remove', {'confirmDirect': True}, b_root).stdout)['enabled'] is False
                assert json.loads(api('exit', 'remove', {'confirmDirect': True}, e_root).stdout)['enabled'] is False
                for tool in ('iptables', 'ip6tables'):
                    assert 'XIO_CN' not in ns('bridge', tool, '-t', 'mangle', '-S').stdout
                    assert 'XIO_CN' not in ns('bridge', tool, '-S').stdout
                    ns('bridge', tool, '-C', 'FORWARD', '-i', 'xioawg0', '-o', 'b0', '-j', 'ACCEPT')
                result = dict(backend=backend, transport=transport, sourceMode=mode, removeLeavesForeignRules=True,
                              requestedFamilies=families,
                              awgIpv4='2/2' if 'ipv4' in families else 'blocked', awgIpv6='2/2' if 'ipv6' in families else 'blocked',
                              rivetIpv4='2/2' if 'ipv4' in families else 'blocked', rivetIpv6='2/2' if 'ipv6' in families else 'blocked',
                              managementDirect=True, nativeCapabilitiesFresh=True, terminalPolicyNoFallthrough=True,
                              tunnelLossNoLeak=True, overlappingExitNativePrefixes=mode == 'hop-snat',
                              scope='private synthetic L3/netns ONLY; no anti-DPI app/public VPS acceptance')
                results.append(result); print(json.dumps(result), flush=True)
            finally:
                for node, data in [('bridge', b_root), ('exit', e_root)]:
                    if (data / 'state.json').exists(): api(node, 'remove', {'confirmDirect': True}, data, check=False)
                for node in ('awg', 'rivet', 'bridge', 'exit', 'world'):
                    pids = run('ip', 'netns', 'pids', node, check=False).stdout.split()
                    for pid in pids:
                        try: os.kill(int(pid), signal.SIGTERM)
                        except ProcessLookupError: pass
                    # Only PIDs enumerated from our freshly-owned private named netns.
                    for _ in range(20):
                        remaining = run('ip', 'netns', 'pids', node, check=False).stdout.split()
                        if not remaining: break
                        time.sleep(.05)
                    for pid in run('ip', 'netns', 'pids', node, check=False).stdout.split():
                        try: os.kill(int(pid), signal.SIGKILL)
                        except ProcessLookupError: pass
                    run('ip', 'netns', 'del', node, check=False)
    (artifacts / 'native-kernel-proof.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS all native L3 cases; private namespaces only', flush=True)


if __name__ == '__main__': main()
