#!/usr/bin/env python3
"""Private late-ingress boot-guard packet proof; no systemd manager mutation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from prove_cascade_native import ROOT, MODULE, run, ns, api, link, ping

spec = importlib.util.spec_from_file_location('native_boot', MODULE)
n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', default='/srv/archives/native-lifecycle-20261105')
    a = p.parse_args()
    for kind in ('mnt', 'net'):
        if os.readlink('/proc/self/ns/' + kind) == os.readlink('/proc/1/ns/' + kind): raise SystemExit('REFUSED host namespace')
    if any(x['ifname'] != 'lo' for x in json.loads(run('ip', '-j', 'link').stdout)): raise SystemExit('REFUSED nonempty outer netns')
    artifacts = Path(a.artifacts).resolve()
    if Path('/srv/archives') not in artifacts.parents: raise SystemExit('artifacts must be under /srv/archives')
    artifacts.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', '-o', 'mode=700', 'native-boot-run', '/run')
    targets = {'ipv4': '1.1.1.1', 'ipv6': '2606:4700:4700::1111'}
    results = []
    with tempfile.TemporaryDirectory(prefix='boot-proof-', dir=artifacts) as temp:
        for backend in ('userspace', 'kernel'):
            print('EARLY GUARD ' + backend + ' before any native ingress interface exists', flush=True)
            root = Path(temp) / backend; root.mkdir(mode=0o700)
            for node in ('bridge', 'world', 'awg', 'rivet'):
                run('ip', 'netns', 'add', node); ns(node, 'ip', 'link', 'set', 'lo', 'up')
            try:
                link('bridge', 'world', 'b0', 'w0', '198.18.0.1/24', '198.18.0.2/24', 'fd00:be::1/64', 'fd00:be::2/64')
                ns('bridge', 'ip', 'route', 'add', 'default', 'via', '198.18.0.2')
                ns('bridge', 'ip', '-6', 'route', 'add', 'default', 'via', 'fd00:be::2')
                ns('bridge', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
                ns('bridge', 'sysctl', '-qw', 'net.ipv6.conf.all.forwarding=1')
                for family, target in targets.items():
                    ns('world', 'ip', '-4' if family == 'ipv4' else '-6', 'addr', 'add', target + ('/32' if family == 'ipv4' else '/128'), 'dev', 'lo')
                private = run('wg', 'genkey').stdout.strip()
                peer = run('wg', 'pubkey', stdin=run('wg', 'genkey').stdout).stdout.strip()
                c = n.validate_config(dict(enabled=True, ownerOptIn=True, role='bridge', backend=backend, sourceMode='hop-snat',
                    interface='xiocboot0', innerFamilies=['ipv4', 'ipv6'],
                    localAddresses={'ipv4': '10.203.0.2', 'ipv6': 'fd42:203::2'},
                    peerAddresses={'ipv4': '10.203.0.1', 'ipv6': 'fd42:203::1'}, peer={'host': '198.18.0.2', 'port': 9443, 'publicKey': peer}))
                # Durable opt-in from the previous epoch; this fresh namespace has no rules,
                # process or native interfaces. Production helper/unit graph is tested separately.
                state = dict(owner=n.OWNER, schema=1, enabled=True, connectorId='boot-proof-' + backend, revision=1,
                             config=c, configHash=n.digest(c), phase='applied', proofs={})
                n.atomic(root / 'private.key', private + '\n'); n.save(root, state)
                assert ns('bridge', 'ip', 'link', 'show', 'dev', 'xioawg0', check=False).returncode != 0
                assert ns('bridge', 'ip', 'link', 'show', 'dev', 'xiorivet', check=False).returncode != 0
                # No JSON stdin: same safe action as the generated boot unit.
                guarded = json.loads(ns('bridge', 'python3', MODULE, 'guard-auto', '--root', root, stdin='').stdout)
                assert guarded['guarded'] is True
                for proto, interface, a4, a6 in [('awg', 'xioawg0', '10.78', 'fd78:1'), ('rivet', 'xiorivet', '10.79', 'fd79:1')]:
                    link(proto, 'bridge', proto[0] + '0', interface, a4 + '.0.2/24', a4 + '.0.1/24', a6 + '::2/64', a6 + '::1/64')
                    ns(proto, 'ip', 'route', 'add', 'default', 'via', a4 + '.0.1')
                    ns(proto, 'ip', '-6', 'route', 'add', 'default', 'via', a6 + '::1')
                    for tool, subnet in [('iptables', a4 + '.0.0/24'), ('ip6tables', a6 + '::/64')]:
                        ns('bridge', tool, '-I', 'FORWARD', '1', '-i', interface, '-o', 'b0', '-j', 'ACCEPT')
                        ns('bridge', tool, '-t', 'nat', '-A', 'POSTROUTING', '-s', subnet, '-j', 'MASQUERADE')
                for proto in ('awg', 'rivet'):
                    for family, target in targets.items():
                        assert ping(proto, family, target, check=False).returncode != 0, 'late interface boot leaked direct'
                # Even loss of tunnel/table/mangle leaves terminal rules bound to interfaces
                # that were absent when the boot guard ran.
                ns('bridge', 'ip', 'link', 'delete', 'xiocboot0')
                for tool, flag in [('iptables', '-4'), ('ip6tables', '-6')]:
                    ns('bridge', 'ip', flag, 'route', 'flush', 'table', str(n.TABLE))
                    for chain in ('XIO_CNP', 'XIO_CNK'): ns('bridge', tool, '-t', 'mangle', '-F', chain)
                for proto in ('awg', 'rivet'):
                    for family, target in targets.items():
                        assert ping(proto, family, target, check=False).returncode != 0, 'late-bound iif fence did not survive'
                for family, source in [('ipv4', '198.18.0.1'), ('ipv6', 'fd00:be::1')]:
                    assert '2 received' in ping('bridge', family, targets[family], source).stdout
                api('bridge', 'remove', {'confirmDirect': True}, root)
                for proto in ('awg', 'rivet'):
                    for family, target in targets.items():
                        assert '2 received' in ping(proto, family, target).stdout, 'positive direct-network control failed'
                result = dict(backend=backend, guardBeforeAnyIngress=True, lateAwgIpv4Blocked=True, lateAwgIpv6Blocked=True,
                              lateRivetIpv4Blocked=True, lateRivetIpv6Blocked=True, lateIifTerminalFenceSurvives=True,
                              managementDirect=True, explicitRemoveRestoresDirect=True,
                              scope='actual private packet guard + separate mocked systemd dependency ordering, NOT real host reboot')
                print(json.dumps(result), flush=True); results.append(result)
            finally:
                for node in ('bridge', 'world', 'awg', 'rivet'):
                    for pid in run('ip', 'netns', 'pids', node, check=False).stdout.split():
                        try: os.kill(int(pid), signal.SIGTERM)
                        except ProcessLookupError: pass
                    time.sleep(.05)
                    for pid in run('ip', 'netns', 'pids', node, check=False).stdout.split():
                        try: os.kill(int(pid), signal.SIGKILL)
                        except ProcessLookupError: pass
                    run('ip', 'netns', 'del', node, check=False)
    (artifacts / 'boot-packet-proof.json').write_text(json.dumps(results, indent=2) + '\n')
    print('PASS early guards with late native interfaces; no host systemd mutation', flush=True)


if __name__ == '__main__': main()
