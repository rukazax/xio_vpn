#!/usr/bin/env python3
"""Isolated config/bootstrap tests. All network/runtime/key tools are local mocks."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / 'deploy' / 'cascade'
spec = importlib.util.spec_from_file_location('payload', ROOT / 'tools' / 'cascade_payload.py')
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)
KEY = '/' * 43 + '='  # Valid base64 containing '/' must NEVER be used as a filename.
MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['MOCK_EVENTS'], 'a') as out: out.write(json.dumps([name] + args) + '\n')
if name == 'ip':
    import ipaddress
    if 'get' in args: ipaddress.ip_address(args[args.index('get') + 1])
    family = '4' if '-4' in args else '6'
    if family == '4' and os.environ.get('MOCK_NO_IPV4'): sys.exit(2)
    print(json.dumps([{'prefsrc': '8.8.4.4' if family == '4' else '2001:4860:4860::8844'}]))
elif name == 'wg':
    print('/' * 43 + '=')
elif name in ('docker', 'podman'):
    if os.environ.get('MOCK_HEALTH'):
        import time
        if args[0] == 'inspect': print('true')
        elif args[0] == 'exec':
            cmd = args[2:]
            if cmd == ['wg', 'show', 'interfaces']: print('wg0 wg1')
            elif cmd[-1] == 'peers': print('/' * 43 + '=')
            elif cmd[-1] == 'latest-handshakes': print('/' * 43 + '= ' + str(int(time.time())))
            elif cmd[0] == 'curl': print('8.8.8.8' if '-4' in cmd else '2001:4860:4860::8888')
            else: print('mock route/set elements')
        sys.exit(0)
    if args[:2] in (['network', 'inspect'], ['container', 'inspect']): sys.exit(1)
    print('mock-only')
elif name == 'curl':
    dest = pathlib.Path(args[args.index('--output') + 1])
    if os.environ.get('MOCK_REPLACE_TEMP'):
        parent = dest.parent
        parent.rename(str(parent) + '.retained')
        parent.symlink_to(os.environ['MOCK_REPLACE_TEMP'], target_is_directory=True)
        sys.exit(22)
    shutil.copyfile(os.environ['MOCK_BUNDLE'], dest)
'''


class CascadeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cascade-tests-')
        self.root = Path(self.temp.name)
        self.bin = self.root / 'mock bin'
        self.bin.mkdir()
        for name in ('ip', 'wg', 'docker', 'podman', 'curl'):
            target = self.bin / name
            target.write_text(MOCK)
            target.chmod(0o700)
        self.events = self.root / 'events.jsonl'
        self.tmp = self.root / 'private tmp'
        self.tmp.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + ':' + os.environ['PATH'],
                        MOCK_EVENTS=str(self.events), TMPDIR=str(self.tmp))
        self.data = self.root / 'persistent data with spaces'
        self.bundle, self.release = payload.build(ROOT)
        self.archive = self.root / 'bundle.tar.gz'
        self.archive.write_bytes(self.bundle)
        self.env['MOCK_BUNDLE'] = str(self.archive)

    def tearDown(self):
        self.temp.cleanup()

    def run_script(self, script, *args, success=True):
        r = subprocess.run(['bash', str(DEPLOY / script), *map(str, args)], env=self.env,
                           capture_output=True, text=True)
        if success:
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        else:
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def logs(self):
        return [json.loads(x) for x in self.events.read_text().splitlines()] if self.events.exists() else []

    def bridge(self, host='203.0.113.7', routing='all', *extra):
        return self.run_script('cascade-bridge-setup.sh', '--exit-host', host, '--exit-pubkey', KEY,
                               '--routing', routing, '--data-dir', self.data, *extra)

    def bootstrap(self, *args, success=True):
        return self.run_script('terminal-install.sh', '--bundle-url', 'https://example.invalid/payload.tar.gz',
                               '--sha256', hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                               '--data-dir', self.data, '--unattended', '--', *args, success=success)

    def mutate(self, action):
        with tarfile.open(fileobj=io.BytesIO(self.bundle), mode='r:gz') as tar:
            records = [(m, tar.extractfile(m).read()) for m in tar.getmembers()]
        records = action(records)
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as tar:
            for member, content in records:
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        self.archive.write_bytes(out.getvalue())

    def test_deterministic_complete_payload(self):
        self.assertEqual(payload.build(ROOT), (self.bundle, self.release))
        release = json.loads(self.release)
        self.assertEqual(release['sha256'], hashlib.sha256(self.bundle).hexdigest())
        with tarfile.open(fileobj=io.BytesIO(self.bundle), mode='r:gz') as tar:
            self.assertEqual(set(tar.getnames()), set(payload.FILES) | {'manifest.json'})
            for member in tar.getmembers():
                self.assertEqual(member.mtime, 0)
                self.assertEqual(member.uid, 0)
                self.assertTrue(member.isfile())
                if member.name != 'manifest.json':
                    self.assertEqual(tar.extractfile(member).read(), (DEPLOY / member.name).read_bytes())

    def test_bash_syntax(self):
        for path in DEPLOY.glob('*.sh'):
            r = subprocess.run(['bash', '-n', str(path)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, str(path) + r.stderr)

    def test_reject_bad_literals_before_side_effects(self):
        for host in ('1.2.3.999', '1.2.3', '010.1.2.3', 'https://[::1]', '[2001:db8::1]',
                     'fe80::1%eth0', '1.2.3.4/24', '2001:::1', '::', '::1', 'ff02::1',
                     '::ffff:192.0.2.1', '203.0.113.1;touch /tmp/evil', '2001:db8::1\nPostUp = evil'):
            with self.subTest(host=host):
                self.run_script('cascade-bridge-setup.sh', '--exit-host', host, '--exit-pubkey', KEY,
                                '--data-dir', self.data, success=False)
                self.run_script('cascade-install.sh', '--role', 'bridge', '--exit-host', host,
                                '--exit-pubkey', KEY, '--data-dir', self.data, success=False)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.logs(), [])

    def test_invalid_controls_and_root_paths_fail_before_mutation(self):
        for controls in [('--port', '0'), ('--routing', 'bogus'), ('--exit-family', 'bogus'),
                         ('--peer-pubkey', 'bad\nkey'), ('--data-dir', '/tmp/..')]:
            self.run_script('cascade-install.sh', '--role', 'bridge', '--exit-host', '203.0.113.7',
                            '--exit-pubkey', KEY, '--data-dir', self.data, *controls, success=False)
        self.run_script('cascade-exit-setup.sh', '--data-dir', self.data, '--add-peer', 'bad/key', success=False)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.logs(), [])

    def test_render_endpoint_both_families(self):
        for host, expected in [('203.0.113.7', '203.0.113.7:9443'), ('2001:db8::7', '[2001:db8::7]:9443')]:
            self.bridge(host)
            conf = (self.data / 'wg0.conf').read_text()
            self.assertIn('Endpoint = ' + expected, conf)
            self.assertIn('fd42:200::2/64', conf)
            self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', conf)

    def test_all_and_split_routing(self):
        self.bridge(routing='all')
        fw = (self.data / 'nft-bridge.sh').read_text()
        self.assertIn('iifname "wg1" meta nfproto ipv4 meta mark set 1', fw)
        self.assertNotIn('oifname != "wg0" masquerade', fw)
        self.assertIn('iifname "wg1" drop', fw)
        self.assertIn('ip -6 route replace default dev wg0 table 201', fw)
        self.bridge(routing='split')
        fw = (self.data / 'nft-bridge.sh').read_text()
        self.assertIn('ip daddr @xio_whitelist4 meta mark set 1', fw)
        self.assertIn('oifname != "wg0" masquerade', fw)

    def test_exit_nat44_dualstack_and_ipv6_only(self):
        for family in ('ipv4', 'ipv6'):
            self.run_script('cascade-exit-setup.sh', '--exit-family', family, '--data-dir', self.data, '--add-peer', KEY)
            fw = (self.data / 'nft-exit.sh').read_text()
            self.assertIn('ip saddr { 10.201.0.0/24, 10.202.0.0/24 }', fw)
            self.assertIn('ip6 saddr { fd42:200::/64, fd42:201::/64 }', fw)
            self.assertNotIn('snat ip6', fw)
            conf = (self.data / 'wg0.conf').read_text()
            self.assertIn('10.202.0.0/24, fd42:200::2/128, fd42:201::/64', conf)
        self.env['MOCK_NO_IPV4'] = '1'
        r = self.run_script('cascade-exit-setup.sh', '--exit-family', 'ipv6', '--data-dir', self.data)
        self.assertIn('IPv4 Internet UNSUPPORTED', r.stderr)
        fw = (self.data / 'nft-exit.sh').read_text()
        self.assertNotIn('ip saddr {', fw)
        self.assertIn('meta nfproto ipv4 drop', fw)
        self.assertFalse(json.loads((self.data / 'state.json').read_text())['ipv4_egress'])
        self.run_script('cascade-exit-setup.sh', '--exit-family', 'ipv4', '--data-dir', self.root / 'bad', success=False)
        self.assertFalse((self.root / 'bad').exists())
        self.run_script('cascade-exit-setup.sh', '--exit-family', 'ipv6', '--routing', 'all', '--data-dir', self.root / 'no-egress', success=False)
        self.assertFalse((self.root / 'no-egress').exists())

    def test_psk_and_peer_paths_and_owned_cleanup(self):
        self.data.mkdir()
        old_tmp = self.data / 'wg0.conf.tmp'
        old_tmp.write_text('caller owned')
        token = self.root / 'secret file with spaces'
        token.write_bytes(b'test token\r\n')
        self.bridge('203.0.113.7', 'all', '--token-file', token, '--add-client', KEY,
                    '--client-ip', '10.202.0.10', '--client-ip6', 'fd42:201::10')
        self.assertIn('AllowedIPs = 10.202.0.10/32, fd42:201::10/128', (self.data / 'wg1.conf').read_text())
        self.assertEqual(len(list((self.data / 'clients').glob('*.json'))), 1)
        self.assertEqual(old_tmp.read_text(), 'caller owned')
        self.assertEqual((self.data / 'wg0.conf').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('test token', json.dumps(self.logs()))
        self.bridge('203.0.113.7', 'all', '--remove-client', KEY)
        self.assertEqual(list((self.data / 'clients').glob('*.json')), [])

    def test_pin_mismatch_no_mutation(self):
        self.run_script('cascade-bridge-setup.sh', '--exit-host', '203.0.113.7', '--exit-pubkey', KEY,
                        '--exit-fingerprint', 'sha256:' + '0' * 64, '--data-dir', self.data, success=False)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.logs(), [])

    def test_bootstrap_success_argv_persistence_and_cleanup(self):
        token = self.root / 'secret with spaces'
        token.write_text('test-only')
        sentinel = self.tmp / 'caller-sentinel'
        sentinel.write_text('keep')
        self.bootstrap('--role', 'bridge', '--exit-host', '203.0.113.7', '--exit-pubkey', KEY,
                       '--token-file', token, '--routing', 'all')
        self.assertTrue((self.data / 'bridge' / 'wg0.conf').exists())
        self.assertTrue((self.data / 'payload' / 'cascade-config.py').exists())
        self.assertEqual(list(self.tmp.iterdir()), [sentinel])
        commands = self.logs()
        self.assertTrue(any(x[:3] == ['docker', 'network', 'create'] and '--ipv6' in x for x in commands))
        self.assertTrue(any(x[:2] == ['docker', 'run'] and str(self.data / 'bridge') + ':/data' in x for x in commands))
        self.assertFalse(any('8443:8443/tcp' in x for x in commands))
        curl = next(x for x in commands if x[0] == 'curl')
        self.assertEqual(curl[curl.index('--proto-redir') + 1], '=https')

    def test_both_real_two_way_registration(self):
        self.run_script('cascade-install.sh', '--role', 'both', '--exit-family', 'ipv4',
                        '--exit-host', '203.0.113.7', '--routing', 'all', '--data-dir', self.data)
        self.assertIn('PublicKey = ' + KEY, (self.data / 'exit' / 'wg0.conf').read_text())
        self.assertIn('PublicKey = ' + KEY, (self.data / 'bridge' / 'wg0.conf').read_text())
        self.assertIn('fd42:201::/64', (self.data / 'exit' / 'wg0.conf').read_text())

    def test_bootstrap_hash_mismatch_no_exec(self):
        self.archive.write_bytes(self.bundle + b'tampered')
        self.run_script('terminal-install.sh', '--bundle-url', 'https://example.invalid/payload',
                        '--sha256', hashlib.sha256(self.bundle).hexdigest(), '--data-dir', self.data,
                        '--unattended', '--', '--role', 'exit', success=False)
        self.assertEqual([x[0] for x in self.logs()], ['curl'])
        self.assertFalse(self.data.exists())
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_bootstrap_missing_or_tampered_dependency_no_exec(self):
        for variant in ('missing', 'tampered', 'symlink', 'duplicate', 'oversize'):
            def change(records):
                if variant == 'missing': return [(m, b) for m, b in records if m.name != 'entrypoint.sh']
                if variant == 'duplicate': return records + [records[0]]
                for m, b in records:
                    if m.name == 'entrypoint.sh':
                        if variant == 'symlink': m.type = tarfile.SYMTYPE; m.linkname = '/etc/passwd'
                        elif variant == 'oversize': b = b'a' * 2097153
                        else: b += b'\ntouch /tmp/NEVER_EXECUTE\n'
                    yield m, b
            # Avoid mixing generator return semantics for missing/duplicate cases.
            def mutate(records):
                if variant == 'missing': return [(m, b) for m, b in records if m.name != 'entrypoint.sh']
                if variant == 'duplicate': return records + [records[0]]
                return list(change(records))
            with self.subTest(variant=variant):
                self.mutate(mutate)
                self.bootstrap('--role', 'exit', success=False)
                self.assertFalse(self.data.exists())
                self.assertEqual(list(self.tmp.iterdir()), [])
        self.assertTrue(all(x[0] == 'curl' for x in self.logs()))

    def test_bootstrap_no_unpinned_or_http_or_forwarded_data(self):
        for args in [[], ['--allow-unpinned'], ['--bundle-url', 'http://example.invalid/a', '--sha256', 'a' * 64],
                     ['--bundle-url', 'https://example.invalid/a', '--sha256', 'a' * 64, '--data-dir', str(self.data), '--', '--data-dir', '/tmp/override']]:
            self.run_script('terminal-install.sh', *args, success=False)
        self.assertEqual(self.logs(), [])

    def test_health_family_and_scope_are_honest(self):
        self.env['MOCK_HEALTH'] = '1'
        for family, host in [('ipv4', '203.0.113.7'), ('ipv6', '2001:db8::7')]:
            bridge = self.run_script('cascade-healthcheck.sh', '--role', 'bridge', '--runtime', 'docker',
                                     '--exit-host', host, '--routing', 'all', '--data-dir', self.data)
            self.assertIn('native XIO/client egress NOT proven', json.loads(bridge.stdout)['scope'])
            self.run_script('cascade-healthcheck.sh', '--role', 'exit', '--runtime', 'docker',
                            '--exit-family', family, '--data-dir', self.data)
            commands = self.logs()
            flag = '-4' if family == 'ipv4' else '-6'
            self.assertTrue(any(x[:3] == ['docker', 'exec', 'xio-cascade-bridge'] and x[3:] == ['ip', flag, 'route', 'get', host] for x in commands))
            self.assertTrue(any(x[:4] == ['docker', 'exec', 'xio-cascade-exit', 'curl'] and flag in x for x in commands))

    def test_cleanup_does_not_follow_replaced_directory(self):
        victim = self.root / 'unrelated'
        victim.mkdir()
        (victim / 'sentinel').write_text('keep')
        self.env['MOCK_REPLACE_TEMP'] = str(victim)
        self.bootstrap('--role', 'exit', success=False)
        self.assertEqual((victim / 'sentinel').read_text(), 'keep')
        self.assertTrue(any(p.is_symlink() for p in self.tmp.iterdir()))


if __name__ == '__main__':
    unittest.main(verbosity=2)
