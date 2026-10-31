import ast
from contextlib import ExitStack
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import dualstack
import network_stack as network
import stack
from test_rivet_public import setup


class RouteAndCapabilityTests(unittest.TestCase):
    def test_reject_default_routes_without_usable_dev_or_with_reject_type(self):
        values = [{'type':'unreachable'}, {'type':'blackhole','dev':'lo'}, {'dev':'eth0;bad'},
                  {'dev':'eth6','metric':5}, {'dev':'eth0','metric':1}]
        with patch.object(dualstack, 'call', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(values))):
            self.assertEqual([x['dev'] for x in dualstack.routes('-6')], ['eth0', 'eth6'])
        with patch.object(setup, 'run', side_effect=lambda *args: json.dumps(values) if '-6' in args else '[{"type":"unreachable"}]'):
            self.assertEqual(setup.outbound_device(), 'eth0')

    def test_split_family_interfaces_and_dns64_are_not_conflated(self):
        for values in [{'ipv4':'eth4'}, {'ipv6':'eth6'}, {'ipv4':'eth4','ipv6':'eth6'}, {}]:
            with self.subTest(values=values), patch.object(dualstack, 'outbounds', return_value=values):
                result = dualstack.capabilities()
                self.assertEqual(result['outboundByFamily'], values)
                self.assertEqual(result['ipv4DefaultRoute'], 'ipv4' in values)
                self.assertEqual(result['ipv6DefaultRoute'], 'ipv6' in values)
                self.assertEqual(result['dns64'], 'notProbed')
                self.assertEqual(result['nat64'], 'notProbed')
                self.assertEqual(result['endToEnd'], 'notProbed')
                self.assertIn('DNS64 does not translate IPv4 literals', result['note'])
                if 'ipv4' not in values:
                    self.assertEqual(result['ipv4LiteralEgress'], 'requiresExplicitTranslation')

    def test_preflight_missing_device_wrong_device_capability_and_open_denial(self):
        for issue in ['missing', 'regular-file', 'wrong-device', 'net-admin', 'net-raw', 'bounding', 'open-denied', 'no-route', 'ok']:
            with self.subTest(issue=issue), tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
                root = Path(directory)
                status = root / 'status'
                effective = 0x3000
                bounding = 0x3000
                if issue == 'net-admin': effective &= ~0x1000
                if issue == 'net-raw': effective &= ~0x2000
                if issue == 'bounding': bounding &= ~0x1000
                status.write_text('CapEff:\t%016x\nCapBnd:\t%016x\n' % (effective, bounding))
                tun = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=stat.S_IFREG if issue == 'regular-file' else stat.S_IFCHR, st_rdev=123))
                if issue == 'missing': tun.stat = lambda: (_ for _ in ()).throw(FileNotFoundError())
                patches.enter_context(patch.object(dualstack, 'TUN', tun))
                patches.enter_context(patch.object(dualstack, 'PROCESS_STATUS', status))
                patches.enter_context(patch.object(dualstack.os, 'major', return_value=10, create=True))
                patches.enter_context(patch.object(dualstack.os, 'minor', return_value=201 if issue == 'wrong-device' else 200, create=True))
                opened = patches.enter_context(patch.object(dualstack.os, 'open', side_effect=PermissionError('fixture') if issue == 'open-denied' else None, return_value=123))
                closed = patches.enter_context(patch.object(dualstack.os, 'close'))
                patches.enter_context(patch.object(dualstack, 'outbounds', return_value={} if issue == 'no-route' else {'ipv6':'eth6'}))
                mutations = patches.enter_context(patch.object(dualstack, 'call', side_effect=AssertionError('Unexpected network command')))
                if issue == 'ok':
                    result = dualstack.preflight()
                    self.assertTrue(result['tunOpen'])
                    self.assertEqual(result['tunSetIff'], 'notProbed')
                    self.assertEqual(result['wireguardCreation'], 'notProbed')
                    opened.assert_called_once(); closed.assert_called_once_with(123)
                else:
                    with self.assertRaises(RuntimeError): dualstack.preflight()
                    if issue in ['missing', 'regular-file', 'wrong-device', 'net-admin', 'net-raw', 'bounding']:
                        opened.assert_not_called()
                mutations.assert_not_called()

    def test_bootstrap_checks_precede_all_installation_writes(self):
        text = Path(__file__).with_name('bootstrap.sh').read_text()
        boundary = text.index('lib=/usr/local/lib/xio-managed')
        for term in ['CAP_NET_ADMIN', 'CAP_NET_RAW', 'exec 3<>/dev/net/tun', 'TUNSETIFF']:
            self.assertLess(text.index(term), boundary)
        for command in ['mknod ', 'modprobe ', 'mount ', 'setenforce ', 'apparmor_parser -R']:
            self.assertNotIn(command, text)

    def test_init_preflight_runs_before_save_and_ready_is_published_last(self):
        spec = importlib.util.spec_from_file_location('admin_preflight', Path(__file__).with_name('admin.py'))
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.object(module.stack.network, 'dualstack', return_value=SimpleNamespace(preflight=lambda: (_ for _ in ()).throw(RuntimeError('TUN blocked')))), patch.object(module, 'save') as save, patch.object(module, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'TUN blocked'):
                module.init({'host':'2001:db8::42'})
            save.assert_not_called(); run.assert_not_called()
        tree = ast.parse(Path(module.__file__).read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'init')
        ready = [n.lineno for n in ast.walk(function) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and n.value.value == 'ready']
        rivet = [n.lineno for n in ast.walk(function) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'rivet_install']
        self.assertEqual(len(ready), 1)
        self.assertGreaterEqual(ready[0], max(rivet))


class ForwardingFixtures(unittest.TestCase):
    def test_wg_awg_and_both_openvpn_subnets_have_scoped_ipv6_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sysnet = root / 'net'; sysnet.mkdir()
            for interface, _, _ in dualstack.SUBNETS: (sysnet / interface).mkdir()
            state = root / 'state.json'; state.write_text('{"owner":"xio-managed-v1"}')
            forward = root / 'forward'; forward.write_text('0')
            receipt = root / 'receipt.json'
            calls = []; existing = set()
            def call(*args, **kwargs):
                calls.append(args)
                if args[:5] == ('ip', '-j', '-6', 'address', 'show'):
                    return SimpleNamespace(returncode=0, stdout='[]')
                if args[0] == 'ip6tables' and '-C' in args:
                    key = args[:args.index('-C')] + args[args.index('-C')+1:]
                    return SimpleNamespace(returncode=0 if key in existing else 1, stdout='')
                if args[0] == 'ip6tables' and '-I' in args:
                    existing.add(args[:args.index('-I')] + args[args.index('-I')+1:])
                return SimpleNamespace(returncode=0, stdout='[]')
            with patch.object(dualstack, 'STATE', state), patch.object(dualstack, 'RECEIPT', receipt), patch.object(dualstack, 'SYS_NET', sysnet), patch.object(dualstack, 'FORWARDING', forward), patch.object(dualstack, 'IPV6_SYS', root), patch.object(dualstack, 'routes', side_effect=lambda family: [{'dev':'eth6'}] if family == '-6' else [{'dev':'eth4'}]), patch.object(dualstack.os, 'geteuid', return_value=0, create=True), patch.object(dualstack, 'call', side_effect=call):
                self.assertTrue(dualstack.apply()['ipv6Forwarding'])
                rules = json.loads(receipt.read_text())['rules']
                for interface, subnet, _ in dualstack.SUBNETS:
                    owned = [rule for table, rule in rules if 'xio-dualstack-v1-' + interface in rule]
                    self.assertTrue(any(rule[0] == 'FORWARD' and '-s' in rule and subnet in rule and 'eth6' in rule for rule in owned))
                    self.assertTrue(any(rule[0] == 'POSTROUTING' and subnet in rule and 'eth6' in rule and 'MASQUERADE' in rule for rule in owned))
                before = len([c for c in calls if c[0] == 'ip6tables' and '-I' in c])
                dualstack.apply()
                self.assertEqual(len([c for c in calls if c[0] == 'ip6tables' and '-I' in c]), before)
                self.assertFalse(any(c[0] == 'ip6tables' and ('-P' in c or '-F' in c) for c in calls))


class ProfileAndBootFixtures(unittest.TestCase):
    def test_openvpn_server_renders_ipv6_subnets_for_both_transports(self):
        for v6 in [False, True]:
            with self.subTest(v6=v6), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch.object(network, 'ROOT', root), patch.object(network, 'dualstack', return_value=SimpleNamespace(ipv6_ready=lambda: v6)):
                    network.openvpn_configs()
                for transport, prefix in [('udp','fd80:0::/64'), ('tcp','fd80:1::/64')]:
                    text = (root / (transport + '.ovpn')).read_text()
                    self.assertEqual('server-ipv6 ' + prefix in text, v6)
                    if v6:
                        self.assertIn('dhcp-option DNS6 2620:fe::fe', text)
                self.assertIn('proto udp6\n' if v6 else 'proto udp\n', (root / 'udp.ovpn').read_text())
                self.assertIn('local 127.0.0.1\n', (root / 'tcp.ovpn').read_text())

    def test_raw_ipv4_ipv6_dns_in_openvpn_and_structured_profiles(self):
        for host in ['192.0.2.8', '2001:db8::42', 'vpn.example.com']:
            with self.subTest(host=host), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); pki = root / 'pki'; pki.mkdir(); (pki / 'ca.crt').write_text('ca-fixture')
                (root / 'tls-crypt-v2.key').write_text('tls-fixture')
                data = {'host':host, 'restrictedNetwork':True, 'users':{'u':{'stack':{'uuid':'fixture','ssKey':'fixture'}}}}
                def run(*args, **kwargs):
                    if '-out' in args: Path(args[args.index('-out')+1]).write_text('client-fixture\n')
                    if args[:2] == ('openvpn','--tls-crypt-v2'): Path(args[-1]).write_text('tls-client-fixture')
                    return b''
                with patch.object(network, 'ROOT', root), patch.object(network, 'PKI', pki), patch.object(network, 'run', side_effect=run):
                    profile = json.loads(network.create(data,'u')['openvpn'])
                self.assertIn('remote ' + host + ' 1194\n', profile['config'])
                self.assertIn('proto udp6\n' if ':' in host else 'proto udp\n', profile['config'])
                (root / 'receipt.json').write_text('{"cloakPublicKey":"fixture","serverName":"vpn.example"}')
                with patch.object(network, 'ROOT', root): cloak = json.loads(network.cloak_profile(data,'u',json.dumps(profile))['cloak'])
                self.assertIn('proto tcp-client\n', cloak['config'])
                self.assertEqual(cloak['cloak']['RemoteHost'], host)
                with patch.object(stack, 'receipt', return_value={'publicKey':'fixture','shortId':'fixture','serverName':'vpn.example','ssKey':'fixture'}):
                    xray = json.loads(stack.profiles(data,'u')['xray'])
                self.assertEqual(xray['outbound']['settings']['vnext'][0]['address'], host)

    def test_owned_hook_merge_preserves_security_and_rejects_foreign_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); unit = root / 'xio-openvpn-tcp.service'
            initial = '[Unit]\nDescription=XIO managed xio-openvpn-tcp\n[Service]\nExecStart=/usr/sbin/openvpn --config ' + str(root / 'tcp.ovpn') + '\nNoNewPrivileges=yes\nProtectSystem=strict\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n[Install]\nWantedBy=multi-user.target\n'
            unit.write_text(initial)
            receipt = root / 'receipt.json'; receipt.write_text('{"owner":"xio-stack-v1"}')
            with patch.object(network, 'ROOT', root), patch.object(network, 'SYSTEMD', root):
                network.reconcile_ipv6_hooks(); first = unit.read_text(); network.reconcile_ipv6_hooks()
                self.assertEqual(unit.read_text(), first)
                self.assertIn(network.ipv6_hook('tcp'), first)
                for term in ['NoNewPrivileges=yes', 'ProtectSystem=strict', 'CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW']:
                    self.assertIn(term, first)
                receipt.write_text('{"owner":"foreign"}')
                with self.assertRaisesRegex(RuntimeError, 'Unowned'):
                    network.reconcile_ipv6_hooks()
                self.assertEqual(unit.read_text(), first)

    def test_post_hook_waits_for_ipv6_address_after_interface_appears(self):
        net = SimpleNamespace(ipv6_ready=lambda: True, SUBNETS=dualstack.SUBNETS, apply=lambda: {'applied':True})
        checks = 0
        def exists(path):
            nonlocal checks
            checks += 1
            return checks > 1
        with patch.object(network, 'dualstack', return_value=net), patch.object(Path, 'exists', exists), patch.object(network, 'run', side_effect=[b'[{"addr_info":[]}]', b'[{"addr_info":[{"local":"fd80:1::1"}]}]']), patch.object(network.time, 'sleep') as sleep:
            self.assertEqual(network.dualstack_up('xioovpn1'), {'applied':True})
            self.assertEqual(sleep.call_count, 2)
        with patch.object(network, 'dualstack', return_value=net), patch.object(Path, 'exists', return_value=False), patch.object(network.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'not configured'):
                network.dualstack_up('xioovpn1')


if __name__ == '__main__':
    unittest.main()
