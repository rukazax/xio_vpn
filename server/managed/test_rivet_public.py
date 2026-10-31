import ast, importlib.util, json, unittest
from pathlib import Path
from urllib.parse import urlsplit
HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('xio_candidate_setup', HERE / 'rivet-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)
class PublicAddressTest(unittest.TestCase):
    def check(self, host):
        address = setup.public_address(host)
        self.assertEqual(address['serverName'], host)
        parsed = urlsplit('//' + address['endpoint'])
        self.assertEqual(parsed.hostname, host.lower())
        self.assertEqual(parsed.port, 8443)
        self.assertEqual(json.loads(json.dumps(address)), address)
        return address
    def test_ipv4(self): self.assertEqual(self.check('192.0.2.8')['endpoint'], '192.0.2.8:8443')
    def test_hostname(self): self.assertEqual(self.check('vpn.example.com')['endpoint'], 'vpn.example.com:8443')
    def test_compressed_ipv6(self): self.assertEqual(self.check('2001:db8::42')['endpoint'], '[2001:db8::42]:8443')
    def test_expanded_ipv6(self): self.check('2001:0db8:0000:0000:0000:0000:0000:0042')
    def test_mapped_ipv6(self): self.check('::ffff:192.0.2.1')
    def test_loopback_ipv6(self): self.check('::1')
    def test_authorised_server_literal(self): self.check('2a0c:b641:1a0:800::2a2')
    def test_server_name_keeps_raw_ipv6(self): self.assertEqual(self.check('2001:db8::1')['serverName'], '2001:db8::1')
    def test_ipv4_and_dns_unchanged(self):
        for host in ['127.0.0.1', '203.0.113.7', 'localhost', 'example.org']:
            with self.subTest(host=host): self.assertEqual(self.check(host)['endpoint'], host + ':8443')
    def test_first_class_domain_hosts(self):
        for host in ['fr-host.fr', 'vpn.example.com', 'xn--bcher-kva.example', 'XN--BCHER-KVA.example', 'fr-host.fr.']:
            with self.subTest(host=host): self.assertEqual(self.check(host)['endpoint'], host + ':8443')
    def test_malformed_domain_hosts_are_rejected(self):
        for host in ['', 'fr-host.fr:8443', '[fr-host.fr]', '[2001:db8::42]', 'bad host', 'fr-host..fr', '-fr-host.fr', 'fr-host-.fr', 'fr_host.fr', 'https://fr-host.fr', '256.256.256.256', 'fe80::1%eth0', 'a' * 64 + '.fr', 'fr-host.fr/', 123]:
            with self.subTest(host=host), self.assertRaises(ValueError): setup.public_address(host)
    def test_valid_name_matches_app_boundary(self):
        for host in ['fr-host.fr', 'fr-host.fr.', 'xn--bcher-kva.example', 'localhost', '203.0.113.112', '2a0c:b641:1a0:800::1']:
            with self.subTest(host=host): self.assertTrue(setup.valid_name(host))
        for host in ['fr_host.fr', 'fr-host..fr', '-fr-host.fr', 'bad host', '[::1]', 'fr-host.fr:8443', '256.256.256.256', '']:
            with self.subTest(host=host): self.assertFalse(setup.valid_name(host))
    def test_original_expression_is_ambiguous_for_ipv6(self):
        with self.assertRaises(ValueError): urlsplit('//2001:db8::42:8443').port
    def test_real_write_path_uses_public_address(self):
        tree = ast.parse((HERE / 'rivet-setup.py').read_text(encoding='utf-8'))
        found = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == 'public' and n.func.attr == 'update']
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0].args), 1)
        self.assertIsInstance(found[0].args[0], ast.Call)
        self.assertEqual(found[0].args[0].func.id, 'public_address')
if __name__ == '__main__': unittest.main(verbosity=2)
