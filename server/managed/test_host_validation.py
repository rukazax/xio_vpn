"""Host-boundary source tests without importing Linux-only service modules."""
import ast
import ipaddress
import re
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load_function(filename, name):
    tree = ast.parse((HERE / filename).read_text(encoding='utf-8'))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    namespace = {'ipaddress': ipaddress, 're': re}
    exec(compile(ast.Module(body=[node], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]


setup_valid = load_function('rivet-setup.py', 'valid_name')
admin_valid = load_function('admin.py', 'valid_host')


class HostBoundaryTests(unittest.TestCase):
    def test_domain_ip_and_trailing_dot_accepted(self):
        for valid in (setup_valid, admin_valid):
            for host in ['fr-host.fr', 'vpn.example.com', 'fr-host.fr.', 'xn--bcher-kva.example',
                         'XN--BCHER-KVA.example', 'localhost', '192.0.2.8', '2001:db8::42',
                         '::ffff:192.0.2.1']:
                with self.subTest(function=valid.__name__, host=host):
                    self.assertTrue(valid(host))

    def test_length_boundary_matches_app_cap(self):
        valid = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 61])
        self.assertEqual(len(valid), 253)
        for function in (setup_valid, admin_valid):
            with self.subTest(function=function.__name__):
                self.assertTrue(function(valid))
                self.assertFalse(function(valid + 'a'))

    def test_malformed_names_rejected(self):
        for valid in (setup_valid, admin_valid):
            for host in ['', ' fr-host.fr', 'fr-host.fr ', 'fr-host.fr:8443', '[fr-host.fr]',
                         '[2001:db8::42]', 'bad host', 'fr-host..fr', '-fr-host.fr',
                         'fr-host-.fr', 'fr_host.fr', 'https://fr-host.fr',
                         '256.256.256.256', 'fe80::1%eth0', 'a' * 64 + '.fr', 123]:
                with self.subTest(function=valid.__name__, host=host):
                    self.assertFalse(valid(host))


if __name__ == '__main__':
    unittest.main(verbosity=2)
