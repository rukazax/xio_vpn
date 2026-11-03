import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('catalog', Path(__file__).with_name('whitelist-catalog.py'))
catalog = importlib.util.module_from_spec(spec); spec.loader.exec_module(catalog)

SOURCE = b'gosuslugi.ru\nGosuslugi.RU\n*.wild.ru\nbad host.ru\nsber.ru.\nxn--e1afmkfd.ru\n'


def args(root, **overrides):
    values = dict(pin=str(root / 'pin.json'), out_dir=str(root / 'out'), lock=str(root / 'lock'),
                  commit='deadbeef', interface='eth0', country='FR', timeout=1.0, budget=60,
                  concurrency=2, min_eligible=1, probe=None)
    values.update(overrides)
    return SimpleNamespace(**values)


def pin(root, data=SOURCE, sha=None):
    (root / 'pin.json').write_text(json.dumps({'schema': 1, 'source': 'https://raw.githubusercontent.com/x/y/main/whitelist.txt',
                                                'sha256': sha or hashlib.sha256(data).hexdigest(), 'license': 'MIT'}))


def ok_probe(name, timeout=3.0):
    return {'fqdn': name, 'eligible': True, 'rejectReason': None, 'resolved': ['10.0.0.1'],
            'tls13': True, 'certSha256': 'a' * 64, 'certNotAfter': 'Jan  1 00:00:00 2027 GMT', 'tlsRttMs': 10}


class NormalizeTests(unittest.TestCase):
    def test_input_filter_drops_wildcards_ports_and_duplicates(self):
        names, rejected = catalog.normalize(SOURCE)
        self.assertIn('gosuslugi.ru', names)
        self.assertIn('sber.ru', names)
        self.assertIn('xn--e1afmkfd.ru', names)
        self.assertEqual(names.count('gosuslugi.ru'), 1)
        self.assertGreaterEqual(rejected, 2)

    def test_canonical_hash_ignores_measurements(self):
        one = [{'fqdn': 'a.ru', 'eligible': True, 'resolved': ['1.1.1.1', '2.2.2.2'], 'tlsRttMs': 10,
                'certNotAfter': 'x', 'certSha256': 'a'}]
        two = [{'fqdn': 'a.ru', 'eligible': True, 'resolved': ['2.2.2.2', '1.1.1.1'], 'tlsRttMs': 999,
                'certNotAfter': 'y', 'certSha256': 'b'}]
        self.assertEqual(catalog.canonical(one), catalog.canonical(two))
        self.assertNotEqual(catalog.canonical(one), catalog.canonical([{'fqdn': 'a.ru', 'eligible': False, 'resolved': ['1.1.1.1', '2.2.2.2']}]))


class RunTests(unittest.TestCase):
    def setUp(self):
        self._fetch = catalog.fetch_source
        catalog.fetch_source = lambda url, timeout=20: SOURCE

    def tearDown(self):
        catalog.fetch_source = self._fetch

    def test_builds_catalog_and_record_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin(root)
            self.assertEqual(catalog.run(args(root, probe=ok_probe)), 0)
            files = sorted(p.name for p in (root / 'out').iterdir())
            self.assertEqual(files, ['whitelist-%s.json' % catalog.time.strftime('%Y%m%d'), 'whitelist-manifest.json'])
            data = json.loads((root / 'out' / ('whitelist-%s.json' % catalog.time.strftime('%Y%m%d'))).read_text())
            self.assertEqual(data['schema'], 1)
            self.assertEqual(data['source']['sha256'], hashlib.sha256(SOURCE).hexdigest())
            self.assertEqual(data['counts']['eligible'], data['counts']['unique'])
            self.assertTrue(data['probe']['bypassTunnel'])
            self.assertEqual(data['contentSha256'], catalog.canonical(data['entries']))

    def test_digest_mismatch_refuses_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin(root, sha='0' * 64)
            self.assertEqual(catalog.run(args(root, probe=ok_probe)), 3)
            self.assertFalse((root / 'out' / 'whitelist-manifest.json').exists())

    def test_threshold_and_empty_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = b'gosuslugi.ru\n'
            pin(root, data=duplicate)
            catalog.fetch_source = lambda url, timeout=20: duplicate
            self.assertEqual(catalog.run(args(root, probe=ok_probe, min_eligible=5)), 4)
            unusable = b'*.only-wild\nbad host\n'
            pin(root, data=unusable)
            catalog.fetch_source = lambda url, timeout=20: unusable
            self.assertEqual(catalog.run(args(root, probe=ok_probe)), 4)

    def test_second_run_keeps_previous_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); pin(root)
            self.assertEqual(catalog.run(args(root, probe=ok_probe)), 0)
            first = json.loads((root / 'out' / 'whitelist-manifest.json').read_text())
            self.assertEqual(catalog.run(args(root, probe=ok_probe)), 0)
            second = json.loads((root / 'out' / 'whitelist-manifest.json').read_text())
            self.assertEqual(first['contentSha256'], second['contentSha256'])
            self.assertEqual(second['previousSha256'], first['sha256'])
            self.assertTrue((root / 'out' / 'whitelist-previous.json').exists())
            self.assertEqual([p.name for p in (root / 'out').iterdir() if p.name.startswith('.')], [])


if __name__ == '__main__':
    unittest.main()
