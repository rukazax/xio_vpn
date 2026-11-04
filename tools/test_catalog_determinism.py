"""Contract §2 determinism: fixed probe input must give byte-identical output.

The live network is not deterministic (xio measured 522 then 499 eligible minutes
apart), so the guarantee is stated on a fixed probe result set: same entries ->
same bytes, and measured fields (RTT, certificate dates) must not leak into
contentSha256.
"""
import importlib.util
from pathlib import Path
import sys
import unittest

MODULE = Path(__file__).resolve().parent.parent / 'server/catalog/catalog.py'
if not MODULE.is_file():  # canon module lands with the P2 commit
    raise unittest.SkipTest('server/catalog/catalog.py is not present')
spec = importlib.util.spec_from_file_location('catalog_canon', MODULE)
catalog = importlib.util.module_from_spec(spec)
sys.modules['catalog_canon'] = catalog  # dataclasses need a registered module on 3.10
spec.loader.exec_module(catalog)

SOURCE = {'url': catalog.SOURCE_URL, 'commit': 'e61be51b', 'sha256': 'dfa4ffee', 'license': 'MIT',
          'fetchedAt': '2026-11-03T06:10:00Z', 'bytes': 15648, 'lines': 910}
PROBE = {'performedOn': 'VPS-721137', 'interface': 'eth0', 'country': 'FR',
         'bypassTunnel': True, 'tlsRequires': '1.3'}


def entries(rtt=10, not_after='Jan  1 00:00:00 2027 GMT'):
    return [
        catalog.Entry(fqdn='a.ru', eligible=False, reject_reason='unresolved', resolved=[],
                       tls13=False),
        catalog.Entry(fqdn='b.ru', eligible=True, resolved=['2.2.2.2', '1.1.1.1'], tls13=True,
                       cert_sha256='a' * 64, cert_not_after=not_after, tls_rtt_ms=rtt),
    ]


def document(**overrides):
    return catalog.build_document(entries(**overrides), dict(SOURCE), dict(PROBE),
                                  {'raw': 3, 'unique': 2})


class DeterminismTests(unittest.TestCase):
    def test_same_probe_input_gives_identical_bytes(self):
        self.assertEqual(catalog.dumps(document()), catalog.dumps(document()))

    def test_measurements_stay_out_of_content_hash(self):
        first = document()
        second = document(rtt=999, not_after='Jan  1 00:00:00 2030 GMT')
        self.assertEqual(first['contentSha256'], second['contentSha256'])
        self.assertNotEqual(catalog.dumps(first), catalog.dumps(second))

    def test_resolved_addresses_are_order_insensitive(self):
        one = catalog.content_sha256([catalog.Entry(fqdn='a.ru', eligible=True, resolved=['1.1.1.1', '2.2.2.2'])])
        two = catalog.content_sha256([catalog.Entry(fqdn='a.ru', eligible=True, resolved=['2.2.2.2', '1.1.1.1'])])
        self.assertEqual(one, two)

    def test_lint_accepts_the_document(self):
        self.assertEqual(catalog.lint_document(document()), [])


if __name__ == '__main__':
    unittest.main()
