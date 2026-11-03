"""Probe bounds: a stuck resolver must not turn one run into an hour.

getaddrinfo has no timeout and ThreadPoolExecutor joins its workers on exit, so a
slow DNS answer used to keep the whole build alive long after the budget was gone.
"""
import importlib.util
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parent.parent / 'catalog.py'
if not MODULE.is_file():
    raise unittest.SkipTest('catalog.py is not present')
spec = importlib.util.spec_from_file_location('catalog_probe', MODULE)
catalog = importlib.util.module_from_spec(spec)
sys.modules['catalog_probe'] = catalog
spec.loader.exec_module(catalog)


class ResolverTimeoutTests(unittest.TestCase):
    def test_stuck_resolver_is_abandoned_after_timeout(self):
        def stuck(*_args, **_kwargs):
            time.sleep(5)
            return []

        started = time.monotonic()
        with patch.object(catalog.socket, 'getaddrinfo', stuck):
            with self.assertRaises(socket.gaierror):
                catalog._resolve('example.test', 0.05)
        self.assertLess(time.monotonic() - started, 2.0)


class BudgetTests(unittest.TestCase):
    def test_budget_exit_does_not_wait_for_slow_probes(self):
        def slow(name, timeout=3.0, interface=''):
            time.sleep(2)
            return catalog.Entry(name, reject_reason='unreachable')

        started = time.monotonic()
        with self.assertRaises(catalog.CatalogError) as caught:
            catalog.probe_all(['a.test', 'b.test', 'c.test', 'd.test'], slow, concurrency=2, budget_s=0.1)
        self.assertEqual(caught.exception.code, catalog.EXIT_THRESHOLD)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_probe_crash_is_reported_as_unreachable(self):
        def boom(name, timeout=3.0, interface=''):
            raise RuntimeError('probe crashed')

        entries = catalog.probe_all(['a.test'], boom, concurrency=1, budget_s=5)
        self.assertEqual(entries[0].reject_reason, 'unreachable')


if __name__ == '__main__':
    unittest.main()
