#!/usr/bin/env python3
"""Hermetic tests for the XIO whitelist catalog (contract §12, criteria 1-7).

No network access: fetching and probing are replaced by fakes.
Run: python3 -m unittest discover -s server/catalog/tests -v
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import datetime as dt
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import catalog  # noqa: E402

SOURCE = b"a.ru\nb.ru\nc.ru\nd.ru\ne.ru\nf.ru\ng.ru\nh.ru\ni.ru\nj.ru\nk.ru\nl.ru\n"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def entry(name: str, eligible: bool = True, rtt: int = 10) -> catalog.Entry:
    if not eligible:
        return catalog.Entry(name, reject_reason="unreachable")
    return catalog.Entry(
        name,
        eligible=True,
        resolved=["203.0.113.10"],
        tls13=True,
        cert_sha256="a" * 64,
        cert_not_after="2027-01-01T00:00:00Z",
        tls_rtt_ms=rtt,
    )


def fake_probe(rtt: int = 10):
    def probe(name: str) -> catalog.Entry:
        if name in {"d.ru", "j.ru"}:
            return catalog.Entry(name, reject_reason="unreachable")
        return entry(name, rtt=rtt)

    return probe


def pins_file(directory: Path, sha: str | None = None, source: str = catalog.SOURCE_URL) -> Path:
    path = directory / "pins.json"
    payload = {
        "schema": 1,
        "source": source,
        "sha256": sha if sha is not None else catalog.hashlib.sha256(SOURCE).hexdigest(),
        "commit": COMMIT,
        "license": "MIT",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.pins = pins_file(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, payload: bytes = SOURCE, probe=None, **kwargs):
        return catalog.build(
            source_payload=payload,
            commit=COMMIT,
            pins_path=kwargs.pop("pins_path", self.pins),
            probe=probe or fake_probe(),
            **kwargs,
        )

    # 1 (contract revision: determinism is stated on a fixed probe input)
    def test_same_probe_input_gives_byte_identical_artifact(self):
        fixed_now = dt.datetime(2026, 11, 3, 12, 0, 0, tzinfo=dt.timezone.utc)
        first = catalog.dumps(self.build(probe=fake_probe(rtt=11), now=fixed_now))
        second = catalog.dumps(self.build(probe=fake_probe(rtt=11), now=fixed_now))
        self.assertEqual(first, second)
        # A different probe result set must produce a different artifact.
        other = catalog.dumps(self.build(probe=fake_probe(rtt=250), now=fixed_now))
        self.assertNotEqual(first, other)
        document = json.loads(first)
        self.assertEqual(document["contentSha256"], catalog.content_sha256(
            catalog._entries_from_json(document["entries"])
        ))

    def test_deterministic_content_hash_and_provenance(self):
        first = self.build(probe=fake_probe(rtt=11))
        second = self.build(probe=fake_probe(rtt=999))
        self.assertEqual(first["contentSha256"], second["contentSha256"])
        self.assertEqual(
            [(e["fqdn"], e["eligible"], e["resolved"]) for e in first["entries"]],
            [(e["fqdn"], e["eligible"], e["resolved"]) for e in second["entries"]],
        )
        self.assertNotEqual(first["entries"][0]["tlsRttMs"], second["entries"][0]["tlsRttMs"])
        source = first["source"]
        for key in ("url", "commit", "sha256", "license", "bytes", "lines"):
            self.assertIn(key, source)
        self.assertEqual(source["sha256"], catalog.hashlib.sha256(SOURCE).hexdigest())
        for key in ("performedOn", "interface", "country", "bypassTunnel", "tlsRequires"):
            self.assertIn(key, first["probe"])

    # 3
    def test_pin_mismatch_is_code_3_and_writes_nothing(self):
        pins = pins_file(self.dir, sha="0" * 64)
        with self.assertRaises(catalog.CatalogError) as ctx:
            self.build(pins_path=pins)
        self.assertEqual(ctx.exception.code, 3)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["pins.json"])

    def test_missing_pin_is_code_3(self):
        with self.assertRaises(catalog.CatalogError) as ctx:
            self.build(pins_path=self.dir / "absent.json")
        self.assertEqual(ctx.exception.code, 3)

    # 4
    def test_empty_source_is_code_3(self):
        with self.assertRaises(catalog.CatalogError) as ctx:
            self.build(payload=b"\n\n# only comments\n")
        self.assertEqual(ctx.exception.code, 3)

    def test_broken_source_is_code_3(self):
        with self.assertRaises(catalog.CatalogError) as ctx:
            self.build(payload=b"\xff\xfe\x00bad")
        self.assertEqual(ctx.exception.code, 3)

    def test_oversized_source_is_code_4(self):
        original = catalog.LIMIT_BYTES
        catalog.LIMIT_BYTES = 10
        try:
            with self.assertRaises(catalog.CatalogError) as ctx:
                self.build()
        finally:
            catalog.LIMIT_BYTES = original
        self.assertEqual(ctx.exception.code, 4)

    # 6
    def test_unreachable_source_is_code_2(self):
        original = catalog.fetch_bytes

        def boom(url, timeout=20.0):
            raise catalog.CatalogError(catalog.EXIT_SOURCE, "source unavailable")

        catalog.fetch_bytes = boom
        try:
            with self.assertRaises(catalog.CatalogError) as ctx:
                catalog.build(commit=COMMIT, pins_path=self.pins, probe=fake_probe())
        finally:
            catalog.fetch_bytes = original
        self.assertEqual(ctx.exception.code, 2)

    # 7
    def test_every_eligible_entry_is_complete(self):
        document = self.build()
        for record in document["entries"]:
            if record["eligible"]:
                self.assertTrue(record["resolved"])
                self.assertIs(record["tls13"], True)
                self.assertEqual(len(record["certSha256"]), 64)
                self.assertTrue(record["certNotAfter"].endswith("Z"))
                self.assertGreater(record["tlsRttMs"], 0)
                self.assertIsNone(record["rejectReason"])
            else:
                self.assertIn(record["rejectReason"], catalog.REJECT_REASONS)

    def test_counts_match_entries(self):
        document = self.build()
        counts = document["counts"]
        self.assertEqual(counts["raw"], 12)
        self.assertEqual(counts["unique"], 12)
        self.assertEqual(counts["eligible"], 10)
        self.assertEqual(counts["rejected"]["unreachable"], 2)

    # 9
    def test_threshold_is_code_4_and_writes_nothing(self):
        small = b"a.ru\nb.ru\nc.ru\nd.ru\ne.ru\n"
        pins = pins_file(self.dir, sha=catalog.hashlib.sha256(small).hexdigest())
        with self.assertRaises(catalog.CatalogError) as ctx:
            self.build(payload=small, pins_path=pins)
        self.assertEqual(ctx.exception.code, 4)

    def test_no_output_written_without_publish(self):
        self.build()
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["pins.json"])


class ParseTests(unittest.TestCase):
    def test_stage0_rejects(self):
        payload = (
            "good.ru\n"
            "*.bad.ru\n"
            "bad.ru/path\n"
            "dot.ru.\n"
            "with space.ru\n"
            "port.ru:443\n"
            "GOOD.ru\n"
            "\u0434\u043e\u043c.\u0440\u0444\n"
        ).encode("utf-8")
        names, stats = catalog.parse_source(payload)
        self.assertIn("good.ru", names)
        self.assertIn("xn--d1aqf.xn--p1ai", names)
        self.assertEqual(names.count("good.ru"), 1)
        self.assertEqual(stats["raw"], 8)
        self.assertEqual(stats["unique"], 2)
        self.assertEqual(stats["duplicates"], 1)


class LintTests(unittest.TestCase):
    def test_lint_flags_tampering(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        pins = pins_file(directory)
        document = catalog.build(
            source_payload=SOURCE,
            commit=COMMIT,
            pins_path=pins,
            probe=fake_probe(),
        )
        self.assertEqual(catalog.lint_document(document), [])
        document["entries"][0]["resolved"] = ["198.51.100.7"]
        self.assertIn("contentSha256 mismatch", " ".join(catalog.lint_document(document)))

    def test_lint_flags_incomplete_eligible(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pins = pins_file(Path(tmp.name))
        document = catalog.build(
            source_payload=SOURCE, commit=COMMIT, pins_path=pins, probe=fake_probe()
        )
        document["entries"][0]["certSha256"] = None
        problems = catalog.lint_document(document)
        self.assertTrue(any("certSha256" in problem for problem in problems))


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_publish_rotates_previous_with_manifest(self):
        first = catalog.dumps({"schema": 1, "entries": [], "contentSha256": "x"})
        second = catalog.dumps({"schema": 1, "entries": [], "contentSha256": "y"})
        catalog.publish(self.dir, "whitelist-20261103.json", first)
        state = catalog.publish(self.dir, "whitelist-20261103.json", second)
        self.assertEqual(state["current"]["sha256"], catalog.hashlib.sha256(second).hexdigest())
        self.assertEqual(state["previous"]["sha256"], catalog.hashlib.sha256(first).hexdigest())
        self.assertEqual((self.dir / catalog.PREVIOUS_NAME).read_bytes(), first)

    def test_rollback_restores_previous(self):
        first = b'{"schema": 1, "entries": [], "contentSha256": "x"}\n'
        second = b'{"schema": 1, "entries": [], "contentSha256": "y"}\n'
        catalog.publish(self.dir, "whitelist-20261103.json", first)
        catalog.publish(self.dir, "whitelist-20261103.json", second)
        catalog.rollback(self.dir)
        self.assertEqual((self.dir / "whitelist-20261103.json").read_bytes(), first)

    def test_rollback_refuses_tampered_previous(self):
        first = b'{"schema": 1, "entries": [], "contentSha256": "x"}\n'
        second = b'{"schema": 1, "entries": [], "contentSha256": "y"}\n'
        catalog.publish(self.dir, "whitelist-20261103.json", first)
        catalog.publish(self.dir, "whitelist-20261103.json", second)
        (self.dir / catalog.PREVIOUS_NAME).write_bytes(b"tampered\n")
        with self.assertRaises(catalog.CatalogError) as ctx:
            catalog.rollback(self.dir)
        self.assertEqual(ctx.exception.code, 5)
        self.assertEqual((self.dir / "whitelist-20261103.json").read_bytes(), second)


@unittest.skipUnless(sys.platform.startswith("linux"), "SIGKILL/flock test needs Linux")
class CrashTests(unittest.TestCase):
    """Criterion 5: kill -9 during the write keeps artifacts intact and frees the lock."""

    def test_kill_during_write(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        artifact = directory / "whitelist-20261103.json"
        original = b'{"schema": 1, "entries": [], "contentSha256": "keep"}\n'
        catalog.publish(directory, artifact.name, original)
        before_state = (directory / catalog.STATE_NAME).read_bytes()
        lock_path = directory / "lock"

        script = f"""
import sys, time, pathlib
sys.path.insert(0, {str(HERE.parent)!r})
import catalog
d = pathlib.Path({str(directory)!r})
with catalog._Lock(pathlib.Path({str(lock_path)!r})):
    tmp = d / '.tmp-mid.json'
    with open(tmp, 'wb') as fh:
        fh.write(b'partial')
        fh.flush()
        import os; os.fsync(fh.fileno())
    print('ready', flush=True)
    time.sleep(120)
"""
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            line = child.stdout.readline().decode().strip()
            self.assertEqual(line, "ready")
            os.kill(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()

        self.assertEqual(artifact.read_bytes(), original)
        self.assertEqual((directory / catalog.STATE_NAME).read_bytes(), before_state)
        with catalog._Lock(lock_path):
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
