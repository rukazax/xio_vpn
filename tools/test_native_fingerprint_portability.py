"""Portable ordering regression tests; pure stdlib and temporary files only."""
import hashlib
import importlib.util
import json
import os
import random
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import tempfile
import unittest
from unittest.mock import patch

from native_fingerprint import (
    canonical_relative_key,
    fingerprint,
    _collect,
    _digest,
)

FROZEN_PROJECTION = "bc87f1048bdda4e6b08e4983691463366a205937949abd141a29efd152467f2d"
FIRST_FIXTURE_NAMES = [
    "protocol/rivet/go.mod",
    "protocol/rivet/go.sum",
    "protocol/rivet/main.go",
    "vendor/xray/LICENSE",
    "vendor/xray/Z.go",
    "vendor/xray/a/z.go",
    "vendor/xray/a.go",
]


class PortabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xio-fingerprint-portable-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, root, name, data):
        path = Path(root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def make_fixture(self, root):
        values = {
            "protocol/rivet/go.mod": b"module xio.local/rivet\n",
            "protocol/rivet/go.sum": b"pinned module bytes\n",
            "protocol/rivet/main.go": b"package rivet\n",
            "vendor/xray/LICENSE": b"license bytes\n",
            "vendor/xray/Z.go": b"package xray\n",
            "vendor/xray/a/z.go": b"package xray\n",
            "vendor/xray/a.go": b"package xray\n",
        }
        for name, data in values.items():
            self.put(root, name, data)
        return values

    def explicit_digest(self, root, names):
        result = hashlib.sha256()
        for name in names:
            result.update(name.encode() + b"\0" + (Path(root) / name).read_bytes())
        return result.hexdigest()

    def test_mixed_case_expected_order_and_digest(self):
        self.make_fixture(self.root)
        self.assertEqual(
            fingerprint(self.root),
            self.explicit_digest(self.root, FIRST_FIXTURE_NAMES),
        )

    def test_canonical_key_is_component_tuple_not_joined_string(self):
        posix = canonical_relative_key(PurePosixPath("vendor/xray/a/z.go"))
        windows = canonical_relative_key(PureWindowsPath(r"vendor\xray\a\z.go"))
        self.assertEqual(posix, windows)
        self.assertLess(
            canonical_relative_key(PurePosixPath("vendor/xray/a/z.go")),
            canonical_relative_key(PurePosixPath("vendor/xray/a.go")),
        )
        self.assertLess(
            canonical_relative_key(PurePosixPath("vendor/xray/LICENSE")),
            canonical_relative_key(PurePosixPath("vendor/xray/a/z.go")),
        )
        self.assertEqual(
            canonical_relative_key(PurePosixPath("vendor/xray/a/z.go")),
            ("vendor", "xray", "a", "z.go"),
        )
        self.assertNotEqual(
            canonical_relative_key(PurePosixPath("vendor/xray/a/z.go")),
            "vendor/xray/a/z.go",
        )

    def test_shuffled_enumeration_has_same_digest(self):
        self.make_fixture(self.root)
        files = _collect(self.root)
        random.Random(7).shuffle(files)
        self.assertEqual(_digest(self.root, files), fingerprint(self.root))

    def test_root_independence(self):
        self.make_fixture(self.root)
        other = self.root / "other-root"
        shutil.copytree(self.root / "protocol", other / "protocol")
        shutil.copytree(self.root / "vendor", other / "vendor")
        self.assertEqual(fingerprint(self.root), fingerprint(other))

    def test_content_rename_add_and_remove_negatives(self):
        self.make_fixture(self.root)
        before = fingerprint(self.root)
        target = self.root / "vendor/xray/a.go"
        target.write_bytes(target.read_bytes() + b"// changed\n")
        after_content = fingerprint(self.root)
        self.assertNotEqual(before, after_content)
        target.rename(self.root / "vendor/xray/a-renamed.go")
        after_rename = fingerprint(self.root)
        self.assertNotEqual(after_content, after_rename)
        self.put(self.root, "vendor/xray/a-extra.go", b"package xray\n")
        after_add = fingerprint(self.root)
        self.assertNotEqual(after_rename, after_add)
        (self.root / "vendor/xray/a-renamed.go").unlink()
        self.assertNotEqual(after_add, fingerprint(self.root))

    def test_case_selection_limitation_is_characterized(self):
        self.put(self.root, "protocol/rivet/go.mod", b"module xio.local/rivet\n")
        self.put(self.root, "protocol/rivet/go.sum", b"sum\n")
        self.put(self.root, "protocol/rivet/lower.go", b"package rivet\n")
        self.put(self.root, "protocol/rivet/UPPER.GO", b"package rivet\n")
        selected = {p.name for p in (self.root / "protocol/rivet").rglob("*.go")}
        self.assertIn("lower.go", selected)
        if os.name == "nt":
            self.assertIn("UPPER.GO", selected)
        else:
            self.assertNotIn("UPPER.GO", selected)

    def test_current_1523_projection_pin(self):
        repo = Path(__file__).resolve().parents[1]
        self.assertEqual(fingerprint(repo), FROZEN_PROJECTION)


class ActualCaptureVerifyTests(unittest.TestCase):
    """Use the real release capture/verify entry, not a local comparator."""

    def test_canonical_fixture_reaches_boundary_stale_source_aar_fail(self):
        tools = Path(__file__).resolve().parents[1] / "tools"
        sys.path.insert(0, str(tools))
        import native_fingerprint as native

        spec = importlib.util.spec_from_file_location(
            "native_order_current_targets", tools / "release" / "current_targets.py"
        )
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        self.assertIs(gate.fingerprint, native.fingerprint)

        sha = "1" * 40

        def git_identity(command, cwd=None):
            if command == ["git", "rev-parse", "HEAD"]:
                return sha
            if command == ["git", "status", "--porcelain", "--untracked-files=no"]:
                return ""
            raise AssertionError(("unexpected external command", command))

        class ReachedArtifacts(RuntimeError):
            pass

        with tempfile.TemporaryDirectory(prefix="actual-native-gate-") as directory:
            root = Path(directory)
            ordered = [
                ("protocol/rivet/go.mod", b"module xio.local/rivet\n"),
                ("protocol/rivet/go.sum", b"sum\n"),
                ("protocol/rivet/main.go", b"package rivet\n"),
                ("vendor/xray/LICENSE", b"license\n"),
                ("vendor/xray/Z.go", b"package xray\n"),
                ("vendor/xray/a/z.go", b"package xray\n"),
                ("vendor/xray/a.go", b"package xray\n"),
            ]
            expected = hashlib.sha256()
            for name, data in ordered:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                expected.update(name.encode() + b"\0" + data)
            expected_source = expected.hexdigest()
            self.assertEqual(native.fingerprint(root), expected_source)

            aar = root / "app/android/app/libs/rivet.aar"
            aar.parent.mkdir(parents=True)
            aar.write_bytes(b"SYNTHETIC-AAR-BYTES-NOT-EXECUTABLE")
            expected_aar = hashlib.sha256(aar.read_bytes()).hexdigest()
            (root / "app/pubspec.yaml").write_bytes(
                b"name: synthetic_gate_fixture\nversion: 9.9.9+999\n"
            )
            meta = root / "vendor-metadata/rivet-build.json"
            meta.parent.mkdir()
            desktop = root / "desktop-reference"
            desktop.mkdir()

            for label, source_hash, aar_hash in [
                ("canonical", expected_source, expected_aar),
                ("stale-source", "0" * 64, expected_aar),
                ("stale-aar", expected_source, "0" * 64),
            ]:
                meta.write_text(json.dumps({
                    "sourceSha256": source_hash,
                    "androidAarSha256": aar_hash,
                }))
                with patch.object(gate, "run", side_effect=git_identity), \
                        patch.object(gate.assets, "capture",
                                     return_value={"appVersion": "9.9.9+999"}), \
                        patch.object(gate, "staged_server_fresh",
                                     return_value=True), \
                        patch.object(gate, "artifact_set",
                                     side_effect=ReachedArtifacts("after native gates")) as downstream:
                    lock = gate.capture(root, sha)
                    self.assertEqual(lock["nativeSourceSha256"], expected_source)
                    self.assertEqual(lock["nativeSourceFresh"], label != "stale-source")
                    self.assertEqual(lock["nativeAarMatchesMetadata"], label != "stale-aar")
                    with self.subTest(label=label):
                        try:
                            gate.verify(
                                root, lock, root / "empty-artifacts", "windows",
                                sha, reference=desktop,
                            )
                        except ReachedArtifacts:
                            self.assertEqual(label, "canonical")
                            self.assertEqual(downstream.call_count, 1)
                        except RuntimeError as error:
                            self.assertNotEqual(label, "canonical")
                            self.assertTrue(str(error).startswith(
                                "Native source/AAR provenance NOT_READY:"
                            ))
                            self.assertEqual(downstream.call_count, 0)
                        else:
                            self.fail("unexpected artifact acceptance")
if __name__ == "__main__":
    unittest.main()