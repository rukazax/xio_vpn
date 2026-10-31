"""Pure temporary-filesystem tests; no Go toolchain, sockets or build actions."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from native_fingerprint import fingerprint


class NativeFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xio-fingerprint-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put("protocol/rivet/go.mod", b"module xio.local/rivet\n")
        self.put("protocol/rivet/go.sum", b"pinned module bytes\n")
        self.put("protocol/rivet/main.go", b"package rivet\n")
        self.put("vendor/anet/go.mod", b"module legacy-anet\n")
        self.put("vendor/cloak/LICENSE", b"legacy license\n")

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def add_awg(self):
        self.put("vendor/amneziawg-go/go.mod",
                 b"module github.com/amnezia-vpn/amneziawg-go/v3\n")
        self.put("vendor/amneziawg-go/LICENSE", b"retained MIT license\n")
        self.put("vendor/amneziawg-go/device/completion.go", b"package device\n")

    def legacy_digest(self):
        module = self.root / "protocol/rivet"
        files = [*module.rglob("*.go"), module / "go.mod", module / "go.sum"]
        for name in ["anet", "cloak", "tailscale", "xray", "tun2socks"]:
            files.extend(p for p in (self.root / "vendor" / name).rglob("*")
                         if p.is_file() and not any(x in p.parts for x in [".git", "__pycache__"]))
        result = hashlib.sha256()
        for path in sorted(files):
            result.update(path.relative_to(self.root).as_posix().encode() + b"\0" + path.read_bytes())
        return result.hexdigest()

    def test_legacy_hash_unchanged_without_optional_awg(self):
        self.assertEqual(fingerprint(self.root), self.legacy_digest())

    def test_enabling_awg_changes_hash(self):
        before = fingerprint(self.root)
        self.add_awg()
        self.assertNotEqual(before, fingerprint(self.root))

    def test_each_shipped_awg_input_is_covered(self):
        self.add_awg()
        for name in ["device/completion.go", "device/asm.s", "device/native.c",
                     "go.mod", "go.sum", "LICENSE", "source.json"]:
            path = self.put("vendor/amneziawg-go/" + name,
                            b"module github.com/amnezia-vpn/amneziawg-go/v3\n" if name == "go.mod" else b"first\n")
            before = fingerprint(self.root)
            path.write_bytes(path.read_bytes() + b"\n// changed\n")
            with self.subTest(name=name):
                self.assertNotEqual(before, fingerprint(self.root))

    def test_deleting_awg_source_changes_hash(self):
        self.add_awg()
        before = fingerprint(self.root)
        (self.root / "vendor/amneziawg-go/device/completion.go").unlink()
        self.assertNotEqual(before, fingerprint(self.root))

    def test_awg_internal_paths_are_part_of_hash(self):
        self.add_awg()
        before = fingerprint(self.root)
        (self.root / "vendor/amneziawg-go/device/completion.go").rename(
            self.root / "vendor/amneziawg-go/device/renamed.go")
        self.assertNotEqual(before, fingerprint(self.root))

    def test_ignored_cache_and_git_bytes_do_not_change_hash(self):
        self.add_awg()
        before = fingerprint(self.root)
        self.put("vendor/amneziawg-go/.git/HEAD", b"ignored metadata\n")
        self.put("vendor/amneziawg-go/__pycache__/ignored.pyc", b"ignored cache")
        self.assertEqual(before, fingerprint(self.root))

    def test_missing_or_foreign_awg_module_is_rejected(self):
        self.put("vendor/amneziawg-go/device/input.go", b"package device\n")
        with self.assertRaisesRegex(RuntimeError, "Missing or foreign"):
            fingerprint(self.root)
        self.put("vendor/amneziawg-go/go.mod", b"module foreign.example/other\n")
        with self.assertRaisesRegex(RuntimeError, "Missing or foreign"):
            fingerprint(self.root)

    def test_linked_awg_input_is_rejected_by_guard(self):
        self.add_awg()
        original = Path.is_symlink
        source = self.root / "vendor/amneziawg-go/device/completion.go"
        # Mock only the link predicate: does not require Windows link privileges.
        with patch.object(Path, "is_symlink", lambda p: p == source or original(p)):
            with self.assertRaisesRegex(RuntimeError, "Linked AWG"):
                fingerprint(self.root)

    def test_linked_awg_root_is_rejected_by_guard(self):
        self.add_awg()
        original = Path.is_symlink
        source = self.root / "vendor/amneziawg-go"
        with patch.object(Path, "is_symlink", lambda p: p == source or original(p)):
            with self.assertRaisesRegex(RuntimeError, "Linked or external"):
                fingerprint(self.root)


if __name__ == "__main__":
    unittest.main()
