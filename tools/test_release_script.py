#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Тесты чистых функций ``tools/release/release.py``.

Сети, apksigner и GitHub здесь нет: проверяются разбор SHA256SUMS, сверка
digest/размера, выбор ассетов для замены, разбор вывода apksigner и полнота
набора из девяти файлов. Запуск:

    python3 tools/test_release_script.py
    python3 -m pytest -q tools/test_release_script.py
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODULE_PATH = ROOT / "release" / "release.py"


def load_release():
    spec = importlib.util.spec_from_file_location("xio_release_under_test", MODULE_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - среда
        raise RuntimeError(f"не удалось загрузить {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


release = load_release()

SHA_A = "a" * 64
SHA_B = "b" * 64


class VersionTests(unittest.TestCase):
    def test_tag_and_version_normalisation(self):
        self.assertEqual(release.normalize_version("v0.24.2"), "0.24.2")
        self.assertEqual(release.normalize_version("0.24.2"), "0.24.2")
        self.assertEqual(release.normalize_version(" V1.2.3 "), "1.2.3")
        self.assertEqual(release.tag_for("0.24.2"), "v0.24.2")
        self.assertEqual(release.tag_for("v0.24.2"), "v0.24.2")

    def test_invalid_versions_rejected(self):
        for bad in ("", "v", "0.24", "0.24.2.1", "release-0.24.2", "0.24.2-rc1"):
            with self.subTest(bad=bad), self.assertRaises(release.ReleaseError):
                release.normalize_version(bad)


class ArtifactNameTests(unittest.TestCase):
    def test_exactly_nine_unique_names(self):
        names = release.expected_artifacts("0.24.2")
        self.assertEqual(len(names), 9)
        self.assertEqual(len(set(names)), 9)
        self.assertEqual(len(names), release.EXPECTED_ARTIFACTS)
        self.assertIn("XIO-Full-0.24.2-windows-x64.zip", names)
        self.assertIn("xio-server-0.24.2.tar.gz", names)

    def test_windows_version_can_differ(self):
        names = release.expected_artifacts("0.24.2", windows_version="0.24.1")
        self.assertIn("XIO-Full-0.24.1-windows-x64.zip", names)
        self.assertEqual(release.windows_version_of("XIO-Full-0.24.1-windows-x64.zip"), "0.24.1")
        self.assertIsNone(release.windows_version_of("XIO-Full-0.24.2-android-arm64-v8a.apk"))

    def test_sums_name(self):
        self.assertEqual(release.sums_name("0.24.2"), "SHA256SUMS-0.24.2.txt")
        self.assertEqual(release.sums_name("v0.24.2"), "SHA256SUMS-0.24.2.txt")


class InventoryTests(unittest.TestCase):
    def test_complete_release_with_older_windows_zip(self):
        names = [name.replace("0.24.2-windows", "0.24.1-windows") for name in release.expected_artifacts("0.24.2")]
        names.append(release.sums_name("0.24.2"))
        inventory = release.classify_artifacts(names, "0.24.2")
        self.assertEqual(inventory.missing, [])
        self.assertEqual(len(inventory.found), 9)
        self.assertEqual(inventory.windows_versions, ["0.24.1"])
        self.assertTrue(inventory.complete)

    def test_missing_and_unexpected_files(self):
        names = release.expected_artifacts("0.24.2")
        names.remove("xio-server-0.24.2.tar.gz")
        names.append("XIO-0.24.2-ubuntu-arm64.deb")
        names.append("notes.txt")
        names.append(".DS_Store")
        inventory = release.classify_artifacts(names, "0.24.2")
        self.assertEqual(inventory.missing, ["xio-server-0.24.2.tar.gz"])
        self.assertEqual(inventory.unexpected, ["XIO-0.24.2-ubuntu-arm64.deb"])
        self.assertFalse(inventory.complete)

    def test_foreign_and_related_asset_matching(self):
        self.assertTrue(release.is_release_asset("SHA256SUMS-0.24.2.txt"))
        self.assertTrue(release.is_release_asset("XIO-Full-0.24.1-windows-x64.zip"))
        self.assertTrue(release.is_release_asset("XIO-Client-0.24.2-android-universal.apk"))
        self.assertTrue(release.is_release_asset("xio-server-0.24.2.tar.gz"))
        self.assertFalse(release.is_release_asset("screenshot.png"))
        self.assertFalse(release.is_release_asset("XIO-0.24.2.tar.gz"))


class SumsParsingTests(unittest.TestCase):
    def test_valid_file(self):
        text = f"{SHA_A}  XIO-0.24.2-ubuntu-amd64.deb\n{SHA_B}  xio-server-0.24.2.tar.gz\n"
        parsed = release.parse_sums(text)
        self.assertEqual(
            parsed,
            {"XIO-0.24.2-ubuntu-amd64.deb": SHA_A, "xio-server-0.24.2.tar.gz": SHA_B},
        )

    def test_crlf_comments_blank_lines_and_uppercase(self):
        text = (
            "# суммы выпуска\r\n"
            "\r\n"
            f"{SHA_A.upper()}  XIO-0.24.2-ubuntu-amd64.deb\r\n"
            "   \n"
        )
        parsed = release.parse_sums(text)
        self.assertEqual(parsed, {"XIO-0.24.2-ubuntu-amd64.deb": SHA_A})

    def test_duplicates_rejected(self):
        text = f"{SHA_A}  file.deb\n{SHA_B}  file.deb\n"
        with self.assertRaises(release.SumsError):
            release.parse_sums(text)

    def test_broken_lines_rejected(self):
        bad_lines = [
            "abc  file.deb",  # короткий хеш
            f"{SHA_A}\n",  # нет имени
            f"{SHA_A}  dir/file.deb\n",  # путь вместо имени
            f"{'z' * 64}  file.deb\n",  # не hex
        ]
        for line in bad_lines:
            with self.subTest(line=line), self.assertRaises(release.SumsError):
                release.parse_sums(line)

    def test_render_is_sorted_lf_with_trailing_newline(self):
        text = release.render_sums({"b.deb": SHA_B, "a.deb": SHA_A})
        self.assertEqual(text, f"{SHA_A}  a.deb\n{SHA_B}  b.deb\n")
        self.assertNotIn("\r", text)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(release.render_sums({}), "")

    def test_roundtrip(self):
        original = {"XIO-0.24.2-ubuntu-x64.tar.gz": SHA_B, "XIO-Full-0.24.1-windows-x64.zip": SHA_A}
        self.assertEqual(release.parse_sums(release.render_sums(original)), original)


class DigestTests(unittest.TestCase):
    def test_sha256_of_known_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "abc.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                release.sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )
            self.assertEqual(release.file_digest(path)[1], 3)

    def test_digest_problems_clean(self):
        self.assertEqual(release.digest_problems(SHA_A, 10, SHA_A, 10), [])

    def test_digest_problems_detects_sha_and_size(self):
        problems = release.digest_problems(SHA_A, 10, SHA_B, 11)
        self.assertEqual(len(problems), 2)
        self.assertIn("sha256", problems[0])
        self.assertIn("размер", problems[1])

    def test_digest_problems_size_optional(self):
        self.assertEqual(release.digest_problems(SHA_A, None, SHA_A, 5), [])
        self.assertEqual(release.digest_problems(SHA_A, 5, SHA_A, None), [])


class AssetPlanTests(unittest.TestCase):
    def test_upload_keep_and_replace(self):
        local = {
            "a.deb": (SHA_A, 10),
            "b.deb": (SHA_A, 20),
            "c.deb": (SHA_A, 30),
        }
        remote = {
            "b.deb": (SHA_A, 20),  # совпало
            "c.deb": (SHA_B, 30),  # digest разошёлся
        }
        plan = release.asset_plan(local, remote)
        self.assertEqual(plan.upload, ["a.deb"])  # ассета нет в релизе
        self.assertEqual(plan.keep, ["b.deb"])
        self.assertEqual(plan.replace, ["c.deb"])
        self.assertIn("sha256", plan.reasons["c.deb"])

    def test_size_mismatch_forces_replace(self):
        plan = release.asset_plan({"a.deb": (SHA_A, 10)}, {"a.deb": (SHA_A, 11)})
        self.assertEqual(plan.replace, ["a.deb"])
        self.assertIn("размер", plan.reasons["a.deb"])

    def test_missing_remote_digest_forces_replace(self):
        plan = release.asset_plan({"a.deb": (SHA_A, 10)}, {"a.deb": (None, 10)})
        self.assertEqual(plan.replace, ["a.deb"])
        self.assertEqual(plan.keep, [])

    def test_orphan_and_foreign_assets(self):
        local = {"a.deb": (SHA_A, 10)}
        remote = {
            "a.deb": (SHA_A, 10),
            "SHA256SUMS-0.23.0.txt": (SHA_B, 5),
            "XIO-Full-0.23.0-windows-x64.zip": (SHA_B, 5),
            "photo.jpg": (SHA_B, 5),
        }
        plan = release.asset_plan(local, remote)
        self.assertEqual(plan.keep, ["a.deb"])
        self.assertEqual(plan.remove, ["SHA256SUMS-0.23.0.txt", "XIO-Full-0.23.0-windows-x64.zip"])
        self.assertEqual(plan.foreign, ["photo.jpg"])
        self.assertFalse(plan.is_empty)

    def test_empty_plan_when_everything_matches(self):
        local = {"a.deb": (SHA_A, 10)}
        plan = release.asset_plan(local, {"a.deb": (SHA_A, 10)})
        self.assertTrue(plan.is_empty)
        self.assertEqual(plan.keep, ["a.deb"])


class ApksignerTests(unittest.TestCase):
    REAL_OUTPUT = (
        "Verifies\n"
        "Verified using v1 scheme (JAR signing): true\n"
        "Verified using v2 scheme (APK Signature Scheme v2): true\n"
        "Verified using v3 scheme (APK Signature Scheme v3): false\n"
        "Number of signers: 1\n"
        "Signer #1 certificate DN: CN=x1o Development, O=x1o\n"
        "Signer #1 certificate SHA-256 digest: e4e81b12ec90709133f5d2be4c4071ab83c55a764aa54dbfc7dce5b2bffc9671\n"
        "Signer #1 certificate SHA-1 digest: c036cad71dc23cfd87e38104d65533cffb329460\n"
    )

    def test_parses_certificate_and_v2(self):
        certs = release.parse_apksigner_cert(self.REAL_OUTPUT)
        self.assertEqual(certs, [release.CERT_SHA256])
        self.assertIs(release.parse_apksigner_v2(self.REAL_OUTPUT), True)
        self.assertEqual(release.CERT_SHORT, "e4e81b12…c9671")
        self.assertTrue(release.CERT_SHA256.startswith("e4e81b12"))
        self.assertTrue(release.CERT_SHA256.endswith("c9671"))

    def test_clean_output_has_no_problems(self):
        self.assertEqual(release.signature_problems(self.REAL_OUTPUT, 0), [])

    def test_wrong_certificate_detected(self):
        other = self.REAL_OUTPUT.replace(release.CERT_SHA256, "f" * 64)
        problems = release.signature_problems(other, 0)
        self.assertEqual(len(problems), 1)
        self.assertIn("сертификат", problems[0])

    def test_failed_verify_and_missing_v2(self):
        no_v2 = self.REAL_OUTPUT.replace("v2 scheme (APK Signature Scheme v2): true", "v2 scheme (APK Signature Scheme v2): false")
        problems = release.signature_problems(no_v2, 1)
        self.assertTrue(any("код 1" in problem for problem in problems))
        self.assertTrue(any("v2" in problem for problem in problems))
        empty = release.signature_problems("", 0)
        self.assertTrue(any("Signer" in problem for problem in empty))


class DownloadUrlTests(unittest.TestCase):
    def test_asset_url(self):
        url = release.download_url("rukazax/xio_vpn", "v0.24.2", "XIO-0.24.2-ubuntu-amd64.deb")
        self.assertEqual(
            url,
            "https://github.com/rukazax/xio_vpn/releases/download/v0.24.2/XIO-0.24.2-ubuntu-amd64.deb",
        )

    def test_remote_map_reads_github_digest(self):
        assets = [
            {"name": "a.deb", "size": 10, "digest": "sha256:" + SHA_A},
            {"name": "b.deb", "size": 20, "digest": None},
        ]
        self.assertEqual(
            release.remote_map(assets),
            {"a.deb": (SHA_A, 10), "b.deb": (None, 20)},
        )
        self.assertEqual(release.asset_id_by_name(assets), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
