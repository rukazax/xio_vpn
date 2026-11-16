"""All adb/tool replies are MOCKS. These tests do not prove VPN operation."""
import contextlib
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import android_acceptance as aa


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class FakeRunner:
    """Reject all commands not explicitly modeled, including install/focus/screencap."""
    def __init__(self, expected, apk):
        self.expected, self.apk = expected, apk
        self.installed = apk.read_bytes()
        self.actual_serial = expected.serial
        self.local_package = self.installed_package = expected.package
        self.local_cert = self.installed_cert = expected.cert_sha256
        self.version = expected.version_code
        self.paths = ["package:/data/app/~~fixture/xio-test/base.apk"]
        self.uid_owners = ["package:" + expected.package]
        self.calls, self.mutations = [], []
        self.radio = {"airplane_mode_on": 0, "wifi_on": 1}
        self.fail_airplane_once = False
        self.fail_restoration = False
        self.meminfo = (f"** MEMINFO in pid 123 [{expected.package}] **\n"
                        " TOTAL PSS: 1200 TOTAL RSS: 2000\n"
                        f"** MEMINFO in pid 124 [{expected.package}:vpn] **\n"
                        " TOTAL PSS: 300 TOTAL RSS: 500\n")
        self.logs = ("1710000001.001 123 123 I XIO/Tile: verification complete\n"
                     "1710000001.002 123 123 I XIO/Tile: candidate=xr\n"
                     "1710000001.003 123 123 I XIO/Tile: privateKey=PRIVATE_SENTINEL\n"
                     "1710000001.004 999 999 I XIO/Tile: verification complete\n"
                     "1709999999.000 123 123 I XIO/Tile: controller complete\n"
                     "1710000001.005 123 123 I flutter: secret=PRIVATE_SENTINEL\n")

    def run(self, args, timeout=15):
        self.calls.append(args)
        if args[0] == "aapt":
            installed = Path(args[-1]).name == "base.apk"
            package = self.installed_package if installed else self.local_package
            version = self.version if installed else self.expected.version_code
            return f"package: name='{package}' versionCode='{version}' versionName='fixture'\n"
        if args[0] == "apksigner":
            cert = self.installed_cert if Path(args[-1]).name == "base.apk" else self.local_cert
            return "Signer #1 certificate SHA-256 digest: " + cert + "\n"
        assert args[:3] == ["adb", "-s", self.expected.serial], args
        command = args[3:]
        if command == ["get-state"]:
            return "device\n"
        if command == ["get-serialno"]:
            return self.actual_serial + "\n"
        if command[:1] == ["pull"]:
            Path(command[2]).write_bytes(self.installed)
            return "1 file pulled\n"
        if command[:1] == ["logcat"]:
            assert "--uid=10234" in command
            assert any(c.startswith("--pid=") for c in command)
            assert "-d" in command and "-c" not in command
            return self.logs
        assert command[0] == "shell", command
        shell = command[1:]
        if shell == ["dumpsys", "package", self.expected.package]:
            return f"userId=10234\n versionCode={self.version} minSdk=24\n key=PRIVATE_SENTINEL\n"
        if shell == ["cmd", "package", "list", "packages", "--uid", "10234"]:
            return "\n".join(self.uid_owners)
        if shell == ["pm", "path", "--user", "0", self.expected.package]:
            return "\n".join(self.paths)
        if shell == ["dumpsys", "meminfo", self.expected.package]:
            return self.meminfo
        if shell == ["date", "+%s"]:
            return "1710000000\n"
        if shell == ["cmd", "wifi", "status"]:
            return ("Wifi is enabled\nWifi is connected to PRIVATE_SSID_SENTINEL\n"
                    if self.radio["wifi_on"] else "Wifi is disabled\n")
        if shell[:3] == ["settings", "get", "global"]:
            return str(self.radio[shell[3]]) + "\n"
        if shell[:3] == ["cmd", "connectivity", "airplane-mode"]:
            self.mutations.append(shell)
            if self.fail_restoration and shell[-1] == "disable":
                raise aa.Rejected("injected radio restoration failure")
            self.radio["airplane_mode_on"] = int(shell[-1] == "enable")
            if self.fail_airplane_once:
                self.fail_airplane_once = False
                self.radio["wifi_on"] = 0  # Mutation happened before the command failed.
                raise aa.Rejected("injected post-mutation failure")
            return ""
        if shell[:2] == ["svc", "wifi"]:
            self.mutations.append(shell)
            self.radio["wifi_on"] = int(shell[-1] == "enable")
            return ""
        raise AssertionError("Unmodeled/forbidden command: " + repr(command))


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk = self.root / "final.apk"
        self.apk.write_bytes(b"MOCK final signed artifact, not an executable APK")
        self.expected = aa.Expected("app.xio.xio", 5020, aa.sha256(self.apk), "a" * 64)
        self.runner = FakeRunner(self.expected, self.apk)
        self.device = aa.Device(self.runner, "adb", self.expected)
        self.clock = Clock()
        self.evidence = aa.Evidence(self.root / "evidence.json", self.expected, self.clock)

    def gate(self):
        return aa.identity_gate(self.apk, self.expected, self.device, "aapt", "apksigner", self.root)

    def answers(self, duration=1, failure=None, change_radio=False):
        def ask(prompt, timeout):
            if "Type EXERCISE" in prompt:
                return "EXERCISE"
            if "type READY" in prompt:
                return "READY"
            if change_radio:
                self.runner.radio = {"airplane_mode_on": 1, "wifi_on": 0}
            self.clock.sleep(duration)
            if failure:
                raise failure
            return "OBSERVED"
        return ask

    def exercise(self, **kwargs):
        options = dict(enabled=True, verify_identity=self.gate, ask=self.answers(),
                       sleep=self.clock.sleep, clock=self.clock)
        options.update(kwargs)
        aa.exercise(self.device, self.evidence, **options)

    def test_full_and_client_exact_apk_gate(self):
        self.assertEqual(self.gate(), 10234)
        self.expected = replace(self.expected, package="app.xio.client")
        self.runner = FakeRunner(self.expected, self.apk)
        self.device = aa.Device(self.runner, "adb", self.expected)
        self.assertEqual(self.gate(), 10234)
        self.assertFalse(self.runner.mutations)
        self.assertEqual(list(self.root.glob("installed-apk-*")), [])

    def test_wrong_local_hash_rejects_before_any_adb(self):
        self.apk.write_bytes(b"old experimental5019")
        with self.assertRaises(aa.Rejected):
            self.gate()
        self.assertEqual(self.runner.calls, [])

    def test_wrong_local_package_or_certificate_rejects_before_adb(self):
        for field in ("local_package", "local_cert"):
            with self.subTest(field=field):
                runner = FakeRunner(self.expected, self.apk)
                setattr(runner, field, "wrong" if field == "local_package" else "b" * 64)
                device = aa.Device(runner, "adb", self.expected)
                with self.assertRaises(aa.Rejected):
                    aa.identity_gate(self.apk, self.expected, device, "aapt", "apksigner", self.root)
                self.assertFalse(any(call[0] == "adb" for call in runner.calls))

    def test_installed_identity_variants_fail_without_mutation(self):
        variants = {"installed": b"stale installed artifact", "version": 5019,
                    "installed_package": "app.xio.client", "installed_cert": "b" * 64,
                    "actual_serial": "other-device", "paths": [],
                    "uid_owners": ["package:app.xio.xio", "package:shared.other"]}
        for field, value in variants.items():
            with self.subTest(field=field):
                runner = FakeRunner(self.expected, self.apk)
                setattr(runner, field, value)
                device = aa.Device(runner, "adb", self.expected)
                with self.assertRaises(aa.Rejected):
                    aa.identity_gate(self.apk, self.expected, device, "aapt", "apksigner", self.root)
                self.assertFalse(runner.mutations)

    def test_split_installed_apk_is_rejected(self):
        self.runner.paths.append("package:/data/app/~~fixture/xio-test/split.apk")
        with self.assertRaises(aa.Rejected):
            self.gate()
        self.assertFalse(self.runner.mutations)

    def test_memory_app_only_sum_and_safe_log_redaction(self):
        self.gate()
        for _ in range(2):
            aa.collect(self.device, 10234, self.evidence, 1, 1, self.clock.sleep)
        data = json.loads(self.evidence.path.read_text())
        memory = [e for e in data["events"] if e["kind"] == "app_memory"]
        self.assertEqual(memory[0]["total_pss_kib"], 1500)
        self.assertEqual(len(memory[0]["processes"]), 2)
        logs = [e for e in data["events"] if e["kind"] == "app_log"]
        self.assertEqual(len(logs), 2)  # Repeated PID-scoped dumps are deduplicated.
        serialized = json.dumps(data)
        self.assertNotIn("PRIVATE_SENTINEL", serialized)
        self.assertNotIn(self.expected.serial, serialized)
        self.assertNotIn("999", serialized)
        self.assertFalse(self.runner.mutations)

    def test_memory_foreign_process_and_unknown_pss_rejected(self):
        for text in ("** MEMINFO in pid 1 [other.app] **\n TOTAL PSS: 10\n",
                     "** MEMINFO in pid 123 [app.xio.xio] **\n UNKNOWN\n"):
            self.runner.meminfo = text
            with self.assertRaises(aa.Rejected):
                aa.memory_sample(self.device)

    def test_missing_process_never_launches_app(self):
        self.runner.meminfo = "No process found for: app.xio.xio\n"
        aa.collect(self.device, 10234, self.evidence, 1, 1)
        self.assertFalse(self.evidence.data["events"][-1]["running"])
        self.assertEqual(self.evidence.data["runtime_acceptance"], "PENDING")
        self.assertFalse(self.runner.mutations)

    def test_exercise_requires_explicit_optin_and_identity_recheck(self):
        for enabled in (False, True):
            with self.assertRaises(aa.Rejected):
                aa.exercise(self.device, self.evidence, enabled=enabled, ask=self.answers())
        self.assertFalse(self.runner.mutations)

    def test_stale_apk_after_consent_cannot_arm_radio_cycle(self):
        self.runner.installed = b"stale"
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        self.assertFalse(self.runner.mutations)
        self.assertFalse(any(e["kind"] == "radio_recovery_journal"
                             for e in self.evidence.data["events"]))

    def test_all_manual_observations_at_30s_are_not_vpn_pass(self):
        observations = []
        self.exercise(ask=self.answers(duration=30), observe=lambda: observations.append(self.clock()))
        recorded = [e for e in self.evidence.data["events"] if e["kind"] == "operator_observation"]
        self.assertEqual([e["action"] for e in recorded], ["disconnect", "connect", "fallback"])
        self.assertTrue(all(e["within_30s"] for e in recorded))
        self.assertEqual(len(observations), 6)
        self.assertEqual(self.evidence.data["runtime_acceptance"], "PENDING")
        self.assertFalse(self.runner.mutations)  # No gratuitous writes if radios are unchanged.

    def test_30s_excess_is_rejected_and_prior_radios_restored(self):
        with self.assertRaises(aa.Rejected):
            self.exercise(ask=self.answers(duration=30.001, change_radio=True))
        self.assertEqual(self.runner.radio, {"airplane_mode_on": 0, "wifi_on": 1})
        event = next(e for e in self.evidence.data["events"] if e["kind"] == "operator_observation")
        self.assertFalse(event["within_30s"])
        self.assertTrue(self.evidence.data["events"][-1]["verified"])

    def test_airplane_cycle_restores_before_operator_observation(self):
        prior = self.runner.radio.copy()
        base_ask = self.answers()
        def ask(prompt, timeout):
            self.assertEqual(self.runner.radio, prior)
            return base_ask(prompt, timeout)
        self.exercise(airplane_cycle=True, ask=ask)
        self.assertEqual(self.runner.radio, prior)
        kinds = [e["kind"] for e in self.evidence.data["events"]]
        self.assertLess(kinds.index("radio_recovery_journal"), kinds.index("airplane_cycle_start"))
        self.assertLess(kinds.index("radio_restored"), kinds.index("operator_action_start"))

    def test_restore_on_adb_failure_after_mutation(self):
        self.runner.fail_airplane_once = True
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        self.assertEqual(self.runner.radio, {"airplane_mode_on": 0, "wifi_on": 1})

    def test_restore_on_timeout_interrupt_and_observer_failure(self):
        for failure in (aa.Rejected("timeout"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(type(failure)):
                    self.exercise(ask=self.answers(failure=failure, change_radio=True))
                self.assertEqual(self.runner.radio, {"airplane_mode_on": 0, "wifi_on": 1})
        def observer():
            self.runner.radio["wifi_on"] = 0
            raise aa.Rejected("injected observer failure")
        with self.assertRaises(aa.Rejected):
            self.exercise(observe=observer)
        self.assertEqual(self.runner.radio["wifi_on"], 1)

    def test_prior_airplane_on_and_wifi_off_are_preserved(self):
        self.runner.radio = {"airplane_mode_on": 1, "wifi_on": 0}
        self.exercise()
        self.assertEqual(self.runner.radio, {"airplane_mode_on": 1, "wifi_on": 0})
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        self.assertFalse(self.runner.mutations)

    def test_unrestorable_device_fails_and_preserves_recovery_journal(self):
        self.runner.fail_restoration = True
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        events = self.evidence.data["events"]
        self.assertTrue(any(e["kind"] == "radio_recovery_journal" for e in events))
        self.assertEqual(events[-1]["kind"], "radio_restore_failed")
        self.assertTrue(any(c[:2] == ["svc", "wifi"] for c in self.runner.mutations))

    def test_cli_default_collect_only_has_no_mutation_focus_or_capture(self):
        out = self.root / "cli-output"
        args = ["--apk", str(self.apk), "--package", self.expected.package,
                "--version-code", str(self.expected.version_code),
                "--apk-sha256", self.expected.apk_sha256, "--cert-sha256", self.expected.cert_sha256,
                "--adb", "adb", "--aapt", "aapt", "--apksigner", "apksigner",
                "--samples", "1", "--out", str(out)]
        with patch.object(aa, "Runner", return_value=self.runner), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(aa.main(args), 0)
        self.assertFalse(self.runner.mutations)
        data = json.loads((out / "evidence.json").read_text())
        self.assertEqual(data["mode"], "collect-only")
        self.assertEqual(data["events"][0]["verified_installed"]["apk_sha256"], self.expected.apk_sha256)
        self.assertEqual(data["events"][0]["verified_installed"]["cert_sha256"], self.expected.cert_sha256)
        self.assertEqual(data["runtime_acceptance"], "PENDING")
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(data))
        self.assertFalse(list(out.glob("installed-apk-*")))

    def test_radio_methods_are_disarmed_by_default_and_after_failure(self):
        for mutate in (self.device.airplane, self.device.wifi):
            with self.assertRaises(aa.Rejected):
                mutate(1)
        self.assertEqual(self.runner.calls, [])
        self.runner.fail_airplane_once = True
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        self.assertFalse(self.device.exercise_armed)
        self.assertEqual(self.runner.radio, {"airplane_mode_on": 0, "wifi_on": 1})

    def test_only_strict_native_attempt_failure_is_retained(self):
        events = aa.filtered_events(
            "1710000001.1 123 123 W XIO/Connect: xray attempt failed: TimeoutException\n"
            "1710000001.2 123 123 W XIO/Connect: xray attempt failed: IOException PRIVATE_SENTINEL\n",
            123, 1710000000)
        self.assertEqual(events, [{"device_epoch_s": 1710000001.1,
                                   "event": "native_attempt_failed", "protocol": "xray"}])

    def test_apk_remote_path_traversal_is_rejected(self):
        self.runner.paths = ["package:/data/app/../private/base.apk"]
        with self.assertRaises(aa.Rejected):
            self.gate()
        self.assertFalse(any("pull" in call for call in self.runner.calls))
        self.assertFalse(self.runner.mutations)

    def test_unstable_radio_refused_before_mutation(self):
        self.runner.radio["wifi_on"] = 2
        with self.assertRaises(aa.Rejected):
            self.exercise(airplane_cycle=True)
        self.assertFalse(self.runner.mutations)

    def test_foreign_wifi_details_are_not_persisted_during_exercise(self):
        self.exercise(airplane_cycle=True)
        serialized = self.evidence.path.read_text()
        self.assertNotIn("PRIVATE_SSID_SENTINEL", serialized)
        self.assertNotIn("PRIVATE_SENTINEL", serialized)
        journal = next(e for e in self.evidence.data["events"] if e["kind"] == "radio_recovery_journal")
        self.assertEqual(journal["prior_wifi_state"], {"enabled": True, "associated": True})

    def test_unrecognized_memory_output_is_not_claimed_as_zero_usage(self):
        self.runner.meminfo = "Unexpected global RAM totals or new Android format"
        with self.assertRaises(aa.Rejected):
            aa.memory_sample(self.device)

    def test_multiple_signers_and_unsigned_apks_are_rejected(self):
        for signing in ("", "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n"
                        + "Signer #2 certificate SHA-256 digest: " + "a" * 64 + "\n"):
            runner = FakeRunner(self.expected, self.apk)
            original = runner.run
            def run(args, timeout=15):
                return signing if args[0] == "apksigner" else original(args, timeout)
            runner.run = run
            with self.assertRaises(aa.Rejected):
                aa.inspect_apk(self.apk, self.expected, runner, "aapt", "apksigner")
            self.assertFalse(any(c[0] == "adb" for c in runner.calls))

    def test_tool_failures_do_not_echo_sensitive_output(self):
        with patch.object(aa.subprocess, "run", return_value=aa.subprocess.CompletedProcess(
                ["tool"], 1, "PRIVATE_SENTINEL", "PRIVATE_SENTINEL")):
            with self.assertRaises(aa.Rejected) as rejected:
                aa.Runner().run(["tool"])
        self.assertNotIn("PRIVATE_SENTINEL", str(rejected.exception))

    def test_airplane_cycle_without_exercise_fails_before_device_access(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as rejected:
            aa.main(["--apk", str(self.apk), "--package", self.expected.package,
                     "--version-code", "5020", "--apk-sha256", self.expected.apk_sha256,
                     "--cert-sha256", self.expected.cert_sha256, "--adb", "adb", "--aapt", "aapt",
                     "--apksigner", "apksigner", "--out", str(self.root / "not-created"), "--airplane-cycle"])
        self.assertEqual(rejected.exception.code, 2)
        self.assertEqual(self.runner.calls, [])
        self.assertFalse((self.root / "not-created").exists())

    def test_bad_pins_cannot_accept_experimental_identity(self):
        for package, digest in (("other.app", "a" * 64), ("app.xio.xio", "33c911...")):
            with self.assertRaises(aa.Rejected):
                aa.Expected(package, 5020, digest, "a" * 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
