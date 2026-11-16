#!/usr/bin/env python3
"""Identity-pinned, collect-only Android evidence. No install/focus/screenshot API.

Exercise mode records OPERATOR observations, not a claim that VPN traffic passed.
Only exercise mode may restore airplane/WiFi; a radio cycle needs a second flag.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import queue
import re
import signal
import subprocess
import tempfile
import threading
import time


class Rejected(RuntimeError):
    """A safe, fixed diagnostic; never include raw adb/tool output."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True)
class Expected:
    package: str
    version_code: int
    apk_sha256: str
    cert_sha256: str
    serial: str = "909f194a"

    def __post_init__(self):
        if self.package not in {"app.xio.xio", "app.xio.client"}:
            raise Rejected("Only the Full or Client package is supported")
        if self.version_code < 1 or not re.fullmatch(r"[A-Za-z0-9_-]+", self.serial):
            raise Rejected("Invalid expected version or serial")
        for digest in (self.apk_sha256, self.cert_sha256):
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise Rejected("Pins must be exact lowercase SHA256 hex digests")


class Runner:
    def run(self, args: list[str], timeout: float = 15) -> str:
        try:
            result = subprocess.run(args, capture_output=True, timeout=timeout,
                                    check=False, encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            raise Rejected("Tool unavailable or timed out") from None
        if result.returncode != 0:
            raise Rejected("Tool command failed (raw output withheld)")
        return result.stdout


class Device:
    def __init__(self, runner: Runner, adb: str, expected: Expected):
        self.runner, self.adb, self.expected = runner, adb, expected
        self.exercise_armed = False

    def call(self, *args: str, timeout: float = 15) -> str:
        return self.runner.run([self.adb, "-s", self.expected.serial, *args], timeout)

    def shell(self, *args: str) -> str:
        return self.call("shell", *args)

    def settings(self) -> dict[str, int]:
        result = {}
        for key in ("airplane_mode_on", "wifi_on"):
            value = self.shell("settings", "get", "global", key).strip()
            if value not in {"0", "1"}:
                raise Rejected("Radio settings are unavailable or not stable 0/1")
            result[key] = int(value)
        return result

    def wifi_state(self) -> dict[str, bool]:
        # cmd wifi may print SSID/BSSID/IP; never retain that text or those fields.
        raw = self.shell("cmd", "wifi", "status")
        match = re.search(r"^Wifi is (enabled|disabled)\s*$", raw, re.M)
        if not match:
            raise Rejected("WiFi runtime state is unavailable")
        enabled = match[1] == "enabled"
        associated = bool(re.search(r"^Wifi is connected to .+", raw, re.M))
        if enabled and not associated and not re.search(r"^Wifi is (not connected|disconnected)\s*$", raw, re.M):
            raise Rejected("WiFi association state is unavailable")
        return {"enabled": enabled, "associated": associated}

    def airplane(self, enabled: int):
        if not self.exercise_armed:
            raise Rejected("Radio mutation is not armed")
        self.shell("cmd", "connectivity", "airplane-mode", "enable" if enabled else "disable")

    def wifi(self, enabled: int):
        if not self.exercise_armed:
            raise Rejected("Radio mutation is not armed")
        self.shell("svc", "wifi", "enable" if enabled else "disable")


def inspect_apk(path: Path, expected: Expected, runner: Runner,
                aapt: str, apksigner: str):
    # Hash first: wrong/stale files never cause an adb command or device mutation.
    if sha256(path) != expected.apk_sha256:
        raise Rejected("APK SHA256 differs from the final signed artifact pin")
    badging = runner.run([aapt, "dump", "badging", str(path)], 30)
    matches = re.findall(r"^package: name='([^']+)' versionCode='([0-9]+)'", badging, re.M)
    if matches != [(expected.package, str(expected.version_code))]:
        raise Rejected("APK package/versionCode differs from the expected identity")
    signing = runner.run([apksigner, "verify", "--verbose", "--print-certs", str(path)], 30)
    certs = re.findall(r"^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})\s*$",
                       signing, re.M)
    if len(certs) != 1 or certs[0].lower() != expected.cert_sha256:
        raise Rejected("APK signer differs from the single expected certificate")


def identity_gate(apk: Path, expected: Expected, device: Device,
                  aapt: str, apksigner: str, scratch: Path) -> int:
    inspect_apk(apk, expected, device.runner, aapt, apksigner)
    if device.call("get-state").strip() != "device":
        raise Rejected("Authorized target device is not available")
    if device.call("get-serialno").strip() != expected.serial:
        raise Rejected("Device serial differs from the explicit target")
    package = device.shell("dumpsys", "package", expected.package)
    versions = set(re.findall(r"\bversionCode=([0-9]+)\b", package))
    uids = set(re.findall(r"\buserId=([0-9]+)\b", package))
    if versions != {str(expected.version_code)} or len(uids) != 1:
        raise Rejected("Installed package version/UID is missing or differs")
    uid = int(next(iter(uids)))
    if not 10000 <= uid < 200000:
        raise Rejected("Expected an ordinary app UID")
    owners = device.shell("cmd", "package", "list", "packages", "--uid", str(uid))
    if owners.strip().splitlines() != ["package:" + expected.package]:
        raise Rejected("App UID is shared or cannot be isolated for logs")
    paths = device.shell("pm", "path", "--user", "0", expected.package).strip().splitlines()
    if len(paths) != 1 or not paths[0].startswith("package:"):
        raise Rejected("Require one monolithic installed APK; split APKs are unsupported")
    remote = paths[0][len("package:"):]
    if ".." in remote.split("/") or not re.fullmatch(r"/data/app/[A-Za-z0-9_./+=~\-]+/base\.apk", remote):
        raise Rejected("Unexpected installed APK location")
    # APK only: never pull application data, profiles, preferences, keys or logs.
    with tempfile.TemporaryDirectory(prefix="installed-apk-", dir=scratch) as folder:
        installed = Path(folder) / "base.apk"
        device.call("pull", remote, str(installed), timeout=90)
        inspect_apk(installed, expected, device.runner, aapt, apksigner)
    return uid


class Evidence:
    def __init__(self, path: Path, expected: Expected, clock=time.monotonic):
        self.path, self.clock, self.started = path, clock, clock()
        self.data = {
            "schema": 1, "mode": "collect-only", "runtime_acceptance": "PENDING",
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "expected": {"package": expected.package, "version_code": expected.version_code,
                         "apk_sha256": expected.apk_sha256, "cert_sha256": expected.cert_sha256,
                         "device_id_sha256": hashlib.sha256(expected.serial.encode()).hexdigest()},
            "events": [],
        }

    def add(self, kind: str, **fields):
        self.data["events"].append({"elapsed_s": round(self.clock() - self.started, 4),
                                    "kind": kind, **fields})
        self.save()

    def save(self):
        # Fresh output directory is required by CLI. Never overwrite old evidence.
        temporary = self.path.with_suffix(".next")
        temporary.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)


def memory_sample(device: Device) -> list[dict]:
    text = device.shell("dumpsys", "meminfo", device.expected.package)
    rows = []
    for block in re.split(r"(?=\*\* MEMINFO in pid )", text):
        match = re.match(r"\*\* MEMINFO in pid ([0-9]+) \[([^\]]+)\] \*\*", block)
        if not match:
            continue
        pid, name = match.groups()
        if name != device.expected.package and not name.startswith(device.expected.package + ":"):
            raise Rejected("Memory dump included a different app")
        pss = re.findall(r"^\s*TOTAL PSS:\s*([0-9]+)\b", block, re.M)
        if not pss:  # Older Android table, whose first numeric TOTAL column is PSS.
            pss = re.findall(r"^\s*TOTAL\s+([0-9]+)\s+", block, re.M)
        if len(pss) != 1:
            raise Rejected("App PSS unavailable; do not substitute system-wide RAM")
        rows.append({"pid": int(pid), "pss_kib": int(pss[0])})
    if len({row["pid"] for row in rows}) != len(rows):
        raise Rejected("Duplicate process PSS entries")
    if not rows and text.strip() != "No process found for: " + device.expected.package:
        raise Rejected("Unrecognized memory output; app absence is not proven")
    return rows


# Entire messages must match. Never retain arbitrary native/Flutter text or URLs.
SAFE_MESSAGES = {
    "verification complete": "native_verification_complete",
    "controller complete": "native_controller_complete",
    "controller created": "native_controller_created",
}
PROTOCOL_PREFIXES = {"wg", "awg", "rvh", "rvs", "xr", "ss", "ov", "ik", "ck", "ts"}


def filtered_events(text: str, pid: int, since_epoch: float) -> list[dict]:
    events = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([0-9]+\.[0-9]+)\s+([0-9]+)\s+[0-9]+\s+[IWE]\s+"
                             r"(XIO/Tile|XIO/Connect|XIO/Network)\s*:\s*(.*?)\s*", line)
        if not match:
            continue
        epoch, observed_pid, tag, message = match.groups()
        if int(observed_pid) != pid or float(epoch) < since_epoch:
            continue
        event = None
        if tag == "XIO/Tile" and message in SAFE_MESSAGES:
            event = {"event": SAFE_MESSAGES[message]}
        elif tag == "XIO/Tile" and message.startswith("candidate="):
            prefix = message[len("candidate="):]
            if prefix in PROTOCOL_PREFIXES:
                event = {"event": "native_candidate", "protocol_prefix": prefix}
        elif tag == "XIO/Network" and re.fullmatch(r"VPN route ready in [0-9]+ms", message):
            event = {"event": "native_route_ready"}
        elif tag == "XIO/Connect":
            failed = re.fullmatch(r"(awg|wireguard|xray|cloak|rivet-h3|rivet-s1) attempt failed: "
                                  r"[A-Za-z][A-Za-z0-9]{0,63}Exception", message)
            if failed:
                event = {"event": "native_attempt_failed", "protocol": failed[1]}
        if event:
            events.append({"device_epoch_s": float(epoch), **event})
    return events


def collect(device: Device, uid: int, evidence: Evidence, samples: int, interval: float,
            sleep=time.sleep, since_epoch: float | None = None) -> float:
    if since_epoch is None:
        since = device.shell("date", "+%s").strip()
        if not re.fullmatch(r"[0-9]{10,}", since):
            raise Rejected("Device time unavailable for log boundary")
        since_epoch = float(since)
    for index in range(samples):
        rows = memory_sample(device)
        evidence.add("app_memory", processes=rows, total_pss_kib=sum(r["pss_kib"] for r in rows),
                     running=bool(rows))
        for row in rows:
            # Both UID and PID scoped; raw output lives only in memory and is discarded.
            output = device.call("logcat", "-d", "-v", "epoch", "--uid=" + str(uid),
                                 "--pid=" + str(row["pid"]), "-t", "200", "-s",
                                 "XIO/Tile:I", "XIO/Connect:W", "XIO/Network:I", "*:S")
            for event in filtered_events(output, row["pid"], since_epoch):
                fields = {"pid": row["pid"], **event}
                if not any(item["kind"] == "app_log" and all(item.get(k) == v for k, v in fields.items())
                           for item in evidence.data["events"]):
                    evidence.add("app_log", **fields)
        if index + 1 < samples:
            sleep(interval)
    return since_epoch


def restore(device: Device, prior: dict[str, int], evidence: Evidence, sleep=time.sleep,
            network_prior: dict[str, bool] | None = None):
    # Restoration is permitted after exercise is armed even if identity later fails.
    # Attempt BOTH settings independently on each retry, including on command errors.
    def restored():
        return device.settings() == prior and (network_prior is None or device.wifi_state() == network_prior)

    for _ in range(30):
        try:
            if restored():
                evidence.add("radio_restored", verified=True, wifi_state_checked=network_prior is not None)
                return
        except Exception:
            pass
        for action, value in ((device.airplane, prior["airplane_mode_on"]),
                              (device.wifi, prior["wifi_on"])):
            try:
                action(value)
            except Exception:
                pass
        try:
            if restored():
                evidence.add("radio_restored", verified=True, wifi_state_checked=network_prior is not None)
                return
        except Exception:
            pass
        sleep(0.5)
    evidence.add("radio_restore_failed", verified=False, recovery=prior)
    raise Rejected("Radio restoration not confirmed; use the saved recovery journal")


def timed_input(prompt: str, timeout: float) -> str:
    answers = queue.Queue()

    def read():
        try:
            answers.put(input(prompt))
        except (EOFError, OSError):
            answers.put(None)

    threading.Thread(target=read, daemon=True).start()
    try:
        answer = answers.get(timeout=timeout)
    except queue.Empty:
        raise Rejected("Operator observation timed out") from None
    if answer is None:
        raise Rejected("Operator input unavailable")
    return answer


def exercise(device: Device, evidence: Evidence, *, enabled: bool = False,
             airplane_cycle: bool = False, ask=timed_input, sleep=time.sleep,
             clock=time.monotonic, verify_identity=None, observe=None):
    if not enabled:
        raise Rejected("Exercise requires explicit --exercise opt-in")
    if ask("Type EXERCISE to permit manual VPN tests and airplane/WiFi restoration: ", 30) != "EXERCISE":
        raise Rejected("Exercise consent not given")
    prior = device.settings()  # Refuse before mutation if recovery state is unknown.
    network_prior = device.wifi_state()
    if network_prior["enabled"] != bool(prior["wifi_on"]):
        raise Rejected("WiFi is transitioning; retry after it stabilizes")
    if airplane_cycle and prior["airplane_mode_on"]:
        raise Rejected("Cannot test an airplane transition while airplane mode is already on")
    if verify_identity is None:
        raise Rejected("Exercise requires an exact installed-APK identity recheck")
    verify_identity()  # After consent prompt, before arming any mutation/restoration.
    evidence.data["mode"] = "exercise-observations"
    evidence.add("radio_recovery_journal", prior=prior, prior_wifi_state=network_prior)
    device.exercise_armed = True
    try:
        if airplane_cycle:
            evidence.add("airplane_cycle_start")
            device.airplane(1)
            sleep(3)
            if device.settings()["airplane_mode_on"] != 1:
                raise Rejected("Airplane cycle was not applied")
            evidence.add("airplane_cycle_held", airplane_on=True)
            # Restore before waiting for a person; never leave radios off at a prompt.
            restore(device, prior, evidence, sleep, network_prior)
            evidence.add("airplane_cycle_end")
        for action in ("disconnect", "connect", "fallback"):
            if ask(f"Prepare the authorized {action} test; type READY (no action yet): ", 30) != "READY":
                raise Rejected("Observation cancelled")
            verify_identity()
            if observe is not None:
                observe()
            started = clock()
            evidence.add("operator_action_start", action=action)
            answer = ask(f"Perform {action} in XIO; type OBSERVED only after confirming its UI state: ", 30)
            elapsed = clock() - started
            within = 0 <= elapsed <= 30
            evidence.add("operator_observation", action=action, duration_s=round(elapsed, 4),
                         within_30s=within, confirmed=answer == "OBSERVED",
                         proof="operator_only_not_network_validation")
            if observe is not None:
                observe()
            if answer != "OBSERVED" or not within:
                raise Rejected("Transition was not observed within the 30 second budget")
    finally:
        try:
            restore(device, prior, evidence, sleep, network_prior)
        finally:
            device.exercise_armed = False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--package", required=True, choices=["app.xio.xio", "app.xio.client"])
    parser.add_argument("--version-code", required=True, type=int)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--cert-sha256", required=True)
    parser.add_argument("--serial", default="909f194a")
    parser.add_argument("--adb", required=True)
    parser.add_argument("--aapt", required=True)
    parser.add_argument("--apksigner", required=True)
    parser.add_argument("--out", required=True, type=Path, help="New, nonexisting output directory")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--exercise", action="store_true")
    parser.add_argument("--airplane-cycle", action="store_true")
    args = parser.parse_args(argv)
    if args.airplane_cycle and not args.exercise:
        parser.error("--airplane-cycle requires --exercise")
    if not 1 <= args.samples <= 120 or not 0.2 <= args.interval <= 60:
        parser.error("samples must be 1..120 and interval 0.2..60 seconds")
    try:
        expected = Expected(args.package, args.version_code, args.apk_sha256,
                            args.cert_sha256, args.serial)
        args.out.mkdir(parents=True, exist_ok=False)
    except (Rejected, OSError) as error:
        print(str(error) if isinstance(error, Rejected) else "Output must be a new writable directory")
        return 2
    evidence = Evidence(args.out / "evidence.json", expected)
    device = Device(Runner(), args.adb, expected)
    # SIGTERM as well as Ctrl+C uses the exercise finally restoration path.
    def interrupted(*_):
        raise KeyboardInterrupt
    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        uid = identity_gate(args.apk, expected, device, args.aapt, args.apksigner, args.out)
        evidence.add("identity_verified", verified_installed={
            "package": expected.package, "version_code": expected.version_code,
            "apk_sha256": expected.apk_sha256, "cert_sha256": expected.cert_sha256,
        })  # Emitted only after measurements of the pulled APK equal all pins.
        since = collect(device, uid, evidence, args.samples, args.interval)
        if args.exercise:
            exercise(device, evidence, enabled=True, airplane_cycle=args.airplane_cycle,
                     verify_identity=lambda: identity_gate(args.apk, expected, device,
                                                           args.aapt, args.apksigner, args.out),
                     observe=lambda: collect(device, uid, evidence, 1, args.interval,
                                             since_epoch=since))
        identity_gate(args.apk, expected, device, args.aapt, args.apksigner, args.out)
        evidence.add("collection_complete", final_identity_verified=True)
        print("Evidence collected. Final Android VPN acceptance remains PENDING.")
        return 0
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error) if isinstance(error, Rejected) else type(error).__name__
        evidence.add("run_rejected", reason=reason)
        print("Run rejected: " + reason)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    raise SystemExit(main())
