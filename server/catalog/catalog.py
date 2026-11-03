#!/usr/bin/env python3
"""XIO whitelist catalog builder (schema 1).

Builds ``whitelist-<YYYYMMDD>.json`` from the pinned public SNI source, probes every
name from the XIO server itself and writes the artifact atomically.

Exit codes (contract §10):
  0 ok, 2 source unavailable, 3 source sha256 != pin (or pin missing),
  4 threshold/budget, 5 write, rollback or signature error.

Only the standard library is used. Network probing is isolated in ``probe_entry`` so
tests can replace it.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

SCHEMA = 1
SOURCE_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"
COMMIT_API = "https://api.github.com/repos/hxehex/russia-mobile-internet-whitelist/commits?path=whitelist.txt&per_page=1"
ALLOWED_HOSTS = {"raw.githubusercontent.com", "api.github.com"}

LIMIT_BYTES = 5 * 1024 * 1024
LIMIT_LINES = 20_000
MAX_NAME = 253
PROBE_TIMEOUT = 3.0
RUN_BUDGET_S = 15 * 60
MIN_ELIGIBLE = 10
MIN_RATIO = 0.01

EXIT_OK = 0
EXIT_SOURCE = 2
EXIT_PIN = 3
EXIT_THRESHOLD = 4
EXIT_IO = 5

REJECT_REASONS = (
    "invalidEntry",
    "unresolved",
    "unreachable",
    "certInvalid",
    "certMismatch",
    "tls12Only",
)

DEFAULT_DIR = Path(__file__).resolve().parent
PINS_NAME = "whitelist-pins.json"
STATE_NAME = "whitelist-state.json"
PREVIOUS_NAME = "whitelist-previous.json"
LOCK_PATH = Path("/run/lock/xio-catalog.lock")


class CatalogError(Exception):
    """Failure that maps to a documented exit code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Entry:
    fqdn: str
    eligible: bool = False
    reject_reason: str | None = None
    resolved: list[str] = field(default_factory=list)
    tls13: bool | None = None
    cert_sha256: str | None = None
    cert_not_after: str | None = None
    tls_rtt_ms: int | None = None

    def as_json(self) -> dict:
        return {
            "fqdn": self.fqdn,
            "eligible": self.eligible,
            "rejectReason": self.reject_reason,
            "resolved": list(self.resolved),
            "tls13": self.tls13,
            "certSha256": self.cert_sha256,
            "certNotAfter": self.cert_not_after,
            "tlsRttMs": self.tls_rtt_ms,
        }


# --------------------------------------------------------------------------- input


def normalize_name(line: str) -> tuple[str | None, str | None]:
    """Return the A-label form of ``line`` or ``(None, reason)``.

    Stage 0 of contract §4: length, characters, no wildcard, port, spaces or
    trailing dot; the value is normalised to an IDNA A-label.
    """
    text = line.strip()
    if not text:
        return None, "invalidEntry"
    if len(text) > MAX_NAME:
        return None, "invalidEntry"
    if text.endswith("."):
        return None, "invalidEntry"
    lowered = text.lower()
    for bad in ("*", "/", ":", " ", "\t", "@"):
        if bad in lowered:
            return None, "invalidEntry"
    try:
        ascii_name = lowered.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None, "invalidEntry"
    if not ascii_name or len(ascii_name) > MAX_NAME:
        return None, "invalidEntry"
    labels = ascii_name.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return None, "invalidEntry"
    for label in labels:
        if label[0] == "-" or label[-1] == "-" or len(label) > 63:
            return None, "invalidEntry"
        if not all(ch.isalnum() or ch == "-" for ch in label):
            return None, "invalidEntry"
    return ascii_name, None


def parse_source(payload: bytes) -> tuple[list[str], dict]:
    """Parse the raw list into unique A-labels, keeping stage-0 rejects."""
    text = payload.decode("utf-8", errors="strict")
    lines = [line for line in text.splitlines()]
    raw = sum(1 for line in lines if line.strip())
    seen: set[str] = set()
    names: list[str] = []
    invalid: list[str] = []
    duplicates = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, reason = normalize_name(line)
        if name is None:
            invalid.append(line.strip())
            continue
        if name in seen:
            duplicates += 1
            continue
        seen.add(name)
        names.append(name)
    names.sort()
    return names, {
        "raw": raw,
        "unique": len(names),
        "invalid": invalid,
        "duplicates": duplicates,
    }


# --------------------------------------------------------------------------- probe


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _decode_cert(der: bytes) -> dict:
    """Decode a DER certificate without verification.

    ``SSLSocket.getpeercert()`` returns an empty dict when verification is off, so the
    DER form is decoded through the stdlib helper instead.
    """
    if not der:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    handle_fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle_fd, "w", encoding="ascii") as stream:
            stream.write(pem)
        decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
        if decoder is None:
            return {}
        return decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _cert_covers(cert: dict, fqdn: str) -> bool:
    names: list[str] = []
    for kind, value in cert.get("subjectAltName", ()):  # type: ignore[union-attr]
        if kind == "DNS":
            names.append(value.lower())
    if not names:
        for rdn in cert.get("subject", ()):  # type: ignore[union-attr]
            for key, value in rdn:
                if key == "commonName":
                    names.append(value.lower())
    for name in names:
        if name == fqdn:
            return True
        if name.startswith("*.") and fqdn.count(".") == name.count("."):
            if fqdn.split(".", 1)[1] == name[2:]:
                return True
    return False


def _bind_to_device(sock: socket.socket, interface: str) -> None:
    """Bind the probe socket to a physical interface, bypassing the XIO tunnel."""
    if not interface:
        return
    option = getattr(socket, "SO_BINDTODEVICE", None)
    if option is None:
        raise CatalogError(EXIT_IO, "SO_BINDTODEVICE is not supported on this platform")
    sock.setsockopt(socket.SOL_SOCKET, option, interface.encode("ascii") + b"\x00")


def _resolve(fqdn: str, timeout: float):
    """getaddrinfo ignores socket timeouts; a daemon thread keeps a stuck resolver from wedging the run."""
    box: dict = {}

    def run():
        try:
            box["info"] = socket.getaddrinfo(fqdn, 443, type=socket.SOCK_STREAM)
        except BaseException as error:  # noqa: BLE001 - reported as unresolved below
            box["error"] = error

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive() or "info" not in box:
        raise socket.gaierror("dns timeout")
    if "error" in box:
        raise box["error"]
    return box["info"]


def probe_entry(fqdn: str, timeout: float = PROBE_TIMEOUT, interface: str = "") -> Entry:
    """Run stages 1-5 for one name. Never raises for expected network errors."""
    try:
        infos = _resolve(fqdn, timeout)
    except (socket.gaierror, UnicodeError):
        return Entry(fqdn, reject_reason="unresolved")
    addrs = sorted({info[4][0] for info in infos})
    public = [addr for addr in addrs if _is_public(addr)]
    if not public:
        return Entry(fqdn, resolved=addrs, reject_reason="unresolved")

    last_reason = "unreachable"
    for addr in public:
        started = time.monotonic()
        raw = socket.socket(
            socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_STREAM
        )
        raw.settimeout(timeout)
        try:
            _bind_to_device(raw, interface)
            raw.connect((addr, 443))
        except CatalogError:
            raw.close()
            raise
        except OSError:
            raw.close()
            continue
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=fqdn) as tls:
                version = tls.version()
                der = tls.getpeercert(binary_form=True) or b""
                cert = _decode_cert(der)
                rtt = int((time.monotonic() - started) * 1000)
                not_after = cert.get("notAfter")
                expired = False
                if not_after:
                    try:
                        expired = ssl.cert_time_to_seconds(not_after) < time.time()
                    except ValueError:
                        expired = True
                else:
                    expired = True
                if expired:
                    return Entry(fqdn, resolved=addrs, reject_reason="certInvalid")
                if not _cert_covers(cert, fqdn):
                    return Entry(fqdn, resolved=addrs, reject_reason="certMismatch")
                if version != "TLSv1.3":
                    return Entry(fqdn, resolved=addrs, tls13=False, reject_reason="tls12Only")
                return Entry(
                    fqdn,
                    eligible=True,
                    resolved=addrs,
                    tls13=True,
                    cert_sha256=hashlib.sha256(der).hexdigest(),
                    cert_not_after=_iso(not_after),
                    tls_rtt_ms=rtt,
                )
        except ssl.SSLError:
            last_reason = "certInvalid"
        except OSError:
            last_reason = "unreachable"
        finally:
            try:
                raw.close()
            except OSError:
                pass
    return Entry(fqdn, resolved=addrs, reject_reason=last_reason)


def _iso(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return parsed.replace(tzinfo=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


ProbeFn = Callable[[str], Entry]


def probe_all(names: Sequence[str], probe: ProbeFn, concurrency: int, budget_s: float) -> list[Entry]:
    deadline = time.monotonic() + budget_s
    results: list[Entry] = []
    workers = max(1, min(32, concurrency))
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(probe, name): name for name in names}
        try:
            # Wait for results no longer than the budget: a stuck probe must not
            # extend the run past the deadline.
            for future in concurrent.futures.as_completed(
                futures, timeout=max(0.0, deadline - time.monotonic())
            ):
                name = futures[future]
                try:
                    results.append(future.result())
                except Exception:  # noqa: BLE001 - a crashed probe must not kill the run
                    results.append(Entry(name, reject_reason="unreachable"))
        except concurrent.futures.TimeoutError:
            pool.shutdown(wait=False, cancel_futures=True)
            raise CatalogError(EXIT_THRESHOLD, "probe budget exceeded")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    results.sort(key=lambda entry: entry.fqdn)
    return results


# --------------------------------------------------------------------------- artifact


def content_sha256(entries: Iterable[Entry]) -> str:
    """Hash over (fqdn, eligible, sorted resolved) only (contract §2)."""
    payload = [
        [entry.fqdn, entry.eligible, sorted(entry.resolved)]
        for entry in sorted(entries, key=lambda item: item.fqdn)
    ]
    blob = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(blob).hexdigest()


def build_document(
    entries: Sequence[Entry],
    source: dict,
    probe: dict,
    counts: dict,
) -> dict:
    rejected = {reason: 0 for reason in REJECT_REASONS}
    for entry in entries:
        if not entry.eligible and entry.reject_reason in rejected:
            rejected[entry.reject_reason] += 1
    counts = dict(counts)
    counts["rejected"] = rejected
    counts["eligible"] = sum(1 for entry in entries if entry.eligible)
    return {
        "schema": SCHEMA,
        "contentSha256": content_sha256(entries),
        "source": source,
        "probe": probe,
        "counts": counts,
        "entries": [entry.as_json() for entry in entries],
    }


def dumps(document: dict) -> bytes:
    return (
        json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def lint_document(document: dict) -> list[str]:
    """Structural validation shared by the linter and the builder."""
    problems: list[str] = []
    if document.get("schema") != SCHEMA:
        problems.append(f"schema != {SCHEMA}")
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        problems.append("entries missing or empty")
        return problems
    names = [entry.get("fqdn") for entry in entries if isinstance(entry, dict)]
    if names != sorted(names):
        problems.append("entries not sorted by fqdn")
    if len(set(names)) != len(names):
        problems.append("duplicate fqdn")
    for entry in entries:
        fqdn = entry.get("fqdn", "?")
        if entry.get("eligible"):
            for key in ("resolved", "tls13", "certSha256", "certNotAfter", "tlsRttMs"):
                if entry.get(key) in (None, [], False, 0, ""):
                    problems.append(f"{fqdn}: eligible without {key}")
            if entry.get("rejectReason") is not None:
                problems.append(f"{fqdn}: eligible with rejectReason")
        elif entry.get("rejectReason") not in REJECT_REASONS:
            problems.append(f"{fqdn}: bad rejectReason {entry.get('rejectReason')!r}")
    expected = content_sha256(_entries_from_json(entries))
    if document.get("contentSha256") != expected:
        problems.append("contentSha256 mismatch")
    counts = document.get("counts") or {}
    if counts.get("eligible") != sum(1 for entry in entries if entry.get("eligible")):
        problems.append("counts.eligible mismatch")
    return problems


def _entries_from_json(entries: Sequence[dict]) -> list[Entry]:
    result = []
    for entry in entries:
        result.append(
            Entry(
                fqdn=entry.get("fqdn", ""),
                eligible=bool(entry.get("eligible")),
                reject_reason=entry.get("rejectReason"),
                resolved=list(entry.get("resolved") or []),
            )
        )
    return result


# --------------------------------------------------------------------------- io


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        host = urllib.parse.urlsplit(newurl).hostname or ""
        if host not in ALLOWED_HOSTS:
            raise CatalogError(EXIT_SOURCE, f"refusing redirect to {host}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_bytes(url: str, timeout: float = 20.0) -> bytes:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise CatalogError(EXIT_SOURCE, f"host not allowed: {host}")
    opener = urllib.request.build_opener(_SameHostRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "xio-catalog/1"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.read(LIMIT_BYTES + 1)
    except CatalogError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CatalogError(EXIT_SOURCE, f"source unavailable: {exc}") from exc


def resolve_commit(url: str = COMMIT_API, timeout: float = 20.0) -> str:
    payload = fetch_bytes(url, timeout=timeout)
    try:
        rows = json.loads(payload.decode("utf-8"))
        sha = rows[0]["sha"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise CatalogError(EXIT_SOURCE, "cannot resolve source commit") from exc
    if not (isinstance(sha, str) and len(sha) == 40):
        raise CatalogError(EXIT_SOURCE, "cannot resolve source commit")
    return sha


def load_pins(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CatalogError(EXIT_PIN, "pin missing") from None
    except (OSError, ValueError) as exc:
        raise CatalogError(EXIT_PIN, f"pin unreadable: {exc}") from exc


def check_pin(pins: dict, payload: bytes, url: str) -> str:
    expected = (pins or {}).get("sha256", "")
    actual = hashlib.sha256(payload).hexdigest()
    if not expected:
        raise CatalogError(EXIT_PIN, "pin missing")
    if pins.get("source") not in (None, "", url):
        raise CatalogError(EXIT_PIN, f"pin source mismatch: {pins.get('source')}")
    if expected.lower() != actual:
        raise CatalogError(EXIT_PIN, f"source sha256 {actual} != pin {expected}")
    return actual


class _Lock:
    """flock holder; a no-op where fcntl is unavailable (Windows tests)."""

    def __init__(self, path: Path = LOCK_PATH):
        self.path = path
        self.handle = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            self.handle = None
            raise CatalogError(EXIT_IO, f"catalog lock busy: {exc}") from exc
        return self

    def __exit__(self, *_exc):
        if self.handle is not None:
            try:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            finally:
                self.handle.close()
                self.handle = None
        return False


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle_fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(handle_fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_state(directory: Path) -> dict:
    path = directory / STATE_NAME
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {}


def publish(directory: Path, name: str, data: bytes) -> dict:
    """Write the artifact, rotate the previous one, return the new state."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / name
    state = read_state(directory)
    previous = dict(state.get("previous") or {})
    current = dict(state.get("current") or {})

    if target.exists():
        old_sha = _sha_file(target)
        if current.get("file") == target.name and current.get("sha256") != old_sha:
            current = {"file": target.name, "sha256": old_sha}
        previous = {"file": PREVIOUS_NAME, "sha256": old_sha}
        write_atomic(directory / PREVIOUS_NAME, target.read_bytes())

    write_atomic(target, data)
    new_state = {
        "schema": SCHEMA,
        "current": {"file": target.name, "sha256": hashlib.sha256(data).hexdigest()},
        "previous": previous,
    }
    write_atomic(directory / STATE_NAME, dumps(new_state))
    return new_state


def rollback(directory: Path) -> dict:
    with _Lock():
        state = read_state(directory)
        previous = state.get("previous") or {}
        name = previous.get("file")
        if not name:
            raise CatalogError(EXIT_IO, "no previous catalog to roll back to")
        source = directory / name
        if not source.exists():
            raise CatalogError(EXIT_IO, f"previous catalog missing: {name}")
        actual = _sha_file(source)
        if actual != previous.get("sha256"):
            raise CatalogError(EXIT_IO, "previous catalog sha256 mismatch, refusing rollback")
        current = state.get("current") or {}
        payload = source.read_bytes()
        target = directory / (current.get("file") or "whitelist.json")
        write_atomic(target, payload)
        new_state = {
            "schema": SCHEMA,
            "current": {"file": target.name, "sha256": actual},
            "previous": {},
        }
        write_atomic(directory / STATE_NAME, dumps(new_state))
        return new_state


# --------------------------------------------------------------------------- build


def local_egress(interface: str) -> dict:
    """Address this host probes from on `interface`: measured, never guessed."""
    if not interface:
        return {}
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", "dev", interface],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {}
        for link in json.loads(result.stdout):
            for info in link.get("addr_info", []):
                family = info.get("family")
                if family in ("inet", "inet6") and info.get("scope") != "link" and info.get("local"):
                    return {"interface": interface, "address": info["local"],
                            "family": "4" if family == "inet" else "6"}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    return {}


def build(
    *,
    url: str = SOURCE_URL,
    source_payload: bytes | None = None,
    commit: str | None = None,
    pins_path: Path | None = None,
    probe: ProbeFn | None = None,
    interface: str = "",
    probe_meta: dict | None = None,
    concurrency: int = 6,
    budget_s: float = RUN_BUDGET_S,
    now: dt.datetime | None = None,
) -> dict:
    """Produce the catalog document in memory; nothing is written here."""
    if source_payload is None:
        source_payload = fetch_bytes(url)
    if len(source_payload) > LIMIT_BYTES:
        raise CatalogError(EXIT_THRESHOLD, "source larger than 5 MiB")
    try:
        names, stats = parse_source(source_payload)
    except UnicodeDecodeError as exc:
        raise CatalogError(EXIT_PIN, f"source is not UTF-8: {exc}") from exc
    if not names:
        raise CatalogError(EXIT_PIN, "source contains no usable names")
    if stats["raw"] > LIMIT_LINES:
        raise CatalogError(EXIT_THRESHOLD, "source has more than 20000 lines")

    pins = load_pins(pins_path or DEFAULT_DIR / PINS_NAME)
    source_sha = check_pin(pins, source_payload, pins.get("source") or url)

    if commit is None and source_payload is not None:
        commit = pins.get("commit")
    if commit is None:
        commit = resolve_commit()

    if probe is None:
        probe = lambda name: probe_entry(name, interface=interface)  # noqa: E731
    entries = probe_all(names, probe, concurrency, budget_s)

    counts = {
        "raw": stats["raw"],
        "unique": stats["unique"],
    }
    metadata = {
        "url": url,
        "commit": commit,
        "sha256": source_sha,
        "license": pins.get("license", "MIT"),
        "fetchedAt": (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bytes": len(source_payload),
        "lines": stats["raw"],
    }
    probe_block = {
        "performedOn": os.uname().nodename if hasattr(os, "uname") else socket.gethostname(),
        "interface": interface,
        "country": "",
        "bypassTunnel": bool(interface),
        "tlsRequires": "1.3",
        "probeMode": "tcp-tls13",
        "countrySource": "operator" if (probe_meta or {}).get("country") else "unknown",
    }
    probe_block.update(probe_meta or {})
    # What the probe actually touched, so "country" can be checked against reality.
    probe_block["families"] = sorted(
        {"6" if ":" in addr else "4" for entry in entries for addr in entry.resolved}
    )
    egress = local_egress(interface)
    if egress:
        probe_block["egress"] = egress

    document = build_document(entries, metadata, probe_block, counts)
    # Lines rejected at stage 0 never become entries, so their count comes from the parser.
    document["counts"]["rejected"]["invalidEntry"] = len(stats["invalid"])
    eligible = document["counts"]["eligible"]
    if eligible < MIN_ELIGIBLE or eligible < stats["raw"] * MIN_RATIO:
        raise CatalogError(
            EXIT_THRESHOLD,
            f"eligible {eligible} below threshold (min {MIN_ELIGIBLE} or 1% of {stats['raw']})",
        )
    problems = lint_document(document)
    if problems:
        raise CatalogError(EXIT_IO, "built catalog fails lint: " + "; ".join(problems))
    return document


def sign(path: Path, key_path: Path) -> Path:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise CatalogError(EXIT_IO, "cryptography is not installed, cannot sign") from exc
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise CatalogError(EXIT_IO, "signing key is not Ed25519")
    signature = key.sign(path.read_bytes())
    target = path.with_suffix(path.suffix + ".sig")
    write_atomic(target, signature + b"\n")
    return target


def artifact_name(now: dt.datetime | None = None) -> str:
    stamp = (now or dt.datetime.now(dt.timezone.utc)).strftime("%Y%m%d")
    return f"whitelist-{stamp}.json"


# --------------------------------------------------------------------------- cli


def _cmd_build(args: argparse.Namespace) -> int:
    directory = Path(args.out_dir).resolve()
    payload = Path(args.source_file).read_bytes() if args.source_file else None
    document = build(
        url=args.url,
        source_payload=payload,
        commit=args.commit,
        pins_path=Path(args.pins).resolve() if args.pins else None,
        interface=args.interface,
        concurrency=args.concurrency,
        budget_s=args.budget_seconds,
        probe_meta={
            "interface": args.interface,
            "country": args.country,
            "performedOn": args.node,
        },
    )
    data = dumps(document)
    name = args.name or artifact_name()
    if args.dry_run:
        sys.stdout.write(data.decode("utf-8"))
        return EXIT_OK
    with _Lock():
        state = publish(directory, name, data)
    if args.sign_key:
        sign(directory / name, Path(args.sign_key).resolve())
    sys.stderr.write(
        f"catalog {name}: eligible {document['counts']['eligible']}/{document['counts']['unique']} "
        f"content {document['contentSha256'][:12]} state {state['current']['sha256'][:12]}\n"
    )
    return EXIT_OK


def _cmd_rollback(args: argparse.Namespace) -> int:
    state = rollback(Path(args.out_dir).resolve())
    sys.stderr.write(f"rolled back to {state['current']['file']}\n")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.file).read_text(encoding="utf-8"))
    problems = lint_document(document)
    if problems:
        for problem in problems:
            sys.stderr.write(f"FAIL {problem}\n")
        return EXIT_IO
    sys.stderr.write(
        f"OK {document['counts']['eligible']}/{document['counts']['unique']} "
        f"content {document['contentSha256']}\n"
    )
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="catalog.py", description="XIO whitelist catalog")
    sub = parser.add_subparsers(dest="command", required=True)

    build_parser = sub.add_parser("build", help="build the catalog artifact")
    build_parser.add_argument("--url", default=SOURCE_URL)
    build_parser.add_argument("--source-file", help="use a local source file instead of the network")
    build_parser.add_argument("--commit", help="40-hex commit of the source (default: from pin/api)")
    build_parser.add_argument("--pins", help="path to whitelist-pins.json")
    build_parser.add_argument("--out-dir", default=str(DEFAULT_DIR))
    build_parser.add_argument("--name", help="artifact file name (default whitelist-YYYYMMDD.json)")
    build_parser.add_argument("--concurrency", type=int, default=6)
    build_parser.add_argument("--budget-seconds", type=float, default=RUN_BUDGET_S)
    build_parser.add_argument("--interface", default="")
    build_parser.add_argument("--country", default="")
    build_parser.add_argument("--node", default=socket.gethostname())
    build_parser.add_argument("--sign-key", help="Ed25519 private key (PEM) for catalog.sig")
    build_parser.add_argument("--dry-run", action="store_true")
    build_parser.set_defaults(func=_cmd_build)

    rollback_parser = sub.add_parser("rollback", help="restore the previous catalog")
    rollback_parser.add_argument("--out-dir", default=str(DEFAULT_DIR))
    rollback_parser.set_defaults(func=_cmd_rollback)

    verify_parser = sub.add_parser("verify", help="lint an existing artifact")
    verify_parser.add_argument("--file", required=True)
    verify_parser.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CatalogError as exc:
        sys.stderr.write(f"catalog: {exc.message}\n")
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
