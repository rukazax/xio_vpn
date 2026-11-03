#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xio-webui — защищённый графический веб-интерфейс XIO-сервера.

Только стандартная библиотека Python 3.8+. Внешних зависимостей нет.

Запуск:
    python3 xio-webui.py                     # https://127.0.0.1:10443
    python3 xio-webui.py --listen 0.0.0.0:10443

Безопасность:
  * только TLS (самоподписанный сертификат в ./tls/, генерируется при первом старте);
  * Bearer-токен из ./token (создаётся с правами 600) + cookie-сессия;
  * сравнение секретов через hmac.compare_digest;
  * CSRF-заголовок X-XIO-CSRF на всех POST;
  * rate-limit: 5 неудачных попыток аутентификации с адреса -> блокировка;
  * все внешние действия — subprocess без shell, только списки аргументов.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_NAME = "xio-webui"
APP_VERSION = "1.0.0"

BASE_DIR = Path(__file__).resolve().parent
TLS_DIR = BASE_DIR / "tls"
TOKEN_FILE = BASE_DIR / "token"
LOG_FILE = BASE_DIR / "webui.log"
INDEX_FILE = BASE_DIR / "index.html"
CERT_FILE = TLS_DIR / "cert.pem"
KEY_FILE = TLS_DIR / "key.pem"

ADMIN_PY = "/usr/local/lib/xio-managed/admin.py"
DEPLOYMENT_FILE = "/etc/xio-managed/deployment.json"

UNITS = [
    "xio-rivet-entry",
    "xio-rivet-gateway",
    "xio-managed-awg",
    "xio-stack",
    "xio-ready",
]
CASCADE_UNIT = "xio-rivet-gateway"
SYSTEMCTL_VERBS = ("start", "stop", "restart")
CASCADE_VERBS = ("enable", "disable")

TIMEOUT_ADMIN = 20
TIMEOUT_SYSTEMCTL = 25
TIMEOUT_CERT = 60
MAX_BODY = 64 * 1024
MAX_OUTPUT = 4000

SESSION_TTL = 12 * 3600
FAIL_LIMIT = 5
FAIL_WINDOW = 900
BLOCK_SECONDS = 900

SAFE_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}

USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")

_log_lock = threading.Lock()


def log(msg, level="INFO"):
    """Пишет строку в ./webui.log. Секреты сюда не попадают никогда."""
    line = "%s %-5s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), level, msg)
    try:
        with _log_lock:
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > 2 * 1024 * 1024:
                try:
                    os.replace(str(LOG_FILE), str(LOG_FILE) + ".1")
                except OSError:
                    pass
            fd = os.open(str(LOG_FILE), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8", "replace"))
            finally:
                os.close(fd)
    except OSError:
        sys.stderr.write(line)


# --------------------------------------------------------------------------
# токен, сессии, rate-limit
# --------------------------------------------------------------------------

class TokenStore(object):
    def __init__(self, path):
        self.path = Path(path)
        self.token = ""
        self.csrf = ""
        self.load()

    def load(self):
        created = False
        if self.path.exists():
            raw = self.path.read_text(encoding="utf-8").strip()
        else:
            raw = ""
        if len(raw) < 32:
            raw = secrets.token_urlsafe(32)
            created = True
            self._write(raw)
        self.token = raw
        digest = hmac.new(raw.encode("utf-8"), b"xio-webui-csrf-v1", hashlib.sha256).digest()
        self.csrf = base64.urlsafe_b64encode(digest[:24]).decode("ascii").rstrip("=")
        if created:
            log("token file created: %s" % self.path)
            sys.stdout.write("XIO WebUI token: %s\n" % raw)
            sys.stdout.flush()

    def _write(self, raw):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (raw + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(str(self.path), 0o600)
        except OSError:
            pass

    def check(self, candidate):
        if not candidate or not self.token:
            return False
        return hmac.compare_digest(self.token.encode("utf-8"), str(candidate).encode("utf-8"))

    def check_csrf(self, candidate):
        if not candidate:
            return False
        return hmac.compare_digest(self.csrf.encode("utf-8"), str(candidate).encode("utf-8"))


class Sessions(object):
    def __init__(self, ttl=SESSION_TTL):
        self.ttl = ttl
        self._data = {}
        self._lock = threading.Lock()

    def create(self):
        sid = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._gc(now)
            self._data[sid] = now + self.ttl
        return sid

    def valid(self, sid):
        if not sid:
            return False
        now = time.time()
        with self._lock:
            exp = self._data.get(sid)
            if exp is None:
                return False
            if exp < now:
                self._data.pop(sid, None)
                return False
            self._data[sid] = now + self.ttl
            return True

    def drop(self, sid):
        with self._lock:
            self._data.pop(sid, None)

    def _gc(self, now):
        for sid in [k for k, v in self._data.items() if v < now]:
            self._data.pop(sid, None)


class RateLimiter(object):
    def __init__(self, limit=FAIL_LIMIT, window=FAIL_WINDOW, block=BLOCK_SECONDS):
        self.limit = limit
        self.window = window
        self.block = block
        self._fails = {}
        self._blocked = {}
        self._lock = threading.Lock()

    def blocked_for(self, ip):
        now = time.time()
        with self._lock:
            until = self._blocked.get(ip)
            if until is None:
                return 0
            if until <= now:
                self._blocked.pop(ip, None)
                self._fails.pop(ip, None)
                return 0
            return int(until - now)

    def fail(self, ip):
        now = time.time()
        with self._lock:
            bucket = [t for t in self._fails.get(ip, []) if now - t < self.window]
            bucket.append(now)
            self._fails[ip] = bucket
            if len(bucket) >= self.limit:
                self._blocked[ip] = now + self.block
                self._fails[ip] = []
                return True
            return False

    def ok(self, ip):
        with self._lock:
            self._fails.pop(ip, None)


TOKENS = TokenStore(TOKEN_FILE)
SESSIONS = Sessions()
LIMITER = RateLimiter()
STATE_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# сертификат: openssl, иначе чистый Python (ASN.1/DER + RSA)
# --------------------------------------------------------------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, payload):
    return bytes([tag]) + _der_len(len(payload)) + payload


def _der_int(value):
    if value == 0:
        return _tlv(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _der_seq(*items):
    return _tlv(0x30, b"".join(items))


def _der_set(*items):
    return _tlv(0x31, b"".join(items))


def _der_oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(reversed(chunk))
    return _tlv(0x06, body)


def _der_utf8(text):
    return _tlv(0x0C, text.encode("utf-8"))


def _der_bits(data):
    return _tlv(0x03, b"\x00" + data)


def _der_octets(data):
    return _tlv(0x04, data)


def _der_utctime(dt):
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def _der_bool(value):
    return _tlv(0x01, b"\xff" if value else b"\x00")


_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109,
                 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179]


def _is_probable_prime(n):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(40):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        cand |= 3
        if _is_probable_prime(cand):
            return cand


def _rsa_keypair(bits=2048):
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1), "qinv": pow(q, -1, p),
        }


def _pem(label, der):
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


def _write_cert_pure_python(hosts):
    """Самоподписанный сертификат без openssl: RSA-2048 + PKCS#1 v1.5/SHA-256."""
    key = _rsa_keypair(2048)
    n, e = key["n"], key["e"]

    spki = _der_seq(
        _der_seq(_der_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
        _der_bits(_der_seq(_der_int(n), _der_int(e))),
    )

    san = b""
    for host in hosts:
        try:
            san += _tlv(0x87, socket.inet_pton(socket.AF_INET, host))
        except OSError:
            try:
                san += _tlv(0x87, socket.inet_pton(socket.AF_INET6, host))
            except OSError:
                san += _tlv(0x82, host.encode("idna"))

    now = datetime.datetime.utcnow()
    name = _der_seq(_der_set(_der_seq(_der_oid("2.5.4.3"), _der_utf8("xio-webui"))))
    tbs = _der_seq(
        _tlv(0xA0, _der_int(2)),
        _der_int(secrets.randbits(63) | 1),
        _der_seq(_der_oid("1.2.840.113549.1.1.11"), b"\x05\x00"),
        name,
        _der_seq(_der_utctime(now - datetime.timedelta(minutes=5)),
                 _der_utctime(now + datetime.timedelta(days=3650))),
        name,
        spki,
        _tlv(0xA3, _der_seq(
            _der_seq(_der_oid("2.5.29.19"), _der_bool(True),
                     _der_octets(_der_seq(_der_bool(True)))),
            _der_seq(_der_oid("2.5.29.17"), _der_octets(_der_seq(san))),
            _der_seq(_der_oid("2.5.29.15"), _der_bool(True),
                     _der_octets(_der_bits(b"\x86"))),
        )),
    )

    digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
    digest_info += hashlib.sha256(tbs).digest()
    k = (n.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), key["d"], n).to_bytes(k, "big")
    cert = _der_seq(
        tbs,
        _der_seq(_der_oid("1.2.840.113549.1.1.11"), b"\x05\x00"),
        _der_bits(sig),
    )

    priv = _der_seq(
        _der_int(0), _der_int(n), _der_int(e), _der_int(key["d"]),
        _der_int(key["p"]), _der_int(key["q"]),
        _der_int(key["dp"]), _der_int(key["dq"]), _der_int(key["qinv"]),
    )

    TLS_DIR.mkdir(parents=True, exist_ok=True)
    _secure_write(KEY_FILE, _pem("RSA PRIVATE KEY", priv).encode("ascii"), 0o600)
    _secure_write(CERT_FILE, _pem("CERTIFICATE", cert).encode("ascii"), 0o644)


def _secure_write(path, data, mode):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(str(path), mode)
    except OSError:
        pass


def _try_openssl(hosts):
    openssl = None
    for cand in ("/usr/bin/openssl", "/usr/local/bin/openssl", "/bin/openssl"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            openssl = cand
            break
    if openssl is None:
        return False

    san_parts = []
    for host in hosts:
        if re.match(r"^[0-9.]+$", host) or ":" in host:
            san_parts.append("IP:%s" % host)
        else:
            san_parts.append("DNS:%s" % host)
    san = ",".join(san_parts) or "DNS:localhost"
    cfg_text = (
        "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n"
        "[dn]\nCN=xio-webui\n"
        "[v3]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=%s\n" % san
    )
    cfg_path = TLS_DIR / "openssl.cnf"
    _secure_write(cfg_path, cfg_text.encode("utf-8"), 0o600)

    argv = [
        openssl, "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
        "-days", "3650", "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
        "-config", str(cfg_path),
    ]
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TIMEOUT_CERT, env=SAFE_ENV, shell=False)
    except (OSError, subprocess.SubprocessError):
        return False
    if proc.returncode != 0 or not CERT_FILE.exists() or not KEY_FILE.exists():
        log("openssl certificate generation failed (rc=%s)" % proc.returncode, "WARN")
        return False
    try:
        os.chmod(str(KEY_FILE), 0o600)
        os.chmod(str(CERT_FILE), 0o644)
    except OSError:
        pass
    return True


def ensure_certificate(listen_host, regenerate=False):
    if regenerate:
        for path in (CERT_FILE, KEY_FILE):
            if path.exists():
                path.unlink()
    if CERT_FILE.exists() and KEY_FILE.exists():
        return False
    hosts = ["localhost", "127.0.0.1", "::1"]
    if listen_host and listen_host not in ("0.0.0.0", "::", ""):
        hosts.append(listen_host)
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    if _try_openssl(hosts):
        log("TLS certificate generated with openssl: %s" % CERT_FILE)
    else:
        log("openssl unavailable, generating certificate in pure Python (may take a minute)")
        _write_cert_pure_python(hosts)
        log("TLS certificate generated (pure Python): %s" % CERT_FILE)
    return True


def cert_fingerprint():
    """SHA-256 отпечаток сертификата в формате AA:BB:..."""
    try:
        text = CERT_FILE.read_text(encoding="ascii")
        body = "".join(line for line in text.splitlines() if not line.startswith("-----"))
        der = base64.b64decode(body)
        digest = hashlib.sha256(der).hexdigest().upper()
        return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------
# внешние команды (без shell, только списки аргументов)
# --------------------------------------------------------------------------

def _clip(text, limit=MAX_OUTPUT):
    if text is None:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    text = text.strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def _systemctl_path():
    for cand in ("/usr/bin/systemctl", "/bin/systemctl"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return "systemctl"


SYSTEMCTL = _systemctl_path()


def run_command(argv, input_bytes=None, timeout=TIMEOUT_SYSTEMCTL):
    """Возвращает dict(rc, out, err, timeout). Никакого shell."""
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("argv must be a non-empty list")
    started = time.time()
    try:
        proc = subprocess.run(
            list(argv), input=input_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, env=SAFE_ENV, shell=False,
        )
    except FileNotFoundError:
        return {"rc": 127, "out": "", "err": "command not found", "timeout": False,
                "ms": int((time.time() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout after %ss" % timeout,
                "timeout": True, "ms": int((time.time() - started) * 1000)}
    except OSError as exc:
        return {"rc": 126, "out": "", "err": "exec failed: %s" % exc.__class__.__name__,
                "timeout": False, "ms": int((time.time() - started) * 1000)}
    return {
        "rc": proc.returncode,
        "out": _clip(proc.stdout),
        "err": _clip(proc.stderr),
        "timeout": False,
        "ms": int((time.time() - started) * 1000),
    }


def admin_call(action, payload, timeout=TIMEOUT_ADMIN):
    """Вызов admin.py: действие в argv, JSON в stdin."""
    if not os.path.isfile(ADMIN_PY):
        return {"ok": False, "code": 502,
                "error": "admin.py not found: %s" % ADMIN_PY,
                "rc": 127, "data": None}
    body = json.dumps(payload if payload is not None else {}, ensure_ascii=False).encode("utf-8")
    res = run_command([sys.executable or "python3", ADMIN_PY, action], body, timeout)
    parsed = None
    if res["out"]:
        try:
            parsed = json.loads(res["out"])
        except ValueError:
            parsed = None
    if res["timeout"]:
        return {"ok": False, "code": 504, "error": "admin.py %s: timeout" % action,
                "rc": res["rc"], "data": parsed}
    if res["rc"] != 0:
        detail = _clip(res["err"] or res["out"], 600)
        return {"ok": False, "code": 502,
                "error": "admin.py %s failed (rc=%s): %s" % (action, res["rc"], detail),
                "rc": res["rc"], "data": parsed}
    if parsed is None:
        return {"ok": False, "code": 502,
                "error": "admin.py %s returned non-JSON output" % action,
                "rc": res["rc"], "data": None}
    return {"ok": True, "code": 200, "error": "", "rc": 0, "data": parsed}


def systemctl_action(verb, unit):
    if verb not in SYSTEMCTL_VERBS:
        return {"ok": False, "code": 400, "error": "unsupported verb"}
    if unit not in UNITS and unit != CASCADE_UNIT:
        return {"ok": False, "code": 400, "error": "unknown unit"}
    res = run_command([SYSTEMCTL, verb, unit], None, TIMEOUT_SYSTEMCTL)
    if res["timeout"]:
        return {"ok": False, "code": 504,
                "error": "systemctl %s %s: timeout" % (verb, unit), "rc": res["rc"]}
    if res["rc"] != 0:
        return {"ok": False, "code": 502,
                "error": "systemctl %s %s failed (rc=%s): %s"
                         % (verb, unit, res["rc"], _clip(res["err"], 400)),
                "rc": res["rc"]}
    return {"ok": True, "code": 200, "error": "", "rc": 0}


_units_cache = {"ts": 0.0, "data": None}
_units_lock = threading.Lock()


def unit_states(use_cache=True):
    now = time.time()
    with _units_lock:
        if use_cache and _units_cache["data"] and now - _units_cache["ts"] < 2.0:
            return _units_cache["data"]
    rows = []
    for unit in UNITS:
        res = run_command(
            [SYSTEMCTL, "show", unit, "--no-pager",
             "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
             "-p", "Description"],
            None, 6,
        )
        info = {"unit": unit, "active": "unknown", "sub": "unknown",
                "enabled": "unknown", "description": "", "error": ""}
        if res["rc"] != 0:
            info["error"] = _clip(res["err"], 200) or "systemctl rc=%s" % res["rc"]
        else:
            for line in res["out"].splitlines():
                key, _, value = line.partition("=")
                if key == "ActiveState":
                    info["active"] = value
                elif key == "SubState":
                    info["sub"] = value
                elif key == "UnitFileState":
                    info["enabled"] = value
                elif key == "Description":
                    info["description"] = value
        rows.append(info)
    with _units_lock:
        _units_cache["ts"] = now
        _units_cache["data"] = rows
    return rows


def read_deployment():
    path = Path(DEPLOYMENT_FILE)
    try:
        if not path.is_file() or path.stat().st_size > 256 * 1024:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        log("deployment.json not readable: %s" % exc.__class__.__name__, "WARN")
        return {}


def _walk_find(obj, keys, depth=0):
    """Ищет первое значение по набору ключей в произвольном JSON."""
    if depth > 6 or not isinstance(obj, (dict, list)):
        return None
    items = obj.items() if isinstance(obj, dict) else enumerate(obj)
    for key, value in items:
        if isinstance(key, str) and key.lower() in keys and isinstance(value, (str, int, float)):
            return value
    for _, value in (obj.items() if isinstance(obj, dict) else enumerate(obj)):
        found = _walk_find(value, keys, depth + 1)
        if found is not None:
            return found
    return None


def _collect_users(*sources):
    users = []
    seen = set()
    for src in sources:
        if not isinstance(src, dict):
            continue
        raw = None
        for key in ("users", "clients", "peers", "user_list"):
            if isinstance(src.get(key), (list, dict)):
                raw = src[key]
                break
        if raw is None:
            continue
        seq = raw.values() if isinstance(raw, dict) else raw
        for item in seq:
            if isinstance(item, str) and item.strip():
                name = item.strip()
                entry = {"name": name, "status": "unknown", "detail": ""}
            elif isinstance(item, dict):
                name = None
                for key in ("name", "username", "user", "login", "common_name", "cn"):
                    if isinstance(item.get(key), str) and item.get(key).strip():
                        name = item[key].strip()
                        break
                if not name:
                    continue
                entry = {
                    "name": name,
                    "status": str(item.get("status") or item.get("state") or "active"),
                    "detail": str(item.get("note") or item.get("comment") or
                                  item.get("created") or ""),
                }
            else:
                continue
            if entry["name"] in seen:
                continue
            seen.add(entry["name"])
            users.append(entry)
    users.sort(key=lambda u: u["name"].lower())
    return users


def _collect_whitelists(*sources):
    out = []
    for src in sources:
        for key in ("whitelists", "whitelist", "allowlist", "allowlists", "routes"):
            if isinstance(src, dict) and isinstance(src.get(key), (list, dict)):
                raw = src[key]
                seq = raw.items() if isinstance(raw, dict) else [(None, v) for v in raw]
                for name, value in seq:
                    if isinstance(value, (list, tuple)):
                        items_ = [str(v) for v in value][:100]
                        out.append({"name": str(name or key), "items": items_})
                    elif isinstance(value, str):
                        out.append({"name": str(name or key), "items": [value]})
                break
    return out[:12]


def _traffic_from(*sources):
    keys = {"rx_bytes", "tx_bytes", "received", "sent", "traffic", "bytes_in",
            "bytes_out", "rx", "tx", "total_bytes", "traffic_total"}
    for src in sources:
        if not isinstance(src, dict):
            continue
        for key in ("traffic", "traffic_total", "counters", "stats"):
            cand = src.get(key)
            if isinstance(cand, dict):
                result = {}
                for out_key, names in (
                    ("rx", ("rx", "rx_bytes", "received", "bytes_in", "download")),
                    ("tx", ("tx", "tx_bytes", "sent", "bytes_out", "upload")),
                ):
                    for name in names:
                        if isinstance(cand.get(name), (int, float)):
                            result[out_key] = int(cand[name])
                            break
                if result:
                    return result
    value = _walk_find({"sources": sources}, keys)
    return None


def build_state():
    deployment = read_deployment()
    admin_status = admin_call("status", {})
    admin_inspect = admin_call("inspect", {})

    sources = []
    for res in (admin_status, admin_inspect):
        if res.get("ok") and isinstance(res.get("data"), dict):
            sources.append(res["data"])

    role = None
    for src in sources + [deployment]:
        if isinstance(src, dict):
            for key in ("cascade_role", "role", "cascade", "node_role", "mode"):
                value = src.get(key)
                if isinstance(value, str) and value.strip():
                    role = value.strip()
                    break
        if role:
            break

    version = None
    for src in sources + [deployment]:
        if isinstance(src, dict):
            for key in ("version", "xio_version", "release", "build"):
                value = src.get(key)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    version = str(value).strip()
                    break
        if version:
            break

    services = unit_states()
    gateway_active = any(s["unit"] == CASCADE_UNIT and s["active"] == "active"
                         for s in services)
    listed = _collect_users(*sources)
    admin_users = bool(listed)

    warnings = []
    if not admin_status.get("ok"):
        warnings.append("admin.py status: %s" % admin_status.get("error"))
    if not admin_inspect.get("ok"):
        warnings.append("admin.py inspect: %s" % admin_inspect.get("error"))
    if not deployment:
        warnings.append("deployment.json недоступен или пуст")

    return {
        "ok": True,
        "app": APP_NAME,
        "app_version": APP_VERSION,
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "csrf": TOKENS.csrf,
        "server": {
            "hostname": socket.gethostname(),
            "role": role or "неизвестна",
            "version": version or "неизвестна",
            "deployment_present": bool(deployment),
            "cert_fingerprint": cert_fingerprint(),
            "admin_present": os.path.isfile(ADMIN_PY),
            "uptime_seconds": _read_uptime(),
        },
        "services": services,
        "users": listed,
        "users_source": "admin.py inspect" if admin_users else "нет данных",
        "cascade": {
            "role": role or "неизвестна",
            "enabled": gateway_active,
            "unit": CASCADE_UNIT,
        },
        "traffic": _traffic_from(*sources) or {},
        "whitelists": _collect_whitelists(*sources),
        "warnings": warnings,
    }


def _read_uptime():
    try:
        with open("/proc/uptime", "r", encoding="ascii") as handle:
            return int(float(handle.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "%s/%s" % (APP_NAME, APP_VERSION)
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- служебное ----

    def log_message(self, fmt, *args):
        pass  # всё пишем сами, без query-строк и заголовков

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "unknown"

    def _send(self, status, body, content_type="application/json; charset=utf-8",
              extra_headers=None, close=False):
        if isinstance(body, str):
            body = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Strict-Transport-Security", "max-age=86400")
            for key, value in (extra_headers or []):
                self.send_header(key, value)
            if close:
                self.close_connection = True
                self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra_headers)

    def _error(self, status, message, extra_headers=None):
        self._json(status, {"ok": False, "error": message}, extra_headers)

    def _path(self):
        return urllib.parse.urlsplit(self.path).path

    # ---- аутентификация ----

    def _cookie_session(self):
        raw = self.headers.get("Cookie", "") or ""
        for chunk in raw.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name == "xio_sid":
                return value.strip()
        return None

    def _authenticate(self):
        """-> (ok, status, reason, via_bearer)."""
        ip = self._client_ip()
        left = LIMITER.blocked_for(ip)
        if left:
            log("auth blocked ip=%s for=%ss" % (ip, left), "WARN")
            return False, HTTPStatus.TOO_MANY_REQUESTS, "blocked, retry later", False

        via_bearer = False
        header = self.headers.get("Authorization", "") or ""
        if header.lower().startswith("bearer "):
            candidate = header[7:].strip()
            if TOKENS.check(candidate):
                via_bearer = True
                return True, 200, "", True
        sid = self._cookie_session()
        if sid and SESSIONS.valid(sid):
            return True, 200, "", False

        blocked = LIMITER.fail(ip)
        log("auth failed ip=%s path=%s%s" % (ip, self._path(),
                                             " -> blocked" if blocked else ""), "WARN")
        if blocked:
            return False, HTTPStatus.TOO_MANY_REQUESTS, "too many failures, blocked", False
        return False, HTTPStatus.UNAUTHORIZED, "authentication required", False

    def _maybe_session_cookie(self):
        sid = self._cookie_session()
        headers = []
        if not (sid and SESSIONS.valid(sid)):
            sid = SESSIONS.create()
            headers.append(("Set-Cookie",
                            "xio_sid=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict"
                            % (sid, SESSION_TTL)))
        return headers

    def _csrf_ok(self):
        return TOKENS.check_csrf(self.headers.get("X-XIO-CSRF", ""))

    # ---- GET ----

    def do_GET(self):
        path = self._path()
        if path in ("/", "/index.html"):
            return self._serve_index()
        if path == "/api/health":
            return self._json(HTTPStatus.OK, {
                "ok": True, "app": APP_NAME, "version": APP_VERSION,
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            })
        if path == "/api/state":
            ok, status, reason, _ = self._authenticate()
            if not ok:
                headers = [("WWW-Authenticate", 'Bearer realm="xio-webui"')] \
                    if status == HTTPStatus.UNAUTHORIZED else []
                return self._error(status, reason, headers)
            LIMITER.ok(self._client_ip())
            try:
                with STATE_LOCK:  # один сбор состояния за раз: не плодим вызовы admin.py
                    state = build_state()
            except Exception as exc:  # noqa: BLE001 - состояние не должно ронять сервер
                log("state build failed: %s" % exc.__class__.__name__, "ERROR")
                return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "state unavailable")
            return self._json(HTTPStatus.OK, state, self._maybe_session_cookie())
        if path.startswith("/api/"):
            if path.startswith("/api/service/") or path.startswith("/api/cascade/") \
                    or path in ("/api/user/add", "/api/user/revoke"):
                return self._error(HTTPStatus.METHOD_NOT_ALLOWED, "use POST")
            return self._error(HTTPStatus.NOT_FOUND, "unknown endpoint")
        return self._error(HTTPStatus.NOT_FOUND, "not found")

    def _serve_index(self):
        try:
            body = INDEX_FILE.read_bytes()
        except OSError:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "index.html missing")
        csp = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
               "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; "
               "frame-ancestors 'none'")
        self._send(HTTPStatus.OK, body, "text/html; charset=utf-8",
                   [("Content-Security-Policy", csp)])

    # ---- POST ----

    def do_POST(self):
        path = self._path()
        length = 0
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            # тело не разбираем: вычитываем до 1 МиБ, чтобы клиент успел получить 413,
            # и закрываем соединение, иначе оно рассинхронизируется
            if 0 < length <= 1024 * 1024:
                try:
                    self.rfile.read(length)
                except OSError:
                    pass
            self.close_connection = True
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
        raw = b""
        if length:
            raw = self.rfile.read(length)
        payload = {}
        if raw:
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype not in ("application/json", ""):
                return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "application/json required")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return self._error(HTTPStatus.BAD_REQUEST, "invalid JSON")
            if not isinstance(payload, dict):
                return self._error(HTTPStatus.BAD_REQUEST, "JSON object expected")

        route = None
        if path.startswith("/api/service/"):
            route = ("service", path[len("/api/service/"):])
        elif path == "/api/user/add":
            route = ("user_add", "")
        elif path == "/api/user/revoke":
            route = ("user_revoke", "")
        elif path.startswith("/api/cascade/"):
            route = ("cascade", path[len("/api/cascade/"):])
        if route is None:
            return self._error(HTTPStatus.NOT_FOUND, "unknown endpoint")

        ok, status, reason, _ = self._authenticate()
        if not ok:
            headers = [("WWW-Authenticate", 'Bearer realm="xio-webui"')] \
                if status == HTTPStatus.UNAUTHORIZED else []
            return self._error(status, reason, headers)
        if not self._csrf_ok():
            log("csrf rejected ip=%s path=%s" % (self._client_ip(), path), "WARN")
            return self._error(HTTPStatus.FORBIDDEN, "csrf header X-XIO-CSRF missing or invalid")
        LIMITER.ok(self._client_ip())

        action, arg = route
        started = time.time()
        if action == "service":
            result = self._do_service(arg)
        elif action == "cascade":
            result = self._do_cascade(arg)
        elif action == "user_add":
            result = self._do_user_add(payload)
        else:
            result = self._do_user_revoke(payload)
        log("action=%s arg=%s ip=%s status=%s ms=%d"
            % (action, arg or "-", self._client_ip(), result.get("code", 500),
               int((time.time() - started) * 1000)))
        return self._json(result.get("code", 500), result)

    def _do_service(self, verb):
        if verb not in SYSTEMCTL_VERBS:
            return {"ok": False, "code": 400, "error": "unsupported action"}
        unit = (self.headers.get("X-XIO-Unit") or "").strip()
        if unit not in UNITS:
            return {"ok": False, "code": 400, "error": "unknown unit"}
        return systemctl_action(verb, unit)

    def _do_cascade(self, verb):
        if verb not in CASCADE_VERBS:
            return {"ok": False, "code": 400, "error": "unsupported action"}
        cmd = "start" if verb == "enable" else "stop"
        result = systemctl_action(cmd, CASCADE_UNIT)
        result["unit"] = CASCADE_UNIT
        result["cascade_enabled"] = (verb == "enable") and result["ok"]
        return result

    def _do_user_add(self, payload):
        name = payload.get("name") or payload.get("username")
        name = str(name).strip() if name is not None else ""
        if not USER_RE.match(name):
            return {"ok": False, "code": 400, "error": "invalid user name"}
        body = {"username": name}
        note = payload.get("note")
        if isinstance(note, str) and note.strip():
            body["note"] = note.strip()[:200]
        return admin_call("add", body)

    def _do_user_revoke(self, payload):
        name = payload.get("name") or payload.get("username")
        name = str(name).strip() if name is not None else ""
        if not USER_RE.match(name):
            return {"ok": False, "code": 400, "error": "invalid user name"}
        return admin_call("revoke", {"username": name})

    # ---- прочие методы ----

    def do_HEAD(self):
        return self.do_GET()

    def do_PUT(self):
        return self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

    def do_DELETE(self):
        return self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

    def do_OPTIONS(self):
        return self._error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")


# --------------------------------------------------------------------------
# запуск
# --------------------------------------------------------------------------

def parse_listen(value):
    text = str(value or "").strip()
    if not text:
        raise ValueError("empty listen address")
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or not text[end + 1:].startswith(":"):
            raise ValueError("expected [addr]:port")
        host, port = text[1:end], text[end + 2:]
    else:
        host, sep, port = text.rpartition(":")
        if not sep:
            raise ValueError("expected host:port")
    port_num = int(port)
    if not 1 <= port_num <= 65535:
        raise ValueError("port out of range")
    return host or "0.0.0.0", port_num


def make_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    try:
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!RC4:!3DES")
    except ssl.SSLError:
        pass
    return ctx


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, handler, ssl_context):
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, handler)
        self.ssl_context = ssl_context

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(30)
        try:
            tls = self.ssl_context.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            log("tls handshake failed: %s" % exc.__class__.__name__, "WARN")
            try:
                sock.close()
            except OSError:
                pass
            raise
        tls.settimeout(None)
        return tls, addr


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=APP_NAME, description="XIO WebUI — TLS-панель управления сервером XIO")
    parser.add_argument("--listen", default="127.0.0.1:10443",
                        help="адрес и порт, по умолчанию 127.0.0.1:10443")
    parser.add_argument("--regenerate-cert", action="store_true",
                        help="пересоздать самоподписанный сертификат")
    parser.add_argument("--version", action="version", version="%s %s" % (APP_NAME, APP_VERSION))
    args = parser.parse_args(argv)

    try:
        host, port = parse_listen(args.listen)
    except ValueError as exc:
        sys.stderr.write("%s: %s\n" % (APP_NAME, exc))
        return 2

    os.umask(0o077)
    TLS_DIR.mkdir(parents=True, exist_ok=True)
    generated = ensure_certificate(host, regenerate=args.regenerate_cert)
    run_command([SYSTEMCTL, "show", "xio-ready", "--no-pager", "-p", "ActiveState"], None, 5)

    ctx = make_tls_context()
    try:
        httpd = TLSServer((host, port), Handler, ctx)
    except OSError as exc:
        sys.stderr.write("%s: cannot bind %s:%s: %s\n" % (APP_NAME, host, port, exc))
        log("bind failed %s:%s" % (host, port), "ERROR")
        return 1

    log("%s %s started on https://%s:%s (cert_generated=%s)"
        % (APP_NAME, APP_VERSION, host, port, generated))
    sys.stdout.write("%s %s\n" % (APP_NAME, APP_VERSION))
    sys.stdout.write("listen: https://%s:%s/\n" % (host if host not in ("0.0.0.0", "::") else "127.0.0.1", port))
    sys.stdout.write("token:  %s\n" % TOKEN_FILE)
    sys.stdout.write("cert:   %s\n" % CERT_FILE)
    sys.stdout.write("sha256: %s\n" % cert_fingerprint())
    sys.stdout.flush()

    def _shutdown(_signum, _frame):
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        log("%s stopped" % APP_NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
