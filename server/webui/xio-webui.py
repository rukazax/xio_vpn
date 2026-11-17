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
  * токен печатается только в интерактивный терминал: при запуске из systemd
    секрет не попадает в журнал (journalctl), а остаётся в файле 0600;
  * сравнение секретов через hmac.compare_digest;
  * CSRF-заголовок X-XIO-CSRF на всех POST;
  * rate-limit: 5 неудачных попыток аутентификации с адреса -> блокировка;
  * диагностический канал /api/diag: отдельный токен X-XIO-Diag-Token,
    только gzip/json/plain до 8 МиБ, отдельный каталог 0700 и лимит загрузок;
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
APP_VERSION = "1.1.0"

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

# диагностика: отдельный токен, отдельный каталог, отдельные лимиты
DIAG_TOKEN_FILE = BASE_DIR / "diag-token"
DIAG_DIR = Path("/var/lib/xio-webui/diag")
DIAG_HEADER = "X-XIO-Diag-Token"
DIAG_TYPES = ("application/gzip", "application/json", "text/plain")
DIAG_MAX_BODY = 8 * 1024 * 1024
DIAG_MAX_BYTES = 200 * 1024 * 1024
DIAG_UPLOADS_PER_HOUR = 30
DIAG_WINDOW = 3600
DIAG_LIST_LIMIT = 50
DIAG_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}-[0-9a-f]{8}\.json\.gz$")

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
    def __init__(self, path, announce=True):
        self.path = Path(path)
        self.announce = announce
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
            # Секрет печатаем только в интерактивный терминал. Под systemd stdout
            # уходит в журнал, а журнал переживает установку: токен оставался бы
            # читаемым для всех членов systemd-journal/adm и в `journalctl -xe`.
            # Для диагностического токена announce=False: он не печатается нигде.
            if self.announce and sys.stdout.isatty():
                sys.stdout.write("XIO WebUI token: %s\n" % raw)
            elif self.announce:
                sys.stdout.write(
                    "XIO WebUI token written to %s (0600); read it with: cat %s\n"
                    % (self.path, self.path))
            if self.announce:
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


class DiagLimiter(object):
    """Скользящее окно загрузок диагностики: не больше 30 в час на адрес."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def allow(self, ip):
        now = time.time()
        with self._lock:
            bucket = [stamp for stamp in self._hits.get(ip, ()) if now - stamp < DIAG_WINDOW]
            if len(bucket) >= DIAG_UPLOADS_PER_HOUR:
                self._hits[ip] = bucket
                return False
            bucket.append(now)
            self._hits[ip] = bucket
            if len(self._hits) > 4096:  # не храним вечно адреса, которые давно молчат
                self._hits = {key: value for key, value in self._hits.items()
                              if value and now - value[-1] < DIAG_WINDOW}
            return True


TOKENS = TokenStore(TOKEN_FILE)
SESSIONS = Sessions()
LIMITER = RateLimiter()
DIAG_TOKENS = TokenStore(DIAG_TOKEN_FILE, announce=False)
DIAG_UPLOADS = DiagLimiter()
DIAG_LOCK = threading.Lock()
DIAG_READY = False
STATE_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# диагностика: каталог, атомарная запись, список, чтение, лимит диска
# --------------------------------------------------------------------------

def ensure_diag_dir():
    """Готовит каталог диагностики 0700. Ошибка ФС не роняет панель: канал выключен."""
    global DIAG_READY
    try:
        DIAG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(str(DIAG_DIR), 0o700)
    except OSError as exc:
        DIAG_READY = False
        log("diag disabled: %s: %s" % (exc.__class__.__name__, DIAG_DIR), "WARN")
        return False
    DIAG_READY = True
    log("diag ingest enabled: dir=%s mode=0700 token_file=%s" % (DIAG_DIR, DIAG_TOKEN_FILE))
    return True


def _diag_name():
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    return "%s-%s.json.gz" % (stamp, secrets.token_hex(4))


def _diag_prune_locked(keep):
    """Удаляет самые старые загрузки, пока каталог не впишется в DIAG_MAX_BYTES.

    Только что принятый файл не удаляется: иначе кап меньше одного бандла
    превращал бы успешную загрузку в пустой список.
    """
    try:
        entries = []
        total = 0
        for item in DIAG_DIR.iterdir():
            if not DIAG_ID_RE.match(item.name):
                continue
            try:
                stat = item.stat()
            except OSError:
                continue
            entries.append((stat.st_mtime, item.name, stat.st_size))
            total += stat.st_size
    except OSError as exc:
        log("diag prune skipped: %s" % exc.__class__.__name__, "WARN")
        return
    removed = 0
    for _mtime, name, size in sorted(entries):
        if total <= DIAG_MAX_BYTES:
            break
        if name == keep:
            continue
        try:
            os.unlink(str(DIAG_DIR / name))
        except OSError:
            continue
        total -= size
        removed += 1
    if removed:
        log("diag pruned %d oldest file(s), %d bytes kept" % (removed, total), "WARN")


def diag_save(body):
    """Атомарно сохраняет тело (*.part -> os.replace). Возвращает id или None."""
    with DIAG_LOCK:
        name = _diag_name()
        path = DIAG_DIR / name
        tmp = DIAG_DIR / (name + ".part")
        try:
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                view = memoryview(body)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
            finally:
                os.close(fd)
            os.chmod(str(tmp), 0o600)
            os.replace(str(tmp), str(path))
            os.chmod(str(path), 0o600)
        except OSError as exc:
            try:
                os.unlink(str(tmp))
            except OSError:
                pass
            log("diag write failed: %s" % exc.__class__.__name__, "ERROR")
            return None
        _diag_prune_locked(name)
        return name


def diag_list():
    """Новые сверху, не больше DIAG_LIST_LIMIT записей."""
    with DIAG_LOCK:
        try:
            entries = []
            for item in DIAG_DIR.iterdir():
                if not DIAG_ID_RE.match(item.name):
                    continue
                try:
                    stat = item.stat()
                except OSError:
                    continue
                entries.append((stat.st_mtime, item.name, stat.st_size))
        except OSError:
            return []
    entries.sort(key=lambda entry: (entry[0], entry[1]), reverse=True)
    return [{"id": name, "size": size, "mtime": int(mtime)}
            for mtime, name, size in entries[:DIAG_LIST_LIMIT]]


def diag_read(name):
    """Читает файл с уже проверенным id. Возвращает bytes или None."""
    if not DIAG_ID_RE.match(name or ""):
        return None
    with DIAG_LOCK:
        try:
            return (DIAG_DIR / name).read_bytes()
        except OSError:
            return None


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


MAX_ADMIN_OUTPUT = 16 * 1024 * 1024
ADMIN_ERRORS = {
    'INVALID_REQUEST': 'Invalid request', 'SERVER_IDENTITY': 'Server identity changed; refresh the page',
    'OWNER_REQUIRED': 'Owner access required', 'UNAVAILABLE': 'Managed admin unavailable',
    'INVALID_RESULT': 'Invalid managed admin response', 'TIMEOUT': 'Operation timed out',
    'OPERATION_FAILED': 'Operation failed; runtime effects may be partial',
    'MODULE_UNAVAILABLE': 'Native module unavailable', 'PREFLIGHT_FAILED': 'Native observation unavailable',
    'IO_FAILURE': 'Operation I/O failed',
    'KEY_UNAVAILABLE': 'Pinned WireGuard key utility unavailable; no user creation was attempted',
}


def failure(code, error_code, unknown=False):
    return {'schema': 1, 'ok': False, 'code': code, 'errorCode': error_code,
            'error': ADMIN_ERRORS[error_code], 'outcomeUnknown': bool(unknown)}


def valid_identity(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9-]{1,80}', value) is not None


def valid_uid(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{32}', value) is not None


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite JSON')
    def number(text):
        value = float(text)
        if value in (float('inf'), float('-inf')):
            raise ValueError('non-finite JSON')
        return value
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    pending, count = [(result, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 500000:
            raise ValueError('JSON complexity limit')
        if isinstance(value, dict):
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
    return result


def run_admin_command(argv, input_bytes, timeout):
    """Bounded intact protocol capture, no stderr retention, one total deadline.

    Admin children inherit a separate POSIX session. Killing that session on an
    unknown result bounds pipe readers too; it is NOT a transactional rollback.
    """
    started = time.monotonic()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=SAFE_ENV, shell=False,
                                start_new_session=(os.name == 'posix'))
    except OSError:
        return {'rc': 127, 'out': '', 'timeout': False, 'started': False}
    output = bytearray()
    done = threading.Event()
    invalid = threading.Event()
    def read():
        try:
            while True:
                chunk = proc.stdout.read1(8192)
                if not chunk:
                    break
                if len(output) + len(chunk) > MAX_ADMIN_OUTPUT:
                    invalid.set()
                    break
                output.extend(chunk)
        except (OSError, ValueError):
            invalid.set()
        finally:
            done.set()
    def send():
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
        except (OSError, ValueError):
            invalid.set()
    reader = threading.Thread(target=read, daemon=True)
    writer = threading.Thread(target=send, daemon=True)
    reader.start(); writer.start()
    expired = not done.wait(max(0, timeout - (time.monotonic() - started)))
    if not expired and not invalid.is_set():
        try:
            proc.wait(timeout=max(0, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            expired = True
    if expired or invalid.is_set():
        try:
            if os.name == 'posix':
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    reader.join(timeout=1); writer.join(timeout=1)
    if reader.is_alive() or writer.is_alive():
        invalid.set()
    if not reader.is_alive():
        proc.stdout.close()
    try:
        text = output.decode('utf-8') if not invalid.is_set() and not expired else ''
    except UnicodeDecodeError:
        text = ''
    return {'rc': proc.returncode, 'out': text, 'timeout': expired, 'started': True}


def admin_call(action, payload, timeout=TIMEOUT_ADMIN):
    """Fixed owner CLI: no argv action, flattened JSON envelope on stdin/stdout."""
    fields = {'inspect': set(), 'status': {'serverId'},
              'add': {'serverId', 'id', 'name', 'publicKeys', 'rivet', 'admin', 'userLimit'},
              'revoke': {'serverId', 'id'}, 'service': {'serverId', 'unit', 'verb'},
              'cascade-native': {'serverId', 'operation'}}
    if action not in fields or type(payload) is not dict or set(payload) != fields[action]:
        return failure(400, 'INVALID_REQUEST')
    if action != 'inspect' and not valid_identity(payload.get('serverId')):
        return failure(400, 'INVALID_REQUEST')
    if action == 'revoke' and not valid_uid(payload.get('id')):
        return failure(400, 'INVALID_REQUEST')
    if action == 'add' and not valid_add_request(payload):
        return failure(400, 'INVALID_REQUEST')
    if action == 'service' and (payload.get('unit') not in UNITS or payload.get('verb') not in SYSTEMCTL_VERBS):
        return failure(400, 'INVALID_REQUEST')
    if action == 'cascade-native' and payload.get('operation') != 'inspect':
        return failure(400, 'INVALID_REQUEST')
    body = json.dumps(dict(payload, action=action), ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(body) > 32768:
        return failure(413, 'INVALID_REQUEST')
    if not os.path.isfile(ADMIN_PY):
        return failure(502, 'UNAVAILABLE')
    mutation = action in ('add', 'revoke', 'service')
    res = run_admin_command([sys.executable or 'python3', ADMIN_PY], body, timeout)
    unknown = mutation and res.get('started', True)
    if res.get('timeout'):
        return failure(504, 'TIMEOUT', unknown)
    try:
        parsed = strict_json(res['out'])
    except (ValueError, TypeError, RecursionError):
        parsed = None
    if type(parsed) is not dict or type(parsed.get('ok')) is not bool:
        return failure(502, 'INVALID_RESULT', unknown)
    if parsed['ok'] is False:
        # Generic failures may follow partial effects. Only typed native errors
        # carry a finite no-effects guarantee (this UI only inspects native).
        code = parsed.get('errorCode') if action == 'cascade-native' else None
        if type(code) is not str or code not in ('OWNER_REQUIRED', 'SERVER_IDENTITY', 'INVALID_REQUEST', 'MODULE_UNAVAILABLE', 'PREFLIGHT_FAILED', 'INVALID_RESULT', 'TIMEOUT', 'IO_FAILURE', 'OPERATION_FAILED'):
            code = 'OPERATION_FAILED'
        if action == 'cascade-native' and type(parsed.get('outcomeUnknown')) is bool:
            unknown = parsed['outcomeUnknown']
        if parsed.get('error') in ('Server identity changed', 'Server identity changed; reopen setup'):
            return failure(409, 'SERVER_IDENTITY', unknown)
        return failure(502, code, unknown)
    if res['rc'] != 0:
        return failure(502, 'INVALID_RESULT', unknown)
    try:
        if action in ('inspect', 'status', 'cascade-native'):
            server = parsed['server']
            if type(server) is not dict or not valid_identity(server.get('id')):
                raise ValueError()
            if action != 'inspect' and server['id'] != payload['serverId']:
                # Positively observed identity conflict is not optional-module
                # unavailability: build_state must discard the whole snapshot.
                return failure(409, 'SERVER_IDENTITY', unknown)
        if action == 'inspect':
            if parsed.get('phase') not in ('ready', 'installing'):
                raise ValueError()
            data = {'server': project_server(server), 'phase': parsed['phase']}
        elif action == 'status':
            data = project_status(parsed)
        elif action == 'cascade-native':
            data = {'server': project_server(server), 'nativeCascade': project_native(parsed['nativeCascade'])}
        elif action == 'add':
            data = project_issuance_add(parsed, payload)
        elif action == 'revoke':
            if parsed.get('revoked') != payload['id']:
                raise ValueError()
            # The successful guarded admin operation belongs to this submitted
            # identity, never a newly observed/current deployment.
            data = {'revoked': payload['id'], 'serverId': payload['serverId']}
        else:
            if parsed.get('service') != {'unit': payload['unit'], 'verb': payload['verb'], 'serverId': payload['serverId']}:
                raise ValueError()
            data = {'service': parsed['service']}
    except (KeyError, TypeError, ValueError, OverflowError):
        return failure(502, 'INVALID_RESULT', unknown)
    return {'schema': 1, 'ok': True, 'code': 200, 'outcomeUnknown': False, 'data': data}


def project_server(value):
    return {'id': value['id'],
            'host': value.get('host') if type(value.get('host')) is str else None,
            'recipeVersion': value.get('recipeVersion') if type(value.get('recipeVersion')) is int else None}


def counter(value):
    return value if type(value) is int and 0 <= value <= 9007199254740991 else None


def project_status(value):
    if type(value.get('users')) is not list or len(value['users']) > 10000:
        raise ValueError()
    users, seen = [], set()
    total = {'rx': 0, 'tx': 0}
    for user in value['users']:
        if type(user) is not dict or not valid_uid(user.get('id')) or user['id'] in seen:
            raise ValueError()
        if type(user.get('name')) is not str or len(user['name']) > 80 or type(user.get('revoked')) is not bool:
            raise ValueError()
        seen.add(user['id'])
        users.append({'id': user['id'], 'name': user['name'], 'revoked': user['revoked'],
                      'role': user.get('role') if user.get('role') in ('user', 'admin') else 'unknown',
                      'online': user.get('online') if type(user.get('online')) is bool else None,
                      'status': 'revoked' if user['revoked'] else 'active'})
        stats = user.get('stats')
        for direction in total:
            if type(stats) is not dict or not stats:
                total[direction] = None
                continue
            for entry in stats.values():
                n = counter(entry.get(direction)) if type(entry) is dict else None
                if n is None or total[direction] is None:
                    total[direction] = None
                else:
                    total[direction] = counter(total[direction] + n)
    sampled = counter(value.get('sampledAt'))
    if not sampled or sampled > time.time() + 5:
        sampled = None
        total = {'rx': None, 'tx': None}
    return {'server': project_server(value['server']), 'users': users,
            'sampledAt': sampled, 'traffic': total}


def project_native(value):
    if type(value) is not dict or type(value.get('schema')) is not int or value['schema'] != 1 or type(value.get('enabled')) is not bool:
        raise ValueError()
    if not value['enabled']:
        return {'available': True, 'enabled': False}
    phase = value.get('phase')
    if phase not in ('prepared', 'applying', 'guarded', 'applied', 'preparation_failed', 'apply_failed', 'fail_closed', 'removing', 'removed'):
        raise ValueError()
    if type(value.get('infrastructureReady')) is not bool:
        raise ValueError()
    connector, revision = value.get('connectorId'), value.get('revision')
    if type(connector) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', connector):
        raise ValueError()
    if not ((type(revision) is int and revision >= 0) or (type(revision) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', revision))):
        raise ValueError()
    result = {'available': True, 'enabled': True, 'phase': phase, 'connectorId': connector,
              'revision': revision, 'infrastructureReady': value['infrastructureReady'],
              'guardState': value.get('guardState') if value.get('guardState') in ('unknown', 'last_installed') else 'unknown',
              'families': [], 'readiness': None}
    config = value.get('config')
    if type(config) is dict and type(config.get('innerFamilies')) is list:
        result['families'] = [f for f in config['innerFamilies'] if f in ('ipv4', 'ipv6')]
    caps = value.get('capabilities')
    if type(caps) is dict:
        try:
            if type(caps.get('schema')) is not int or caps['schema'] != 1 or caps.get('enabled') is not True:
                raise ValueError()
            for key in ('observedAt', 'expiresAt'):
                if type(caps.get(key)) is not str or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)', caps[key]):
                    raise ValueError()
            observed = datetime.datetime.fromisoformat(caps['observedAt'].replace('Z', '+00:00')).timestamp()
            expires = datetime.datetime.fromisoformat(caps['expiresAt'].replace('Z', '+00:00')).timestamp()
            now = time.time()
            fresh = (observed <= now + 5 and now < expires and 0 < expires - observed <= 60 and now - observed <= 60
                     and caps.get('connectorId') == connector and caps.get('revision') == revision
                     and phase == 'applied' and value['infrastructureReady'])
            readiness = {}
            for protocol in ('awg', 'rivet'):
                entry = caps[protocol]
                if type(entry) is not dict or any(type(entry.get(f)) is not bool for f in ('ipv4', 'ipv6')):
                    raise ValueError()
                readiness[protocol] = {f: entry[f] and fresh for f in ('ipv4', 'ipv6')}
            result['readiness'] = readiness
            result['fresh'] = bool(fresh)
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            pass
    return result


# --------------------------------------------------------------------------
# One-response client issuance. Private material exists only in this process
# and in the final HTTP response; managed admin receives public peer keys.
# --------------------------------------------------------------------------

WG_CANDIDATES = ('/usr/bin/wg', '/usr/local/bin/wg', '/bin/wg')
AWG_NUMERIC_KEYS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4'}
AWG_RANGE_KEYS = {'H1', 'H2', 'H3', 'H4'}
AWG_TEXT_KEYS = {'I1', 'I2', 'I3', 'I4', 'I5'}


def valid_user_name(value):
    return type(value) is str and 0 < len(value.strip()) <= 80


def decode_base64_key(value, size=32, reject_zero=True):
    if type(value) is not str:
        raise ValueError('key type')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        raise ValueError('key encoding')
    if len(raw) != size or base64.b64encode(raw).decode('ascii') != value:
        raise ValueError('key encoding')
    if reject_zero and raw == b'\x00' * size:
        raise ValueError('zero key')
    return raw


def valid_add_request(payload):
    if not valid_uid(payload.get('id')) or not valid_user_name(payload.get('name')):
        return False
    if payload.get('admin') is not False or type(payload.get('userLimit')) is not int \
            or payload['userLimit'] != 0:
        return False
    keys = payload.get('publicKeys')
    if type(keys) is not dict or set(keys) != {'wireguard', 'awg'}:
        return False
    try:
        for protocol in ('wireguard', 'awg'):
            decode_base64_key(keys[protocol])
        rivet = payload.get('rivet')
        if type(rivet) is not dict or set(rivet) != {'secret', 'entryToken'}:
            return False
        secret = decode_base64_key(rivet['secret'])
        token = decode_base64_key(rivet['entryToken'])
    except (KeyError, ValueError, TypeError):
        return False
    return secret != token


def _pinned_wg():
    for candidate in WG_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


class KeyUtilityUnavailable(Exception):
    pass


def generate_peer_key():
    """WireGuard/X25519 via the installed pinned utility, never via disk/argv."""
    executable = _pinned_wg()
    if executable is None:
        raise KeyUtilityUnavailable()
    try:
        private_result = run_admin_command([executable, 'genkey'], b'', 8)
        if private_result.get('rc') != 0 or private_result.get('timeout') \
                or not private_result.get('started'):
            raise KeyUtilityUnavailable()
        private = private_result.get('out', '').strip()
        decode_base64_key(private)
        public_result = run_admin_command(
            [executable, 'pubkey'], (private + '\n').encode('ascii'), 8)
        if public_result.get('rc') != 0 or public_result.get('timeout') \
                or not public_result.get('started'):
            raise KeyUtilityUnavailable()
        public = public_result.get('out', '').strip()
        decode_base64_key(public)
    except (ValueError, TypeError, AttributeError):
        raise KeyUtilityUnavailable()
    if private == public:
        raise KeyUtilityUnavailable()
    return private, public


def generate_issuance_material():
    # Both keys are required by the actual managed add protocol, including on a
    # restricted host where only AWG is exported for Android.
    public, private = {}, {}
    for protocol in ('wireguard', 'awg'):
        private[protocol], public[protocol] = generate_peer_key()
    return {
        'id': secrets.token_hex(16),
        'public': public,
        'private': private,
        'rivet': {
            'secret': base64.b64encode(secrets.token_bytes(32)).decode('ascii'),
            'entryToken': base64.b64encode(secrets.token_bytes(32)).decode('ascii'),
        },
    }


def normalize_server_host(value):
    """Python equivalent of app/lib/server_address.dart normalizeServerHost."""
    if type(value) is not str:
        raise ValueError('host type')
    host = value.strip()
    if not host or len(host) > 253 or '%' in host:
        raise ValueError('host')
    bracketed = host.startswith('[') or host.endswith(']')
    if bracketed:
        if not (host.startswith('[') and host.endswith(']')):
            raise ValueError('host')
        host = host[1:-1]
    try:
        family = socket.AF_INET6 if bracketed or ':' in host else socket.AF_INET
        packed = socket.inet_pton(family, host)
        return socket.inet_ntop(family, packed)
    except OSError:
        pass
    if bracketed or ':' in host or re.fullmatch(r'[0-9.]+', host):
        raise ValueError('host')
    name = host[:-1] if host.endswith('.') else host
    labels = name.split('.')
    if not name or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$', label)
                       for label in labels):
        raise ValueError('host')
    return host


def server_endpoint(host, port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('port')
    host = normalize_server_host(host)
    return ('[%s]:%d' if ':' in host else '%s:%d') % (host, port)


def project_awg_extensions(value):
    if type(value) is not dict:
        raise ValueError('awg')
    result = {}
    allowed = AWG_NUMERIC_KEYS | AWG_RANGE_KEYS | AWG_TEXT_KEYS
    for key, raw in value.items():
        if key not in allowed or type(raw) not in (str, int) or type(raw) is bool:
            raise ValueError('awg extension')
        text = str(raw).strip()
        if '\x00' in text or '\r' in text or '\n' in text or len(text) > 8192:
            raise ValueError('awg extension')
        if key in AWG_NUMERIC_KEYS:
            if not re.fullmatch(r'\d+', text):
                raise ValueError('awg number')
            number = int(text)
            if number > (128 if key == 'Jc' else 1280):
                raise ValueError('awg number')
        elif key in AWG_RANGE_KEYS:
            parts = text.split('-')
            if len(parts) > 2 or any(not re.fullmatch(r'\d+', part) for part in parts):
                raise ValueError('awg range')
            numbers = [int(part) for part in parts]
            if any(number > 4294967295 for number in numbers) \
                    or len(numbers) == 2 and numbers[0] > numbers[1]:
                raise ValueError('awg range')
        result[key] = text
    if int(result.get('Jmin', '0')) > int(result.get('Jmax', '1280')):
        raise ValueError('awg J range')
    return result


def project_rivet_metadata(value):
    if type(value) is not dict:
        raise ValueError('rivet')
    result = {
        'serverName': normalize_server_host(value.get('serverName')),
        'pin': value.get('pin'),
        'gatewayId': value.get('gatewayId'),
        'ipv6': value.get('ipv6') is True,
    }
    if value.get('ipv6') is not None and type(value.get('ipv6')) is not bool:
        raise ValueError('rivet ipv6')
    decode_base64_key(result['pin'], 32)
    decode_base64_key(result['gatewayId'], 16)
    if value.get('outerCA') is not None:
        if type(value['outerCA']) is not str or len(value['outerCA']) > 8192:
            raise ValueError('outer CA')
        result['outerCA'] = value['outerCA']
    return result


def _readiness_time(value):
    if type(value) is not str or not re.fullmatch(
            r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)', value):
        raise ValueError('readiness time')
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() != datetime.timedelta(0) \
            or parsed.strftime('%Y-%m-%dT%H:%M:%S') != value[:19]:
        raise ValueError('readiness time')
    return parsed.timestamp()


def project_native_readiness(value):
    if type(value) is not dict or value.get('schema') != 1 or type(value.get('schema')) is bool \
            or value.get('enabled') is not True:
        raise ValueError('native readiness')
    connector = value.get('connectorId')
    revision = value.get('revision')
    if type(connector) is not str or not connector or connector != connector.strip():
        raise ValueError('native identity')
    if type(revision) is bool or not (
            type(revision) is int and revision >= 0
            or type(revision) is str and bool(revision) and revision == revision.strip()):
        raise ValueError('native revision')
    observed = _readiness_time(value.get('observedAt'))
    expires = _readiness_time(value.get('expiresAt'))
    now = time.time()
    if observed > now + 5 or expires <= now or expires <= observed \
            or expires - observed > 60 or now - observed > 60:
        raise ValueError('stale readiness')
    entries, required = {}, {}
    for protocol in ('awg', 'rivet'):
        entry = value.get(protocol)
        wanted = value.get('requiredFamilies', {}).get(protocol) \
            if type(value.get('requiredFamilies')) is dict else None
        if type(entry) is not dict or type(wanted) is not dict:
            raise ValueError('native families')
        for family in ('ipv4', 'ipv6'):
            if type(entry.get(family)) is not bool or type(wanted.get(family)) is not bool:
                raise ValueError('native family')
            if wanted[family] and entry[family] is not True:
                raise ValueError('native family down')
        entries[protocol] = {family: entry[family] for family in ('ipv4', 'ipv6')}
        required[protocol] = {family: wanted[family] for family in ('ipv4', 'ipv6')}
    return {
        'schema': 1, 'enabled': True, 'connectorId': connector, 'revision': revision,
        'observedAt': value['observedAt'], 'expiresAt': value['expiresAt'],
        'awg': entries['awg'], 'rivet': entries['rivet'], 'requiredFamilies': required,
    }


def project_issuance_server(value, expected_server_id):
    if type(value) is not dict or value.get('id') != expected_server_id:
        raise ValueError('issuance identity')
    public_keys = value.get('publicKeys')
    if type(public_keys) is not dict:
        raise ValueError('public keys')
    awg_public = public_keys.get('awg')
    decode_base64_key(awg_public)
    result = {
        'id': expected_server_id,
        'host': normalize_server_host(value.get('host')),
        'publicKeys': {'awg': awg_public},
        'awg': project_awg_extensions(value.get('awg')),
    }
    if value.get('rivet') is not None:
        result['rivet'] = project_rivet_metadata(value['rivet'])
    if 'nativeProfileReadiness' in value:
        result['nativeProfileReadiness'] = project_native_readiness(value['nativeProfileReadiness'])
    return result


def _no_unsafe_xray(value):
    if type(value) is dict:
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered.endswith('file') or lowered == 'allowinsecure' and item is not False \
                    or lowered in {'sockopt', 'dialerproxy', 'proxysettings', 'downloadsettings', 'reverse'}:
                raise ValueError('unsafe xray')
            _no_unsafe_xray(item)
    elif type(value) is list:
        for item in value:
            _no_unsafe_xray(item)


def _valid_reality_key(value):
    if type(value) is not str or not value or len(value) > 100 \
            or not re.fullmatch(r'[A-Za-z0-9_=-]+', value):
        raise ValueError('reality key')
    try:
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except ValueError:
        raise ValueError('reality key')
    if len(raw) != 32:
        raise ValueError('reality key')


def normalize_xray_profile(raw):
    """Validate the actual stack.create VLESS JSON and return ExtendedProfile form."""
    if type(raw) is not str or len(raw) > 65536 or '\x00' in raw:
        raise ValueError('xray')
    parsed = strict_json(raw)
    if type(parsed) is not dict or set(parsed) != {'protocol', 'outbound'} \
            or parsed.get('protocol') != 'xray' or type(parsed.get('outbound')) is not dict:
        raise ValueError('xray envelope')
    outbound = parsed['outbound']
    if set(outbound) - {'protocol', 'settings', 'streamSettings', 'mux', 'tag'} \
            or outbound.get('protocol') != 'vless':
        raise ValueError('xray outbound')
    _no_unsafe_xray(outbound)
    settings = outbound.get('settings')
    if type(settings) is not dict:
        raise ValueError('xray settings')
    servers = settings.get('vnext')
    if type(servers) is not list or len(servers) != 1 or type(servers[0]) is not dict:
        raise ValueError('xray vnext')
    server = servers[0]
    normalize_server_host(server.get('address'))
    port = server.get('port')
    if type(port) is bool or not re.fullmatch(r'\d+', str(port)) \
            or not 1 <= int(str(port)) <= 65535:
        raise ValueError('xray port')
    users = server.get('users')
    if type(users) is not list or len(users) != 1 or type(users[0]) is not dict:
        raise ValueError('xray users')
    user = users[0]
    identifier = user.get('id')
    if type(identifier) is not str or not re.fullmatch(
            r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', identifier):
        raise ValueError('xray UUID')
    if user.get('encryption') != 'none':
        raise ValueError('unsupported VLESS encryption')
    stream = outbound.get('streamSettings', {})
    if type(stream) is not dict or stream.get('network', 'tcp') not in {
            'tcp', 'raw', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'splithttp'}:
        raise ValueError('xray transport')
    security = stream.get('security', 'none')
    if security not in ('tls', 'reality'):
        raise ValueError('xray security')
    if security == 'reality':
        reality = stream.get('realitySettings')
        if type(reality) is not dict:
            raise ValueError('reality settings')
        normalize_server_host(reality.get('serverName'))
        _valid_reality_key(reality.get('publicKey', reality.get('password')))
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', str(reality.get('shortId', ''))):
            raise ValueError('shortId')
    else:
        tls = stream.get('tlsSettings', {})
        if type(tls) is not dict:
            raise ValueError('tls settings')
        normalize_server_host(tls.get('serverName', server['address']))
    outbound['tag'] = 'proxy'
    return json.dumps({'protocol': 'xray', 'outbound': outbound},
                      ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def project_issuance_add(parsed, payload):
    user = parsed.get('user')
    if type(user) is not dict or user.get('id') != payload['id'] \
            or user.get('name') != payload['name'].strip() \
            or type(user.get('slot')) is not int or type(user.get('slot')) is bool \
            or not 2 <= user['slot'] <= 254 or user.get('revoked') is not False \
            or user.get('role') != 'user':
        raise ValueError('issued user')
    server = project_issuance_server(parsed.get('server'), payload['serverId'])
    if 'rivet' in server and user.get('rivet') is not True:
        raise ValueError('missing issued RIVET identity')
    configs = parsed.get('configs')
    if type(configs) is not dict:
        raise ValueError('issued configs')
    projected = {}
    # Removed/foreign transport configs are never forwarded. Current native
    # cascade readiness intentionally excludes legacy proxy profiles, as in app.
    if 'nativeProfileReadiness' not in server and 'xray' in configs:
        projected['xray'] = normalize_xray_profile(configs['xray'])
    return {
        'user': {'id': payload['id'], 'name': payload['name'].strip(), 'slot': user['slot']},
        'server': server,
        'configs': projected,
    }


def profile_readiness(server, protocol):
    if 'nativeProfileReadiness' not in server:
        ipv6 = True if protocol == 'awg' else server.get('rivet', {}).get('ipv6') is True
        return {'explicit': False, 'ipv4': True, 'ipv6': ipv6,
                'selected': True, 'captureIpv4': True, 'captureIpv6': ipv6}
    native = server['nativeProfileReadiness']
    wanted = native['requiredFamilies'][protocol]
    selected = wanted['ipv4'] or wanted['ipv6']
    return {'explicit': True, 'ipv4': wanted['ipv4'], 'ipv6': wanted['ipv6'],
            'selected': selected, 'captureIpv4': selected, 'captureIpv6': selected}


def profile_dns(server, readiness):
    if 'nativeProfileReadiness' in server:
        values = [value for family, value in (('ipv4', '9.9.9.9'), ('ipv6', '2620:fe::fe'))
                  if readiness[family]]
        if not values:
            raise ValueError('no DNS family')
        return ', '.join(values)
    if server.get('rivet', {}).get('ipv6') is True:
        return '9.9.9.9, 2620:fe::fe'
    return '9.9.9.9'


def build_xio_profile(projected, material):
    server, remote_user = projected['server'], projected['user']
    if remote_user['id'] != material['id']:
        raise ValueError('profile identity')
    host, slot = server['host'], remote_user['slot']
    configs = {}
    awg_readiness = profile_readiness(server, 'awg')
    rivet_readiness = profile_readiness(server, 'rivet')
    if rivet_readiness['explicit'] and rivet_readiness['selected'] and 'rivet' not in server:
        raise ValueError('selected RIVET is missing')
    if awg_readiness['selected']:
        addresses = [('10.78.0.%d/32' % slot) if awg_readiness['captureIpv4'] else None,
                     ('fd78:1::%x/128' % slot) if awg_readiness['captureIpv6'] else None]
        routes = ['0.0.0.0/0' if awg_readiness['captureIpv4'] else None,
                  '::/0' if awg_readiness['captureIpv6'] else None]
        extras = '\n'.join('%s = %s' % (key, value) for key, value in server['awg'].items())
        # This is byte-for-byte the Android createUser/provisioningBundle layout.
        configs['awg'] = (
            '[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = 1280\n%s\n\n'
            '[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n'
        ) % (material['private']['awg'], ', '.join(x for x in addresses if x),
             profile_dns(server, awg_readiness), extras, server['publicKeys']['awg'],
             server_endpoint(host, 51821), ', '.join(x for x in routes if x))
    if 'rivet' in server and rivet_readiness['selected']:
        meta = server['rivet']
        for protocol in ('rivet-h3', 'rivet-s1'):
            config = {
                'protocol': protocol, 'endpoint': server_endpoint(host, 8443),
                'serverName': meta['serverName'], 'pin': meta['pin'],
                'gatewayId': meta['gatewayId'], 'id': material['id'],
                'secret': material['rivet']['secret'],
                'entryToken': material['rivet']['entryToken'],
                'ip': '10.79.0.%d' % slot,
            }
            if rivet_readiness['ipv6']:
                config['ip6'] = 'fd79:1::%x' % slot
            if 'outerCA' in meta:
                config['outerCA'] = meta['outerCA']
            configs[protocol] = json.dumps(config, ensure_ascii=False,
                                           separators=(',', ':'), allow_nan=False)
    if 'nativeProfileReadiness' not in server:
        configs.update(projected['configs'])
    if not configs:
        raise ValueError('no selected native transport')
    if any(len(value) > 65536 for value in configs.values()):
        raise ValueError('profile size')
    document = {'schema': 1, 'name': remote_user['name'], 'userId': material['id'],
                'serverId': server['id'], 'configs': configs}
    encoded = base64.urlsafe_b64encode(json.dumps(
        document, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')).decode('ascii')
    profile = 'xio://' + encoded
    if len(profile) > 200000:
        raise ValueError('profile size')
    return profile


def issue_user(payload):
    if type(payload) is not dict or set(payload) != {'expectedServerId', 'name'} \
            or not valid_identity(payload.get('expectedServerId')) \
            or not valid_user_name(payload.get('name')):
        return failure(400, 'INVALID_REQUEST')
    try:
        material = generate_issuance_material()
    except KeyUtilityUnavailable:
        return failure(503, 'KEY_UNAVAILABLE')
    name = payload['name'].strip()
    request = {
        'serverId': payload['expectedServerId'], 'id': material['id'], 'name': name,
        'publicKeys': material['public'], 'rivet': material['rivet'],
        'admin': False, 'userLimit': 0,
    }
    result = admin_call('add', request)
    if not result['ok']:
        return result
    try:
        profile = build_xio_profile(result['data'], material)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        # An add may already have succeeded. Never compensate blindly or pretend
        # that a different fresh profile belongs to the same remote user.
        return failure(502, 'INVALID_RESULT', unknown=True)
    material.clear()
    return {'schema': 1, 'ok': True, 'code': 200, 'outcomeUnknown': False,
            'data': {'uid': request['id'], 'profile': profile}}


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
            info["error"] = "service observation unavailable"
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


def build_state():
    inspected = admin_call("inspect", {})
    status = None
    native = {'available': False, 'enabled': None}
    identity = None
    warnings = []
    server = {'hostname': socket.gethostname(), 'id': None, 'role': 'unknown',
              'version': None, 'cert_fingerprint': cert_fingerprint(),
              'admin_present': os.path.isfile(ADMIN_PY), 'uptime_seconds': _read_uptime()}
    if inspected['ok']:
        identity = inspected['data']['server']['id']
        server.update(inspected['data']['server'])
        server['phase'] = inspected['data']['phase']
        server['version'] = server.get('recipeVersion')
        result = admin_call('status', {'serverId': identity})
        if result['ok']:
            status = result['data']
            observed = admin_call('cascade-native', {'serverId': identity, 'operation': 'inspect'})
            if observed['ok']:
                native = observed['data']['nativeCascade']
            else:
                warnings.append(observed['error'])
                if observed.get('errorCode') == 'SERVER_IDENTITY':
                    status = None
        else:
            warnings.append(result['error'])
    else:
        warnings.append(inspected['error'])
    available = status is not None
    # An identity discovered by inspect is not a usable mutation context after
    # failed/mixed status observations. Do not fall back to deployment secrets.
    if not available:
        server['id'] = None
    services = unit_states()
    gateway = next((s['active'] for s in services if s['unit'] == CASCADE_UNIT), 'unknown')
    return {'schema': 1, 'ok': True, 'app': APP_NAME, 'app_version': APP_VERSION,
            'csrf': TOKENS.csrf, 'server': server, 'managedAvailable': available,
            'services': services, 'users': status['users'] if available else None,
            'users_source': 'admin.py status' if available else 'unavailable',
            'sampledAt': status['sampledAt'] if available else None,
            'traffic': status['traffic'] if available else {'rx': None, 'tx': None},
            'cascade': {'kind': 'legacy-rivet-gateway', 'state': gateway, 'unit': CASCADE_UNIT},
            'nativeCascade': native, 'whitelists': [], 'warnings': warnings}


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

    def _json(self, status, payload, extra_headers=None, close=False):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra_headers, close)

    def _error(self, status, message, extra_headers=None, close=False):
        self._json(status, {"ok": False, "error": message}, extra_headers, close)

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
        # диагностический канал живёт на своём токене: проверка ДО _authenticate
        if path == "/api/diag" or path.startswith("/api/diag/"):
            return self._do_diag_get(path)
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
        # диагностический канал: свой токен, свой лимит тела, без сессии и CSRF
        if path == "/api/diag":
            return self._do_diag_post()
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
                payload = strict_json(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError, RecursionError):
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
            result = self._do_service(arg, payload)
        elif action == "cascade":
            result = self._do_cascade(arg, payload)
        elif action == "user_add":
            result = self._do_user_add(payload)
        else:
            result = self._do_user_revoke(payload)
        log("action=%s arg=%s ip=%s status=%s ms=%d"
            % (action, arg or "-", self._client_ip(), result.get("code", 500),
               int((time.time() - started) * 1000)))
        return self._json(result.get("code", 500), result)

    def _do_service(self, verb, payload):
        if type(payload) is not dict or set(payload) != {'expectedServerId'}:
            return failure(400, 'INVALID_REQUEST')
        unit = self.headers.get('X-XIO-Unit')
        return admin_call('service', {'serverId': payload['expectedServerId'],
                                     'unit': unit, 'verb': verb})

    def _do_cascade(self, verb, payload):
        # Backwards-compatible endpoint name, explicitly legacy gateway only.
        if verb not in CASCADE_VERBS or type(payload) is not dict or set(payload) != {'expectedServerId'}:
            return failure(400, 'INVALID_REQUEST')
        return admin_call('service', {'serverId': payload['expectedServerId'],
                                     'unit': CASCADE_UNIT,
                                     'verb': 'start' if verb == 'enable' else 'stop'})

    def _do_user_add(self, payload):
        return issue_user(payload)

    def _do_user_revoke(self, payload):
        if type(payload) is not dict or set(payload) != {'expectedServerId', 'id'}:
            return failure(400, 'INVALID_REQUEST')
        return admin_call('revoke', {'serverId': payload['expectedServerId'], 'id': payload['id']})

    # ---- диагностика ----

    def _diag_authorize(self):
        """-> True, если X-XIO-Diag-Token верен; иначе ответ уже отправлен.

        Сравнение — через TokenStore.check (hmac.compare_digest). Сессия, Bearer
        и CSRF на этом канале не используются и не запрашиваются.
        """
        if not (DIAG_READY and DIAG_TOKENS.token):
            self._error(HTTPStatus.SERVICE_UNAVAILABLE, "diag unavailable", close=True)
            return False
        candidate = self.headers.get(DIAG_HEADER, "") or ""
        if candidate and DIAG_TOKENS.check(candidate):
            return True
        log("diag auth failed ip=%s path=%s" % (self._client_ip(), self._path()), "WARN")
        self._error(HTTPStatus.UNAUTHORIZED, "invalid diag token", close=True)
        return False

    def _do_diag_get(self, path):
        if not self._diag_authorize():
            return None
        if path == "/api/diag":
            return self._json(HTTPStatus.OK, diag_list())
        name = path[len("/api/diag/"):]
        if not DIAG_ID_RE.match(name):
            return self._error(HTTPStatus.BAD_REQUEST, "invalid diag id")
        body = diag_read(name)
        if body is None:
            return self._error(HTTPStatus.NOT_FOUND, "diag not found")
        return self._send(HTTPStatus.OK, body, "application/gzip",
                          [("Content-Disposition", 'attachment; filename="%s"' % name)])

    def _do_diag_post(self):
        # Тело читается ровно один раз; отказ до чтения закрывает соединение,
        # иначе остаток тела был бы разобран как следующий запрос.
        if not self._diag_authorize():
            return None
        lengths = self.headers.get_all("Content-Length") or []
        try:
            length = int(lengths[0]) if len(lengths) == 1 else -1
        except ValueError:
            length = -1
        # chunked/дублирующийся Content-Length не разбираем: иначе остаток тела
        # мог бы уехать следующим запросом.
        if self.headers.get("Transfer-Encoding") or length <= 0 or length > DIAG_MAX_BODY:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               "body size 1..%d required" % DIAG_MAX_BODY, close=True)
        if not DIAG_UPLOADS.allow(self._client_ip()):
            log("diag upload rate-limited ip=%s" % self._client_ip(), "WARN")
            return self._error(HTTPStatus.TOO_MANY_REQUESTS,
                               "too many uploads, retry later", close=True)
        buf = bytearray()
        while len(buf) < length:
            chunk = self.rfile.read(length - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        if len(buf) != length:
            return self._error(HTTPStatus.BAD_REQUEST, "incomplete body", close=True)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype not in DIAG_TYPES:
            return self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                               "application/gzip, application/json or text/plain required")
        if ctype == "application/gzip" and bytes(buf[:2]) != b"\x1f\x8b":
            return self._error(HTTPStatus.BAD_REQUEST, "gzip magic expected")
        name = diag_save(bytes(buf))
        if name is None:
            return self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "diag storage unavailable")
        log("diag upload ip=%s id=%s bytes=%d" % (self._client_ip(), name, length))
        return self._json(HTTPStatus.OK, {"ok": True, "id": name})

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
    connection_limit = 32
    handshake_timeout = 5
    http_idle_timeout = 15
    request_deadline = 60

    def __init__(self, address, handler, ssl_context):
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        super().__init__(address, handler)
        self.ssl_context = ssl_context
        self._connection_slots = threading.BoundedSemaphore(self.connection_limit)

    def process_request(self, request, client_address):
        # Admission happens before creating a worker. A slow TLS client cannot
        # block accept(), and unlimited sockets cannot create unlimited threads.
        if not self._connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    @staticmethod
    def _expire_connection(connection):
        # An absolute deadline also closes trickled headers/body: an idle timeout
        # alone can be defeated by sending one byte before each timeout expires.
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def process_request_thread(self, request, client_address):
        connection = request
        deadline = None
        try:
            request.settimeout(self.handshake_timeout)
            connection = self.ssl_context.wrap_socket(request, server_side=True)
            connection.settimeout(self.http_idle_timeout)
            deadline = threading.Timer(
                self.request_deadline, self._expire_connection, (connection,))
            deadline.daemon = True
            deadline.start()
            self.finish_request(connection, client_address)
        except (ssl.SSLError, OSError) as exc:
            log("TLS/HTTP connection failed: %s" % exc.__class__.__name__, "WARN")
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            if deadline is not None:
                deadline.cancel()
            try:
                self.shutdown_request(connection)
            finally:
                self._connection_slots.release()


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
    ensure_diag_dir()
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
