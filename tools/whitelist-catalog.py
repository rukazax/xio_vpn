#!/usr/bin/env python3
"""Build the white-SNI catalog used by XIO entry masking (SNI-only filtering).

The catalog answers one question: which exact FQDNs from the community white list are
usable as an outer SNI (Xray REALITY serverName/dest, RIVET/S1) *from this server*.
It does not translate domains into routes: the client split-routing accepts IP/CIDR only,
and ip+sni operator filtering is out of scope (see docs).

Exit codes: 0 ok, 2 source unreachable, 3 digest/pin mismatch or unusable input,
4 not enough eligible entries or the time budget was exceeded, 5 write/lock failure.
"""
from concurrent.futures import ThreadPoolExecutor
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # Linux servers take the flock; Windows has no fcntl
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows only
    fcntl = None

MAX_BYTES = 5 * 1024 * 1024
MAX_LINES = 20000
MAX_NAME = 253
MAX_ENTRIES = 5000
ALLOWED_HOSTS = {'raw.githubusercontent.com'}
LABEL = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$')
RECORD = re.compile(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$')


class Refused(Exception):
    """Input that must not be published (maps to exit code 3)."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical(entries):
    """Deterministic content hash: only identity, eligibility and resolved addresses."""
    rows = [[e['fqdn'], e['eligible'], sorted(e.get('resolved') or [])] for e in sorted(entries, key=lambda x: x['fqdn'])]
    payload = json.dumps(rows, separators=(',', ':'), sort_keys=True)
    return sha256_bytes(payload.encode('utf-8'))


def load_pin(path):
    try:
        pin = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise Refused('pin missing or unreadable: ' + str(error))
    if pin.get('schema') != 1 or not pin.get('source') or not re.fullmatch(r'[a-f0-9]{64}', pin.get('sha256', '')):
        raise Refused('pin file is invalid')
    return pin


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused('source redirected to ' + urllib.parse.urlsplit(newurl).netloc)


def fetch_source(url, timeout=20):
    host = urllib.parse.urlsplit(url).hostname or ''
    if host not in ALLOWED_HOSTS:
        raise Refused('source host is not pinned: ' + host)
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={'User-Agent': 'xio-catalog/1'})
    try:
        with opener.open(request, timeout=timeout) as response:
            data = response.read(MAX_BYTES + 1)
    except Refused:
        raise
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise ConnectionError(str(error))
    if len(data) > MAX_BYTES:
        raise Refused('source is larger than 5 MiB')
    return data


def normalize(raw):
    """Strict input filter. Returns (entries, rejected count) with A-label ASCII names."""
    text = raw.decode('utf-8', errors='replace')
    lines = [line.strip() for line in text.splitlines()]
    entries, seen, rejected = [], set(), 0
    for line in lines:
        if not line or line.startswith('#'):
            continue
        if len(line) > MAX_NAME or any(ch in line for ch in '*/:@ \\'):
            rejected += 1
            continue
        name = line.rstrip('.').lower()
        try:
            labels = name.split('.')
            if not labels or len(labels) < 2 or any(not LABEL.match(label) for label in labels):
                raise ValueError
            ascii_name = '.'.join(label.encode('idna').decode('ascii') for label in labels)
        except (UnicodeError, ValueError):
            rejected += 1
            continue
        if len(ascii_name) > MAX_NAME or not RECORD.match(ascii_name):
            rejected += 1
            continue
        if ascii_name in seen:
            continue
        seen.add(ascii_name)
        entries.append(ascii_name)
    if len(entries) > MAX_ENTRIES:
        raise Refused('source has more than %d usable entries' % MAX_ENTRIES)
    return entries, rejected


def _looks_private(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast


def probe(fqdn, timeout=3.0):
    """One eligibility probe from this host. Never raises for a normal rejection."""
    result = {'fqdn': fqdn, 'eligible': False, 'rejectReason': None, 'resolved': [],
              'tls13': False, 'certSha256': None, 'certNotAfter': None, 'tlsRttMs': None}
    try:
        infos = socket.getaddrinfo(fqdn, 443, proto=socket.IPPROTO_TCP)
        resolved = sorted({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        result['rejectReason'] = 'unresolved'
        return result
    resolved = [address for address in resolved if not _looks_private(address)]
    if not resolved:
        result['rejectReason'] = 'unresolved'
        return result
    result['resolved'] = resolved
    context = ssl.create_default_context()
    started = time.monotonic()
    try:
        with socket.create_connection((resolved[0], 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=fqdn) as tls:
                result['tlsRttMs'] = int((time.monotonic() - started) * 1000)
                result['tls13'] = tls.version() == 'TLSv1.3'
                der = tls.getpeercert(binary_form=True)
                info = tls.getpeercert()
    except socket.timeout:
        result['rejectReason'] = 'unreachable'
        return result
    except (ConnectionError, OSError):
        result['rejectReason'] = 'unreachable'
        return result
    except ssl.SSLCertVerificationError as error:
        message = str(error).lower()
        result['rejectReason'] = 'certMismatch' if ('mismatch' in message or 'not valid for' in message) else 'certInvalid'
        return result
    except ssl.SSLError:
        result['rejectReason'] = 'certInvalid'
        return result
    if not der or not info:
        result['rejectReason'] = 'certInvalid'
        return result
    result['certSha256'] = sha256_bytes(der)
    result['certNotAfter'] = info.get('notAfter')
    if not result['tls13']:
        result['rejectReason'] = 'tls12Only'
        return result
    result['eligible'] = True
    return result


def build_catalog(entries, rejected_input, probe_fn, concurrency=6, budget=900):
    started = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(8, concurrency))) as pool:
        futures = [pool.submit(probe_fn, name) for name in entries]
        for future in futures:
            if time.monotonic() - started > budget:
                raise TimeoutError('probe budget exceeded')
            results.append(future.result())
    counts = {'raw': len(entries) + rejected_input, 'unique': len(entries), 'eligible': 0, 'rejected': {
        'invalidEntry': rejected_input, 'unresolved': 0, 'unreachable': 0,
        'certInvalid': 0, 'certMismatch': 0, 'tls12Only': 0}}
    for item in results:
        if item['eligible']:
            counts['eligible'] += 1
        elif item['rejectReason'] in counts['rejected']:
            counts['rejected'][item['rejectReason']] += 1
    return sorted(results, key=lambda item: item['fqdn']), counts


def write_catalog(out_dir, catalog, previous_sha=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(catalog, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    target = out_dir / ('whitelist-%s.json' % catalog['generatedAt'][:10].replace('-', ''))
    temporary = out_dir / ('.whitelist.tmp-%d' % os.getpid())
    with open(temporary, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    manifest = {'schema': 1, 'file': target.name, 'sha256': sha256_bytes(payload.encode('utf-8')),
                'contentSha256': catalog['contentSha256'], 'previousSha256': previous_sha}
    manifest_target = out_dir / 'whitelist-manifest.json'
    manifest_tmp = out_dir / ('.manifest.tmp-%d' % os.getpid())
    if target.exists():
        (out_dir / 'whitelist-previous.json').write_text(target.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    os.replace(temporary, target)
    with open(manifest_tmp, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(manifest_tmp, manifest_target)
    return target, manifest


def run(args):
    pin = load_pin(args.pin)
    try:
        raw = fetch_source(pin['source'], timeout=args.timeout * 5)
    except ConnectionError as error:
        print('source unreachable: %s' % error, file=sys.stderr)
        return 2
    digest = sha256_bytes(raw)
    if digest != pin['sha256']:
        print('source digest %s does not match the pin %s' % (digest, pin['sha256']), file=sys.stderr)
        return 3
    try:
        entries, rejected_input = normalize(raw)
    except Refused as error:
        print(str(error), file=sys.stderr)
        return 3
    if not entries:
        print('source has no usable entries', file=sys.stderr)
        return 4
    probe_fn = getattr(args, 'probe', None) or probe
    try:
        rows, counts = build_catalog(entries, rejected_input, probe_fn, args.concurrency, args.budget)
    except TimeoutError as error:
        print(str(error), file=sys.stderr)
        return 4
    if counts['eligible'] < args.min_eligible or counts['eligible'] * 100 < counts['raw']:
        print('not enough eligible entries: %d of %d' % (counts['eligible'], counts['raw']), file=sys.stderr)
        return 4
    commit = args.commit or ''
    catalog = {
        'schema': 1, 'generatedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'contentSha256': canonical(rows),
        'source': {'url': pin['source'], 'commit': commit, 'sha256': digest,
                   'license': pin.get('license', 'MIT'), 'fetchedAt': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                   'bytes': len(raw), 'lines': len([line for line in raw.decode('utf-8', 'replace').splitlines() if line.strip()])},
        'probe': {'performedOn': socket.gethostname(), 'interface': args.interface,
                  'country': args.country, 'bypassTunnel': bool(args.interface), 'tlsRequires': '1.3'},
        'counts': counts, 'entries': rows}
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    lock_path = Path(args.lock)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, 'w') as lock:
        if fcntl is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        previous = None
        manifest_path = out_dir / 'whitelist-manifest.json'
        if manifest_path.exists():
            try:
                previous = json.loads(manifest_path.read_text())['sha256']
            except (OSError, ValueError, KeyError):
                previous = None
        try:
            target, manifest = write_catalog(out_dir, catalog, previous)
        except OSError as error:
            print('write failed: %s' % error, file=sys.stderr)
            return 5
        finally:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_UN)
    print(json.dumps({'catalog': str(target), 'sha256': manifest['sha256'],
                      'contentSha256': catalog['contentSha256'], 'eligible': counts['eligible'],
                      'unique': counts['unique'], 'rejected': counts['rejected']}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='Build the XIO white-SNI catalog')
    parser.add_argument('--pin', default='server/catalog/whitelist-pins.json')
    parser.add_argument('--out-dir', default='server/catalog')
    parser.add_argument('--lock', default='/run/lock/xio-catalog.lock')
    parser.add_argument('--commit', default='')
    parser.add_argument('--interface', default='')
    parser.add_argument('--country', default='')
    parser.add_argument('--timeout', type=float, default=3.0)
    parser.add_argument('--budget', type=int, default=900)
    parser.add_argument('--concurrency', type=int, default=6)
    parser.add_argument('--min-eligible', type=int, default=10)
    args = parser.parse_args(argv)
    return run(args)


if __name__ == '__main__':
    sys.exit(main())
