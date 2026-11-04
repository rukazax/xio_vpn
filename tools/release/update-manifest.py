#!/usr/bin/env python3
"""Generate or verify the signed XIO update manifest (XIO-update.json).

The application never reads a release feed for the payload itself: it looks for
an asset named ``XIO-update.json`` on a ``vX.Y.Z`` release, downloads it and
verifies an Ed25519 envelope (see ``app/lib/update_service.dart``):

    {"payload": "<base64 of the release JSON>", "signature": "<base64 Ed25519>"}

The signature covers the *exact bytes* of the payload, and the pinned public key
lives in ``app/assets/security/update-ed25519.pub``. Therefore this script does
not invent its own format: it emits precisely the envelope the client accepts,
and refuses to write anything the client would reject.

Nothing here is HMAC or a private signing service: an HMAC manifest cannot be
verified by the shipped application at all (it expects a 32-byte Ed25519 public
key and a 64-byte signature), so a symmetric signature would silently restore
the dead channel for zero clients. See ``docs/update-channel.ru.md``.

Usage (release):
  python tools/release/update-manifest.py \
      --key ~/.keys/update-ed25519.key \
      --asset android-arm64-v8a=releases/XIO-Full-0.24.2-android-arm64-v8a.apk \
      --asset android-armeabi-v7a=releases/XIO-Full-0.24.2-android-armeabi-v7a.apk \
      --asset linux-x64=releases/XIO-0.24.2-ubuntu-amd64.deb \
      --notes-file docs/release-notes-0.24.2.md \
      --out releases/XIO-update.json

Usage (verify a published manifest, no key needed):
  python tools/release/update-manifest.py --check releases/XIO-update.json \
      --asset-dir C:/path/to/downloaded/assets
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]

# Platform keys the client actually asks for (app/lib/update_service.dart
# platformKey()). android-* uses the ABI reported by the Kotlin updateAbi call.
PLATFORMS = (
    'android-arm64-v8a',
    'android-armeabi-v7a',
    'android-x86_64',
    'ios',
    'linux-x64',
    'windows-x64',
)

MAX_PAYLOAD = 64000            # update_service.dart verifyReleaseEnvelope
MAX_NOTES = 12000              # XioRelease
MIN_SIZE = 1
MAX_SIZE = 800 * 1024 * 1024   # UpdateAsset


def die(message: str) -> 'NoReturn':
    print(f'error: {message}', file=sys.stderr)
    raise SystemExit(2)


def read_version(version_file: Path, pubspec: Path, check_pubspec: bool) -> tuple[str, int]:
    """Read version/build from app/lib/version.dart - the single source of truth."""
    try:
        text = version_file.read_text(encoding='utf-8')
    except OSError as exc:
        die(f'cannot read {version_file}: {exc}')
    version = re.search(r"xioVersion\s*=\s*'([0-9]+\.[0-9]+\.[0-9]+)'", text)
    build = re.search(r'xioBuild\s*=\s*(\d+)', text)
    if not version or not build:
        die(f'{version_file}: xioVersion/xioBuild not found')
    found_version, found_build = version.group(1), int(build.group(1))
    if check_pubspec:
        try:
            pubspec_text = pubspec.read_text(encoding='utf-8')
        except OSError as exc:
            die(f'cannot read {pubspec}: {exc}')
        declared = re.search(r'^version:\s*([0-9]+\.[0-9]+\.[0-9]+)\+(\d+)\s*$', pubspec_text, re.M)
        if not declared:
            die(f'{pubspec}: "version: X.Y.Z+N" not found')
        if (declared.group(1), int(declared.group(2))) != (found_version, found_build):
            die(
                f'version drift: app/lib/version.dart has {found_version}+{found_build}, '
                f'{pubspec.name} has {declared.group(1)}+{declared.group(2)}'
            )
    if found_build < 1:
        die(f'{version_file}: build must be >= 1')
    return found_version, found_build


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def asset_url(repo: str, tag: str, name: str) -> str:
    return f'https://github.com/{repo}/releases/download/{tag}/{name}'


def validate_url(url: str, tag: str) -> None:
    """Mirror of validateAssetUrl() so a rejected manifest never leaves the build."""
    from urllib.parse import urlsplit

    parsed = urlsplit(url)
    path = parsed.path
    if (
        parsed.scheme != 'https'
        or parsed.hostname != 'github.com'
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or not path.startswith(f'/rukazax/xio_vpn/releases/download/{tag}/')
        or parsed.query
        or parsed.fragment
        or not path.rsplit('/', 1)[-1]
        or any(part in ('..', '.') for part in path.split('/'))
    ):
        die(f'invalid asset URL for {tag}: {url}')


def collect_assets(pairs: list[str], repo: str, tag: str) -> dict[str, dict[str, object]]:
    assets: dict[str, dict[str, object]] = {}
    for pair in pairs:
        if '=' not in pair:
            die(f'--asset expects PLATFORM=PATH, got {pair!r}')
        platform, raw_path = pair.split('=', 1)
        platform = platform.strip()
        if platform not in PLATFORMS:
            die(f'unknown platform {platform!r}; the client asks for: {", ".join(PLATFORMS)}')
        if platform in assets:
            die(f'duplicate platform {platform}')
        path = Path(raw_path).expanduser()
        if not path.is_file():
            die(f'missing package for {platform}: {path}')
        size = path.stat().st_size
        if not MIN_SIZE <= size <= MAX_SIZE:
            die(f'{path.name}: size {size} outside {MIN_SIZE}..{MAX_SIZE}')
        url = asset_url(repo, tag, path.name)
        validate_url(url, tag)
        assets[platform] = {'url': url, 'size': size, 'sha256': sha256_file(path)}
    if not assets:
        die('at least one --asset PLATFORM=PATH (or --apk) is required')
    return assets


def load_private_key(path: Path, public_key_file: Path) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        die(f'cannot read signing key {path}: {exc}')
    if len(raw) != 32:
        die(f'{path}: expected a raw 32-byte Ed25519 key, got {len(raw)} bytes')
    key = Ed25519PrivateKey.from_private_bytes(raw)
    derived = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    pinned = public_key_file.read_text(encoding='utf-8').strip()
    if derived != pinned:
        die(
            'signing key does not match the pinned application key '
            f'({public_key_file}): derived {derived}, pinned {pinned}'
        )
    return key


def envelope(payload: bytes, key: Ed25519PrivateKey) -> dict[str, str]:
    return {
        'payload': base64.b64encode(payload).decode(),
        'signature': base64.b64encode(key.sign(payload)).decode(),
    }


def verify_envelope(data: bytes, public_key_file: Path) -> tuple[dict, Ed25519PublicKey]:
    public_raw = base64.b64decode(public_key_file.read_text(encoding='utf-8').strip())
    key = Ed25519PublicKey.from_public_bytes(public_raw)
    try:
        document = json.loads(data)
        payload = base64.b64decode(document['payload'], validate=True)
        signature = base64.b64decode(document['signature'], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        die(f'malformed envelope: {exc}')
    if len(payload) > MAX_PAYLOAD:
        die(f'payload is {len(payload)} bytes, the client limit is {MAX_PAYLOAD}')
    if len(signature) != 64:
        die(f'signature is {len(signature)} bytes, Ed25519 requires 64')
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        die('signature does not verify with the pinned key')
    try:
        release = json.loads(payload)
    except ValueError as exc:
        die(f'payload is not JSON: {exc}')
    return release, key


def validate_release(release: dict) -> None:
    """Mirror of XioRelease/UpdateAsset so verification matches the client."""
    version = release.get('version')
    build = release.get('build')
    tag = release.get('tag')
    notes = release.get('notes')
    assets = release.get('assets')
    if release.get('schema') != 1:
        die('schema must be 1')
    if not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version):
        die(f'invalid version: {version!r}')
    if tag != f'v{version}' or not re.fullmatch(r'v\d+\.\d+\.\d+', str(tag)):
        die(f'tag must be v{version}, got {tag!r}')
    if not isinstance(build, int) or build < 1:
        die(f'invalid build: {build!r}')
    if not isinstance(notes, str) or len(notes) > MAX_NOTES:
        die(f'notes must be a string of at most {MAX_NOTES} characters')
    if not isinstance(assets, dict) or not assets:
        die('assets must be a non-empty object')
    for platform, asset in assets.items():
        if platform not in PLATFORMS:
            die(f'asset platform {platform!r} is never requested by the client')
        if not isinstance(asset, dict):
            die(f'asset {platform}: expected an object')
        url, sha, size = asset.get('url'), asset.get('sha256'), asset.get('size')
        if not isinstance(url, str):
            die(f'asset {platform}: url must be a string')
        validate_url(url, tag)
        if not isinstance(sha, str) or not re.fullmatch(r'[a-f0-9]{64}', sha):
            die(f'asset {platform}: sha256 must be 64 lowercase hex characters')
        if not isinstance(size, int) or not MIN_SIZE <= size <= MAX_SIZE:
            die(f'asset {platform}: size {size!r} outside {MIN_SIZE}..{MAX_SIZE}')


def cmd_generate(args: argparse.Namespace) -> int:
    key_path = args.key or os.environ.get('XIO_UPDATE_KEY')
    if not key_path:
        die('--key PATH (or XIO_UPDATE_KEY) is required to sign; use --check to verify an existing manifest')
    public_key_file = Path(args.public_key).expanduser()
    if args.payload:
        return sign_payload(Path(args.payload).expanduser(), Path(key_path).expanduser(), public_key_file, args)

    version_file = Path(args.version_file).expanduser()
    pubspec = Path(args.pubspec).expanduser()
    version, build = read_version(version_file, pubspec, not args.skip_pubspec_check)
    if args.version and args.version != version:
        die(f'--version {args.version} contradicts {version_file} ({version})')
    if args.build and args.build != build:
        die(f'--build {args.build} contradicts {version_file} ({build})')
    tag = f'v{version}'

    pairs = list(args.asset)
    if args.apk:
        pairs.append(f'android-arm64-v8a={args.apk}')
    assets = collect_assets(pairs, args.repo, tag)

    notes = ''
    if args.notes_file:
        notes = Path(args.notes_file).expanduser().read_text(encoding='utf-8').strip()
    if args.notes:
        notes = args.notes.strip()
    if not notes:
        notes = f'XIO {version}'
    if len(notes) > MAX_NOTES:
        die(f'notes are {len(notes)} characters, the client limit is {MAX_NOTES}')

    payload = {
        'schema': 1,
        'tag': tag,
        'version': version,
        'build': build,
        'notes': notes,
        'assets': assets,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(payload_bytes) > MAX_PAYLOAD:
        die(f'payload is {len(payload_bytes)} bytes, the client limit is {MAX_PAYLOAD}')
    validate_release(payload)

    key_path = args.key or os.environ.get('XIO_UPDATE_KEY')
    if not key_path:
        die('--key PATH (or XIO_UPDATE_KEY) is required to sign; use --check to verify an existing manifest')
    key = load_private_key(Path(key_path).expanduser(), public_key_file)

    document = envelope(payload_bytes, key)
    _emit(payload, document, key, public_key_file, args)
    print(f'manifest  {Path(args.out).expanduser()}')
    print(f'version   {version}+{build}  tag {tag}')
    for platform, asset in assets.items():
        print(f'  {platform:<20} {asset["size"]:>10}  {asset["sha256"]}  {Path(asset["url"]).name}')
    print('signature verified with the pinned key', flush=True)
    if build <= args.assume_installed_build:
        print(
            f'warning: build {build} is not newer than the assumed installed build '
            f'{args.assume_installed_build}; clients at that build ignore this manifest',
            file=sys.stderr,
        )
    return 0


def sign_payload(payload_file: Path, key_file: Path, public_key_file: Path, args: argparse.Namespace) -> int:
    """Sign a prepared payload (used for reviewed releases and test fixtures)."""
    try:
        payload = json.loads(payload_file.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        die(f'cannot read payload {payload_file}: {exc}')
    if not isinstance(payload, dict):
        die('payload must be a JSON object')
    validate_release(payload)
    payload_bytes = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if len(payload_bytes) > MAX_PAYLOAD:
        die(f'payload is {len(payload_bytes)} bytes, the client limit is {MAX_PAYLOAD}')
    key = load_private_key(key_file, public_key_file)
    _emit(payload, envelope(payload_bytes, key), key, public_key_file, args)
    print(f'manifest  {Path(args.out).expanduser()}')
    print(f'version   {payload["version"]}+{payload["build"]}  tag {payload["tag"]}  (signed payload)')
    print('signature verified with the pinned key', flush=True)
    return 0


def _emit(
    payload: dict,
    document: dict[str, str],
    key: Ed25519PrivateKey,
    public_key_file: Path,
    args: argparse.Namespace,
) -> None:
    out = Path(args.out).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.payload_out:
        Path(args.payload_out).expanduser().write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
        )
    out.write_text(json.dumps(document, separators=(',', ':')) + '\n', encoding='utf-8')
    # Read back what was written and re-verify it exactly as the client would.
    check, _ = verify_envelope(out.read_bytes(), public_key_file)
    validate_release(check)
    if check != payload:
        die('written manifest does not round-trip')


def cmd_check(args: argparse.Namespace) -> int:
    path = Path(args.check).expanduser()
    public_key_file = Path(args.public_key).expanduser()
    release, _ = verify_envelope(path.read_bytes(), public_key_file)
    validate_release(release)
    print(f'manifest  {path}')
    print(f'version   {release["version"]}+{release["build"]}  tag {release["tag"]}')
    print(f'notes     {len(release["notes"])} characters')
    status = 0
    for platform, asset in release['assets'].items():
        name = Path(asset['url']).name
        line = f'  {platform:<20} {asset["size"]:>10}  {asset["sha256"]}  {name}'
        if args.asset_dir:
            local = Path(args.asset_dir).expanduser() / name
            if not local.is_file():
                line += '  MISSING'
                status = 1
            else:
                size = local.stat().st_size
                digest = sha256_file(local)
                ok = size == asset['size'] and digest == asset['sha256']
                line += '  ok' if ok else f'  MISMATCH (size {size}, sha256 {digest})'
                status = status or (0 if ok else 1)
        print(line)
    print('signature verified with the pinned key')
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description='Generate or verify the signed XIO update manifest (XIO-update.json).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('--version-file', default=str(ROOT / 'app/lib/version.dart'))
    parser.add_argument('--pubspec', default=str(ROOT / 'app/pubspec.yaml'))
    parser.add_argument('--skip-pubspec-check', action='store_true')
    parser.add_argument('--public-key', default=str(ROOT / 'app/assets/security/update-ed25519.pub'))
    parser.add_argument('--repo', default='rukazax/xio_vpn')
    parser.add_argument('--version', help='expected version; fails on drift')
    parser.add_argument('--build', type=int, help='expected build; fails on drift')
    parser.add_argument('--notes', help='release notes text shown in the update dialog')
    parser.add_argument('--notes-file', help='file with release notes (max 12000 characters)')
    parser.add_argument('--apk', help='shorthand for --asset android-arm64-v8a=PATH')
    parser.add_argument(
        '--payload', metavar='FILE',
        help='sign an already prepared payload JSON instead of building one from packages',
    )
    parser.add_argument(
        '--asset', action='append', default=[], metavar='PLATFORM=PATH',
        help=f'repeatable; PLATFORM in {", ".join(PLATFORMS)}',
    )
    parser.add_argument('--key', help='raw 32-byte Ed25519 private key (or XIO_UPDATE_KEY)')
    parser.add_argument('--out', default=str(ROOT / 'releases/XIO-update.json'))
    parser.add_argument('--payload-out', help='also write the unsigned payload for review')
    parser.add_argument('--assume-installed-build', type=int, default=0,
                        help='warn when build is not newer than this (default: 0, no warning)')
    parser.add_argument('--check', metavar='MANIFEST', help='verify an existing manifest, no key needed')
    parser.add_argument('--asset-dir', help='with --check: compare local files against sizes and hashes')
    args = parser.parse_args(argv)
    if args.check:
        return cmd_check(args)
    return cmd_generate(args)


if __name__ == '__main__':
    raise SystemExit(main())
