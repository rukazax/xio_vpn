#!/usr/bin/env python3
"""Restore the reviewed server asset without rebuilding unrelated Android/Linux engines.

Only one ZIP member is read, never extractall(). Both the release ZIP and extracted
resource are SHA-256 checked. Existing unexpected assets are preserved, not replaced.
"""
from pathlib import Path
import hashlib
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
URL = 'https://github.com/rukazax/xio_vpn/releases/download/v0.23.0/XIO-Full-0.23.0-windows-x64.zip'
ZIP_SHA256 = '252e8b82432d0a3eabfc3653d04020e2cdb442c8183911184d8cf96314171611'
ZIP_BYTES = 63126111
MEMBER_SUFFIX = 'data/flutter_assets/assets/xio-server.tar.gz'


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_member(name):
    """Windows-built archives store backslash separators; compare with forward slashes."""
    return name.replace('\\', '/')


def restore(root=ROOT):
    metadata = json.loads((root / 'app/assets/xio-server-release.json').read_text())
    expected = metadata['sha256']
    target = root / 'app/assets/xio-server.tar.gz'
    if target.is_symlink():
        raise RuntimeError('Refusing a symlink asset')
    if target.exists():
        if sha256(target) != expected:
            raise RuntimeError('Existing server asset differs; preserved without replacement')
        print('Existing server asset SHA-256 PASS')
        return
    cache = root / '.build-support/ios-ci-inputs'
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / 'XIO-Full-0.23.0-windows-x64.zip'
    if not archive.exists() or archive.stat().st_size != ZIP_BYTES or sha256(archive) != ZIP_SHA256:
        partial = archive.with_suffix('.zip.part')
        request = urllib.request.Request(URL, headers={'User-Agent': 'XIO-iOS-compile-check'})
        total = 0
        with urllib.request.urlopen(request, timeout=120) as response, partial.open('wb') as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > ZIP_BYTES:
                    raise RuntimeError('Release ZIP exceeded its pinned size')
                output.write(chunk)
        if total != ZIP_BYTES or sha256(partial) != ZIP_SHA256:
            raise RuntimeError('Release ZIP SHA-256/size mismatch; not used')
        partial.replace(archive)
    with zipfile.ZipFile(archive) as package:
        members = [item for item in package.infolist()
                   if normalize_member(item.filename) == MEMBER_SUFFIX
                   or normalize_member(item.filename).endswith('/' + MEMBER_SUFFIX)]
        if len(members) != 1 or members[0].file_size > 128 * 1024 * 1024:
            raise RuntimeError('Missing/ambiguous/oversized server resource')
        content = package.read(members[0])
    if hashlib.sha256(content).hexdigest() != expected:
        raise RuntimeError('Extracted asset SHA-256 differs from the checked-in recipe')
    with target.open('xb') as output:
        output.write(content)
    print('Restored reviewed server asset; ZIP and asset SHA-256 PASS')


if __name__ == '__main__':
    restore()
