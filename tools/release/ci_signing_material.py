#!/usr/bin/env python3
"""Materialize named owner-supplied CI secrets, never generate a key or print values."""
from pathlib import Path
import argparse
import base64
import os
import sys

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('XIO_ANDROID_KEYSTORE_BASE64', 'XIO_ANDROID_STORE_PASSWORD',
         'XIO_ANDROID_KEY_ALIAS', 'XIO_ANDROID_KEY_PASSWORD')
MARKER = 'XIO CI ephemeral signing material v1\n'
FILES = {'.xio-ci-owned', 'release.keystore', 'signing.properties'}


def materialize(root=ROOT, environment=os.environ):
    missing = [name for name in NAMES if not environment.get(name)]
    if missing:
        raise RuntimeError('Signing NOT_READY; missing named secrets: ' + ', '.join(missing))
    content = base64.b64decode(environment[NAMES[0]], validate=True)
    if not content:
        raise RuntimeError('Signing NOT_READY; empty keystore')
    target = root.resolve() / '.signing'
    if target.exists() or target.is_symlink():
        raise RuntimeError('Refuse existing signing directory; no credentials replaced')
    target.mkdir(mode=0o700)
    (target / '.xio-ci-owned').write_text(MARKER)
    key = target / 'release.keystore'
    key.write_bytes(content)
    key.chmod(0o600)

    def escaped(value):
        # Properties.load(InputStream) is ISO-8859-1, not UTF-8. Emit ASCII Unicode
        # escapes (including UTF-16 surrogate pairs) for non-ASCII aliases/passwords.
        data = value.encode('utf-16-be')
        units = [int.from_bytes(data[index:index+2], 'big') for index in range(0, len(data), 2)]
        escapes = {'\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', ' ': '\\ '}
        return ''.join(('\\u%04x' % unit) if unit > 127 else escapes.get(chr(unit), chr(unit)) for unit in units)

    properties = [('storeFile', key.as_posix()), ('storePassword', environment[NAMES[1]]),
                  ('keyAlias', environment[NAMES[2]]), ('keyPassword', environment[NAMES[3]])]
    config = target / 'signing.properties'
    config.write_text(''.join(name + '=' + escaped(value) + '\n' for name, value in properties), encoding='utf-8')
    config.chmod(0o600)


def cleanup(root=ROOT):
    # Resolve/verify the exact owned target and every file before any deletion.
    target = root.resolve() / '.signing'
    if not target.exists() and not target.is_symlink():
        return
    if target.is_symlink() or not target.is_dir() or target.resolve() != root.resolve() / '.signing':
        raise RuntimeError('Refuse linked/foreign signing path')
    marker = target / '.xio-ci-owned'
    if not marker.is_file() or marker.is_symlink() or marker.read_text() != MARKER:
        raise RuntimeError('Refuse non-owned signing directory')
    entries = list(target.iterdir())
    if not {path.name for path in entries} <= FILES or any(path.is_symlink() or not path.is_file() for path in entries):
        raise RuntimeError('Refuse unexpected signing-directory entries')
    for path in entries:
        if path.name != '.xio-ci-owned':
            path.unlink()
    marker.unlink()
    target.rmdir()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['create', 'cleanup'])
    args = parser.parse_args()
    try:
        materialize() if args.action == 'create' else cleanup()
    except (RuntimeError, ValueError, OSError) as error:
        # Messages contain only missing variable names or ownership checks, never secret content.
        print(str(error), file=sys.stderr)
        sys.exit(1)
