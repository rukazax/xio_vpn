#!/usr/bin/env python3
"""Deterministic complete cascade payload; stdlib only, no downloads or execution."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

FILES = (
    '99-xio-cascade.conf', 'Dockerfile', 'README.md', 'cascade-bridge-setup.sh',
    'cascade-config.py', 'cascade-exit-setup.sh', 'cascade-healthcheck.sh',
    'cascade-install.sh', 'entrypoint.sh', 'terminal-install.sh', 'whitelist-update.sh',
    'whitelists.conf', 'xio-awg-uapi.conf', 'xio-cascade-awg-firewall.sh',
    'xio-cascade-exit.service', 'xio-cascade-exit.sh', 'xio-cascade-tunnel.sh',
    'xio-cascade.service',
)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def build(root):
    sources = {name: (root / 'deploy' / 'cascade' / name).read_bytes() for name in sorted(FILES)}
    for name, content in sources.items():
        if b'\r' in content:
            raise ValueError(f'{name}: canonical LF sources required')
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in sources.items()}
    manifest = dict(schema=1, files=hashes)
    sources['manifest.json'] = encode(manifest)
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', filename='', mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for name in sorted(sources):
                entry = tarfile.TarInfo(name)
                entry.size = len(sources[name])
                entry.mode = 0o600
                entry.uid = entry.gid = entry.mtime = 0
                entry.uname = entry.gname = ''
                tar.addfile(entry, io.BytesIO(sources[name]))
    payload = buffer.getvalue()
    release = dict(schema=1, archive='xio-cascade.tar.gz', sha256=hashlib.sha256(payload).hexdigest(),
                   size=len(payload), files=hashes,
                   source_tree_sha256=hashlib.sha256(encode(hashes)).hexdigest(),
                   trust='Pin archive URL + sha256 in frontend; bootstrap must itself be trusted/pinned',
                   scope='Standalone kernel WireGuard cascade; native XIO RIVET/AWG NOT integrated')
    return payload, encode(release)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument('--output-dir', type=Path)
    p.add_argument('--check', action='store_true')
    a = p.parse_args()
    payload, release = build(a.root)
    out = a.output_dir or a.root / 'app' / 'assets'
    targets = [(out / 'xio-cascade.tar.gz', payload), (out / 'xio-cascade-release.json', release)]
    if a.check:
        for path, content in targets:
            if not path.exists() or path.read_bytes() != content:
                raise SystemExit(f'stale/missing payload: {path}')
    else:
        out.mkdir(parents=True, exist_ok=True)
        for path, content in targets:
            path.write_bytes(content)
    print(release.decode(), end='')


if __name__ == '__main__':
    main()
