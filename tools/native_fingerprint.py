"""Fingerprint all owned Go inputs, including the small upstream compatibility forks."""
from pathlib import Path
import hashlib

def fingerprint(root: Path):
    module=root/'protocol/rivet'
    files=[*module.rglob('*.go'),module/'go.mod',module/'go.sum']
    for name in ['anet','cloak','tailscale','xray','tun2socks']:
        files.extend(p for p in (root/'vendor'/name).rglob('*') if p.is_file() and not any(x in p.parts for x in ['.git','__pycache__']))
    source=hashlib.sha256()
    for path in sorted(files):
        source.update(path.relative_to(root).as_posix().encode()+b'\0'+path.read_bytes())
    return source.hexdigest()
