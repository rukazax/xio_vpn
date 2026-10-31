"""Fingerprint all owned Go inputs, including the small upstream compatibility forks."""
from pathlib import Path
import hashlib

def fingerprint(root: Path):
    module=root/'protocol/rivet'
    files=[*module.rglob('*.go'),module/'go.mod',module/'go.sum']
    for name in ['anet','cloak','tailscale','xray','tun2socks','amneziawg-go']:
        fork = root/'vendor'/name
        # The optional observed-AWG fork must stay project-owned.  Missing it
        # preserves legacy hashes; enabling it fingerprints every shipped byte.
        if name == 'amneziawg-go' and (fork.exists() or fork.is_symlink()):
            if fork.is_symlink() or not fork.resolve().is_relative_to(root.resolve()):
                raise RuntimeError('Linked or external AWG source fork refused')
            for entry in fork.rglob('*'):
                if entry.is_symlink() or not entry.resolve().is_relative_to(fork.resolve()):
                    raise RuntimeError('Linked AWG source input refused')
            mod = fork/'go.mod'
            if not mod.is_file() or not any(line.strip() == 'module github.com/amnezia-vpn/amneziawg-go/v3' for line in mod.read_text(encoding='utf-8').splitlines()):
                raise RuntimeError('Missing or foreign AWG source module refused')
        files.extend(p for p in fork.rglob('*') if p.is_file() and not any(x in p.parts for x in ['.git','__pycache__']))
    source=hashlib.sha256()
    for path in sorted(files):
        source.update(path.relative_to(root).as_posix().encode()+b'\0'+path.read_bytes())
    return source.hexdigest()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    print(fingerprint(args.root.resolve()))
