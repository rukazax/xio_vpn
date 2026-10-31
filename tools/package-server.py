#!/usr/bin/env python3
"""Package only digest-verified pinned native inputs; --check never writes assets."""
from pathlib import Path
import argparse
import ast
import gzip
import hashlib
import json
import os
import tarfile
import tempfile
from native_fingerprint import fingerprint

ROOT = Path(__file__).resolve().parent.parent
RECIPE = 25
AWG_SHA256 = 'fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a'
BINARY_MEMBERS = {'amneziawg-go', 'rivet', 'xraygateway', 'cloak'}
MIRRORS = [('admin.py', 'xio-admin.py'), ('stack.py', 'xio-stack.py'),
           ('network_stack.py', 'xio-network-stack.py'), ('mesh_stack.py', 'xio-mesh-stack.py'),
           ('mesh-pins.json', 'mesh-pins.json'), ('bootstrap.sh', 'xio-bootstrap.sh'),
           ('update.py', 'xio-server-update.py')]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(root):
    managed = root / 'server/managed'
    files = [(managed / name, name) for name in
             ('dualstack.py', 'client_api.py', 'admin.py', 'stack.py', 'network_stack.py',
              'mesh_stack.py', 'mesh-pins.json', 'rivet-setup.py')]
    files += [(p, 'xio_vici/' + p.name) for p in sorted((managed / 'xio_vici').iterdir())
              if p.is_file() and (p.suffix == '.py' or p.name == 'LICENSE')]
    files += [(root / 'vendor-server' / name, member) for name, member in
              [('xio-xray-linux-amd64', 'xraygateway'), ('xio-cloak-linux-amd64', 'cloak'),
               ('amneziawg-go-linux-amd64', 'amneziawg-go'), ('xio-rivet-linux-amd64', 'rivet')]]
    return files


def check_inputs(root, native_root):
    required = [root / 'vendor-server' / name for name in
                ('amneziawg-go-linux-amd64', 'xio-rivet-linux-amd64',
                 'xio-xray-linux-amd64', 'xio-cloak-linux-amd64')]
    required += [root / 'vendor-metadata/rivet-build.json', root / 'app/android/app/libs/rivet.aar']
    missing = [str(p.relative_to(root)) for p in required if not p.is_file()]
    if missing:
        raise RuntimeError('Packaging blocked: missing pinned inputs: ' + ', '.join(missing)
                           + '. Rebuild/restore verified owned inputs; do not substitute downloaded binaries.')
    for name in ('admin.py', 'update.py'):
        tree = ast.parse((root / 'server/managed' / name).read_bytes())
        values = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'RECIPE' for t in n.targets)]
        if values != [RECIPE]:
            raise RuntimeError('Recipe mismatch: ' + name)
    metadata = json.loads((root / 'vendor-metadata/rivet-build.json').read_bytes())
    checks = [('vendor-server/amneziawg-go-linux-amd64', AWG_SHA256),
              ('vendor-server/xio-rivet-linux-amd64', metadata['serverSha256']),
              ('vendor-server/xio-xray-linux-amd64', metadata['xrayServerSha256']),
              ('vendor-server/xio-cloak-linux-amd64', metadata['cloakServerSha256']),
              ('app/android/app/libs/rivet.aar', metadata['androidAarSha256'])]
    for relative, expected in checks:
        if sha256(root / relative) != expected:
            raise RuntimeError('Pinned native input digest mismatch: ' + relative)
    if fingerprint(native_root) != metadata['sourceSha256']:
        raise RuntimeError('Native sources changed; run tools/build-rivet.py before packaging')
    files = sources(root)
    for source, _ in files:
        if source.suffix == '.py':
            compile(source.read_bytes(), source.name, 'exec')
    return files


def archive(files, destination):
    # Explicit modes as well as timestamps make Linux/Windows packaging identical.
    hashes = {name: sha256(source) for source, name in files}
    with destination.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as tar:
        for source, name in files:
            entry = tar.gettarinfo(str(source), arcname=name)
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = ''
            entry.mtime = 0
            entry.mode = 0o755 if name in BINARY_MEMBERS else 0o600
            with source.open('rb') as data:
                tar.addfile(entry, data)
    with tarfile.open(destination, 'r:gz') as tar:
        if tar.getnames() != [name for _, name in files]:
            raise RuntimeError('Packaged member list mismatch')
        for member in tar:
            if hashlib.sha256(tar.extractfile(member).read()).hexdigest() != hashes[member.name]:
                raise RuntimeError('Packaged member digest mismatch: ' + member.name)
    if any(sha256(source) != hashes[name] for source, name in files):
        raise RuntimeError('Packaging source changed while building archive')
    return sha256(destination)


def package(root, native_root, output, check=False):
    files = check_inputs(root, native_root)  # All native guards precede ALL asset writes.
    if check:
        return {'checked': True, 'recipeVersion': RECIPE, 'members': len(files)}
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.xio-package-', dir=output.parent) as temporary:
        staged = Path(temporary)
        digest = archive(files, staged / 'xio-server.tar.gz')
        for source, target in MIRRORS:
            payload = (root / 'server/managed' / source).read_bytes()
            if source.endswith('.sh'):
                payload = payload.replace(b'\r\n', b'\n')
            (staged / target).write_bytes(payload)
        (staged / 'xio_vici').mkdir()
        for source, name in files:
            if name.startswith('xio_vici/'):
                (staged / name).write_bytes(source.read_bytes())
        artifacts = {}
        for source, target in MIRRORS:
            artifacts[target] = sha256(staged / target)
        manifest = {'schema': 1, 'recipeVersion': RECIPE, 'sha256': digest,
                    'bootstrapSha256': artifacts['xio-bootstrap.sh'],
                    'updateSha256': artifacts['xio-server-update.py'],
                    'artifacts': artifacts}
        (staged / 'xio-server-release.json').write_text(json.dumps(manifest) + '\n', encoding='utf-8')
        output.mkdir(exist_ok=True)
        paths = sorted(p for p in staged.rglob('*') if p.is_file() and p.name != 'xio-server-release.json')
        paths.append(staged / 'xio-server-release.json')  # Publish commit manifest last.
        for source in paths:
            target = output / source.relative_to(staged)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native-source-root', type=Path)
    parser.add_argument('--output-dir', type=Path, help='isolated staging output (default app/assets)')
    parser.add_argument('--check', action='store_true', help='validate pinned inputs and recipes without writing')
    args = parser.parse_args()
    try:
        result = package(ROOT, args.native_source_root or ROOT, args.output_dir or ROOT / 'app/assets', args.check)
    except (OSError, KeyError, ValueError, RuntimeError) as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
