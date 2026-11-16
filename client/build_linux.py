#!/usr/bin/env python3
"""Build side-by-side Ubuntu Client; provenance checked, never installed/launched."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tooling/cross-platform'))
from linux_provenance import capture, verify_source, verify_bundle, verify_package


def build(args, root=ROOT):
    app = root / '.build-support/client-linux/app'
    if not args.prepared:
        subprocess.run([sys.executable, root / 'client/prepare_platform.py', 'linux'], check=True)
    expected = capture(app, 'client')  # Prepared source, before Flutter; explicit staging pin is unchanged.
    version = expected['appVersion'].split('+', 1)[0]
    if not args.prepared:
        subprocess.run(['flutter', 'pub', 'get', '--offline'], cwd=app, check=True)
        subprocess.run(['flutter', 'build', 'linux', '--release', '--no-pub',
                        '--target=lib/client_main.dart', '--dart-define=XIO_CLIENT_ONLY=true'], cwd=app, check=True)
    bundle = app / 'build/linux/x64/release/bundle'
    if not (bundle / 'XIOClient').is_file():
        raise RuntimeError('Missing Linux Client build output')
    verify_source(app, expected)
    verify_bundle(bundle, expected)
    (bundle / 'libexec').mkdir(exist_ok=True)
    subprocess.run([args.go, 'build', '-trimpath', '-ldflags=-s -w', '-o',
                    str(bundle / 'libexec/xio-tunnel'), './cmd/xio-desktop'],
                   cwd=root / 'protocol/rivet', env=dict(os.environ, CGO_ENABLED='0'), check=True)
    shutil.copy2(root / 'client/brand/client-linux.png', bundle / 'client-icon.png')
    for name in ['LICENSE', 'COPYRIGHT', 'THIRD-PARTY-0.22.md']:
        shutil.copy2(root / name, bundle / name)
    for lang in ['ru', 'en']:
        shutil.copy2(root / f'client/README.{lang}.md', bundle / f'README.{lang}.md')
    out = root / f'releases/client-{version}'
    out.mkdir(parents=True, exist_ok=True)
    portable = out / f'XIO-Client-{version}-ubuntu-x64.tar.gz'
    deb = out / f'XIO-Client-{version}-ubuntu-amd64.deb'
    tar_part, deb_part = Path(str(portable) + '.part'), Path(str(deb) + '.part')
    with tarfile.open(tar_part, 'w:gz') as tar:
        tar.add(bundle, arcname='XIOClient')
    stage = root / '.build-support/client-linux/deb'
    shutil.rmtree(stage, ignore_errors=True)
    target = stage / 'opt/xio-client'
    target.parent.mkdir(parents=True)
    shutil.copytree(bundle, target)
    for relative in ['usr/share/applications', 'usr/share/icons/hicolor/256x256/apps', 'DEBIAN']:
        (stage / relative).mkdir(parents=True, exist_ok=True)
    (stage / 'usr/share/applications/app.xio.client.desktop').write_text('[Desktop Entry]\nType=Application\nName=XIO Client\nExec=/opt/xio-client/XIOClient\nIcon=app.xio.client\nTerminal=false\nCategories=Network;Security;\nStartupWMClass=app.xio.client\n', encoding='utf-8')
    shutil.copy2(root / 'client/brand/client-linux.png', stage / 'usr/share/icons/hicolor/256x256/apps/app.xio.client.png')
    (stage / 'DEBIAN/control').write_text(f'''Package: xio-client
Version: {version}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Konstantin Eryomin <er-ka@mail.ru>
Depends: libc6 (>= 2.34), libgtk-3-0 | libgtk-3-0t64, libstdc++6, libegl1, libgl1, iproute2, pkexec | policykit-1, systemd-resolved | systemd
Description: Optional XIO Client candidate for existing servers
 No NAS or server administration. Four native desktop transports; no Cloak yet.
''', encoding='utf-8')
    for path in stage.rglob('*'):
        if path.is_file() and not path.is_symlink():
            path.chmod(0o755 if path.name in ['XIOClient', 'xio-tunnel'] else 0o644)
    subprocess.run(['dpkg-deb', '-Zxz', '--root-owner-group', '--build', stage, deb_part], check=True)
    verify_source(app, expected)
    reports = [verify_package(path, expected) for path in (deb_part, tar_part)]
    deb_part.replace(deb)
    tar_part.replace(portable)
    print(json.dumps({'packaged': [str(deb), str(portable)], 'provenance': reports,
                      'installed': False, 'vpnStarted': False}))
    return deb, portable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--prepared', action='store_true')
    build(parser.parse_args(argv))


if __name__ == '__main__':
    main()
