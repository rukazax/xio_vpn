#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import tarfile
from linux_provenance import capture, verify_source, verify_bundle, verify_package

ROOT = Path(__file__).resolve().parents[2]


def package(root=ROOT, expected_snapshot=None):
    app = root / 'app'
    expected = (json.loads(Path(expected_snapshot).read_text(encoding='utf-8'))
                if expected_snapshot else capture(app, 'full'))
    if expected['flavor'] != 'full':
        raise RuntimeError('Full Ubuntu packaging requires a Full provenance snapshot')
    verify_source(app, expected)
    bundle = app / 'build/linux/x64/release/bundle'
    if not (bundle / 'XIO').is_file() or not (bundle / 'libexec/xio-tunnel').is_file():
        raise RuntimeError('Missing Linux app/tunnel build outputs')
    verify_bundle(bundle, expected)  # Catch stale Flutter assets before writing package outputs.
    version = expected['appVersion'].split('+', 1)[0]
    out = root / 'releases'
    stage = root / '.build-support/ubuntu022/deb'
    out.mkdir(exist_ok=True)
    shutil.rmtree(stage, ignore_errors=True)
    target = stage / 'opt/xio'
    target.parent.mkdir(parents=True)
    shutil.copytree(bundle, target)
    for name in ['LICENSE', 'COPYRIGHT', 'THIRD-PARTY-0.22.md', 'THIRD-PARTY-0.21.md',
                 'THIRD-PARTY-0.18.md', 'THIRD-PARTY-0.19.md', 'CROSS-PLATFORM-0.19.ru.md']:
        if (root / name).exists():
            shutil.copy2(root / name, target / name)
    desktop = stage / 'usr/share/applications'
    desktop.mkdir(parents=True)
    (desktop / 'app.xio.client.desktop').write_text('[Desktop Entry]\nType=Application\nName=XIO\nComment=VPN client\nExec=/opt/xio/XIO\nIcon=app.xio.client\nTerminal=false\nCategories=Network;Security;\nStartupWMClass=app.xio.xio\n', encoding='utf-8')
    icon = stage / 'usr/share/icons/hicolor/256x256/apps'
    icon.mkdir(parents=True)
    shutil.copy2(root / 'app/assets/icons/green_dark_0.png', icon / 'app.xio.client.png')
    bindir = stage / 'usr/bin'
    bindir.mkdir(parents=True)
    os.symlink('/opt/xio/XIO', bindir / 'xio')
    control = stage / 'DEBIAN'
    control.mkdir()
    size = sum(path.stat().st_size for path in target.rglob('*') if path.is_file()) // 1024
    (control / 'control').write_text(f'''Package: xio-vpn
Version: {version}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Ерёмин Константин Александрович <er-ka@mail.ru>
Installed-Size: {size}
Depends: libc6 (>= 2.34), libgtk-3-0 | libgtk-3-0t64, libstdc++6, libglu1-mesa, libegl1, libgl1, libgles2, iproute2, pkexec | policykit-1, systemd-resolved | systemd
Description: XIO VPN desktop client
 Flutter client with separate privileged VPN helper and seven tunnel engines.
''', encoding='utf-8')
    # No setuid executable, no service started at install, no existing VPN removed.
    for path in stage.rglob('*'):
        if path.is_file() and not path.is_symlink():
            path.chmod(0o755 if path.name in ['XIO', 'xio-tunnel'] else 0o644)
    deb = out / f'XIO-{version}-ubuntu-amd64.deb'
    portable = out / f'XIO-{version}-ubuntu-x64.tar.gz'
    deb_part, tar_part = Path(str(deb) + '.part'), Path(str(portable) + '.part')
    subprocess.run(['dpkg-deb', '-Zxz', '--root-owner-group', '--build', str(stage), str(deb_part)], check=True)
    with tarfile.open(tar_part, 'w:gz') as tar:
        tar.add(target, arcname='XIO')
    verify_source(app, expected)
    reports = [verify_package(path, expected) for path in (deb_part, tar_part)]
    deb_part.replace(deb)
    tar_part.replace(portable)
    print(json.dumps({'packaged': [str(deb), str(portable)], 'provenance': reports}))
    return deb, portable


def main(argv=None):
    parser = argparse.ArgumentParser(description='Package Linux Full with fail-closed payload provenance.')
    parser.add_argument('--expected-snapshot', type=Path, help='snapshot captured before Flutter build')
    args = parser.parse_args(argv)
    package(expected_snapshot=args.expected_snapshot)


if __name__ == '__main__':
    main()
