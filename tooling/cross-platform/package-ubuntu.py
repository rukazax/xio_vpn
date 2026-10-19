#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
import shutil,subprocess,os,tarfile,re
r=Path(__file__).resolve().parents[2];bundle=r/'app/build/linux/x64/release/bundle';out=r/'releases';stage=r/'.build-support/ubuntu022/deb';out.mkdir(exist_ok=True)
version=re.search(r'^version: ([0-9.]+)',(r/'app/pubspec.yaml').read_text(),re.M).group(1)
assert (bundle/'XIO').exists() and (bundle/'libexec/xio-tunnel').exists()
shutil.rmtree(stage,ignore_errors=True);target=stage/'opt/xio';target.parent.mkdir(parents=True);shutil.copytree(bundle,target)
for name in ['LICENSE','COPYRIGHT','THIRD-PARTY-0.22.md','THIRD-PARTY-0.21.md','THIRD-PARTY-0.18.md','THIRD-PARTY-0.19.md','CROSS-PLATFORM-0.19.ru.md']:
 if (r/name).exists():shutil.copy2(r/name,target/name)
desktop=stage/'usr/share/applications';desktop.mkdir(parents=True)
(desktop/'app.xio.client.desktop').write_text('[Desktop Entry]\nType=Application\nName=XIO\nComment=VPN client\nExec=/opt/xio/XIO\nIcon=app.xio.client\nTerminal=false\nCategories=Network;Security;\nStartupWMClass=app.x1o.x1o\n')
icon=stage/'usr/share/icons/hicolor/256x256/apps';icon.mkdir(parents=True)
shutil.copy2(r/'app/assets/icons/green_dark_0.png',icon/'app.xio.client.png')
bindir=stage/'usr/bin';bindir.mkdir(parents=True);os.symlink('/opt/xio/XIO',bindir/'xio')
control=stage/'DEBIAN';control.mkdir()
size=sum(p.stat().st_size for p in target.rglob('*') if p.is_file())//1024
(control/'control').write_text(f'''Package: xio-vpn
Version: {version}
Section: net
Priority: optional
Architecture: amd64
Maintainer: Ерёмин Константин Александрович <er-ka@mail.ru>
Installed-Size: {size}
Depends: libc6 (>= 2.34), libgtk-3-0 | libgtk-3-0t64, libstdc++6, libglu1-mesa, libegl1, libgl1, libgles2, iproute2, pkexec | policykit-1, systemd-resolved | systemd
Description: XIO VPN desktop client
 Flutter client with separate privileged VPN helper and seven tunnel engines.
''')
# No setuid executable, no service started at install, no existing VPN removed.
for path in stage.rglob('*'):
 if path.is_file() and not path.is_symlink():path.chmod(0o755 if path.name in ['XIO','xio-tunnel'] else 0o644)
subprocess.run(['dpkg-deb','--root-owner-group','--build',str(stage),str(out/f'XIO-{version}-ubuntu-amd64.deb')],check=True)
with tarfile.open(out/f'XIO-{version}-ubuntu-x64.tar.gz','w:gz') as tar:tar.add(target,arcname='XIO')
print('Ubuntu DEB and portable archive packaged')
