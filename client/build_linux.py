#!/usr/bin/env python3
"""Build a side-by-side Ubuntu client candidate, without installing/starting VPN."""
from pathlib import Path
import argparse,subprocess,shutil,tarfile,json,os
r=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('--go',default='go');p.add_argument('--prepared',action='store_true');a=p.parse_args()
app=r/'.build-support/client-linux/app'
if not a.prepared:subprocess.run(['python3',r/'client/prepare_platform.py','linux'],check=True)
if not a.prepared:
 subprocess.run(['flutter','pub','get','--offline'],cwd=app,check=True)
 subprocess.run(['flutter','build','linux','--release','--no-pub','--target=lib/client_main.dart','--dart-define=XIO_CLIENT_ONLY=true'],cwd=app,check=True)
bundle=app/'build/linux/x64/release/bundle';assert (bundle/'XIOClient').exists();(bundle/'libexec').mkdir(exist_ok=True)
subprocess.run([a.go,'build','-trimpath','-ldflags=-s -w','-o',str(bundle/'libexec/xio-tunnel'),'./cmd/xio-desktop'],cwd=r/'protocol/rivet',env=dict(os.environ,CGO_ENABLED='0'),check=True)
shutil.copy2(r/'client/brand/client-linux.png',bundle/'client-icon.png')
for name in ['LICENSE','COPYRIGHT','THIRD-PARTY-0.22.md']:shutil.copy2(r/name,bundle/name)
for lang in ['ru','en']:shutil.copy2(r/f'client/README.{lang}.md',bundle/f'README.{lang}.md')
out=r/'releases/client-0.22.4';out.mkdir(exist_ok=True)
with tarfile.open(out/'XIO-Client-0.22.4-ubuntu-x64.tar.gz','w:gz') as t:t.add(bundle,arcname='XIOClient')
stage=r/'.build-support/client-linux/deb';shutil.rmtree(stage,ignore_errors=True);target=stage/'opt/xio-client';target.parent.mkdir(parents=True);shutil.copytree(bundle,target)
for rel in ['usr/share/applications','usr/share/icons/hicolor/256x256/apps','DEBIAN']:(stage/rel).mkdir(parents=True,exist_ok=True)
(stage/'usr/share/applications/app.xio.client.desktop').write_text('[Desktop Entry]\nType=Application\nName=XIO Client\nExec=/opt/xio-client/XIOClient\nIcon=app.xio.client\nTerminal=false\nCategories=Network;Security;\nStartupWMClass=app.xio.client\n')
shutil.copy2(r/'client/brand/client-linux.png',stage/'usr/share/icons/hicolor/256x256/apps/app.xio.client.png')
(stage/'DEBIAN/control').write_text('Package: xio-client\nVersion: 0.22.4\nSection: net\nPriority: optional\nArchitecture: amd64\nMaintainer: Konstantin Eryomin <er-ka@mail.ru>\nDepends: libc6 (>= 2.34), libgtk-3-0 | libgtk-3-0t64, libstdc++6, libegl1, libgl1, iproute2, pkexec | policykit-1, systemd-resolved | systemd\nDescription: Optional XIO Client candidate for existing servers\n No NAS or server administration. Four native desktop transports; no Cloak yet.\n')
for f in stage.rglob('*'):
 if f.is_file():f.chmod(0o755 if f.name in ['XIOClient','xio-tunnel'] else 0o644)
subprocess.run(['dpkg-deb','--root-owner-group','--build',stage,out/'XIO-Client-0.22.4-ubuntu-amd64.deb'],check=True)
print('Ubuntu client packaged; not installed and VPN not started')
