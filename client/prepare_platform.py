#!/usr/bin/env python3
"""Prepare isolated client source for Linux/Windows/iOS. Preparation is not a native build."""
from pathlib import Path
import argparse,importlib.util,shutil,subprocess,json
r=Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('platform',choices=['linux','windows','ios']);p.add_argument('--stage',type=Path,help='Fresh owned staging root');a=p.parse_args()
spec=importlib.util.spec_from_file_location('client_stage',r/'client/build.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.STAGE=a.stage.resolve() if a.stage else r/'.build-support'/('client-'+a.platform);m.APP=m.STAGE/'app';m.prepare();app=m.APP
shutil.copytree(r/'app'/a.platform,app/a.platform,dirs_exist_ok=True,ignore=shutil.ignore_patterns('ephemeral','build','.symlinks'))
if a.platform=='windows':
 shutil.copy2(r/'client/brand/client-windows.ico',app/'windows/runner/resources/app_icon.ico')
 for rel in ['windows/CMakeLists.txt','windows/runner/main.cpp','windows/runner/Runner.rc']:
  f=app/rel;f.write_text(f.read_text().replace('"XIO"','"XIOClient"'))
elif a.platform=='linux':
 f=app/'linux/CMakeLists.txt';f.write_text(f.read_text().replace('BINARY_NAME "XIO"','BINARY_NAME "XIOClient"').replace('app.xio.xio','app.xio.client'))
 f=app/'linux/runner/my_application.cc';f.write_text(f.read_text().replace('"XIO"','"XIO Client"').replace('  g_object_set(gtk_settings_get_default(), "gtk-application-prefer-dark-theme", TRUE, nullptr);\n',''))
 shutil.copy2(r/'client/brand/client-linux.png',app/'client-icon.png')
else:
 for f in (app/'ios').rglob('*'):
  if f.is_file() and f.suffix in {'.swift','.plist','.entitlements','.pbxproj','.xcconfig'}:
   f.write_text(f.read_text().replace('app.xio.client','app.xio.light').replace('<string>XIO</string>','<string>XIO Client</string>'))
 icons=app/'ios/Runner/Assets.xcassets/AppIcon.appiconset';shutil.rmtree(icons);shutil.copytree(r/'client/brand/AppIcon.appiconset',icons)
for lang in ['ru','en']:
 for name in ['privacy','legal']:
  f=r/f'client/{name}.portable.{lang}.txt';shutil.copy2(f,app/f'assets/help/{name}.{lang}.txt')
(m.STAGE/'platform.json').write_text(json.dumps({'platform':a.platform,'entry':'lib/client_main.dart','defines':['XIO_CLIENT_ONLY=true'],'identity':{'linux':'app.xio.client','windows':'XIOClient','ios':'app.xio.light'}[a.platform],'nativeBuild':'NOT_EXECUTED','allProtocolParity':False},indent=2)+'\n')
print(app)
