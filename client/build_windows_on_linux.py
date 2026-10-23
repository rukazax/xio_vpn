#!/usr/bin/env python3
"""Cross-build only. Wine runs the trusted AOT compiler, never proves Windows networking."""
from pathlib import Path
import argparse,subprocess,shutil,os,zipfile,json
p=argparse.ArgumentParser();p.add_argument('--engine-cache',type=Path,required=True);p.add_argument('--runtime-template',type=Path,required=True);p.add_argument('--wine-prefix',type=Path,required=True);p.add_argument('--go',default='go');a=p.parse_args();r=Path(__file__).resolve().parents[1];stage=r/'.build-support/client-windows';app=stage/'app';build=stage/'cross';build.mkdir(exist_ok=True)
def run(cmd,**kw):subprocess.run(list(map(str,cmd)),check=True,**kw)
run(['python3',r/'client/prepare_platform.py','windows']);run(['flutter','pub','get','--offline'],cwd=app)
assets=build/'assets';run(['flutter','build','bundle','--release','--no-pub','--target-platform=windows-x64','--target=lib/client_main.dart','--dart-define=XIO_CLIENT_ONLY=true','--asset-dir='+str(assets)],cwd=app)
dill=max((app/'.dart_tool/flutter_build').glob('*/app.dill'),key=lambda p:p.stat().st_mtime)
bundle=build/'XIOClient';bundle.mkdir(exist_ok=True);data=bundle/'data';data.mkdir(exist_ok=True)
shutil.rmtree(data/'flutter_assets',ignore_errors=True);shutil.copytree(assets,data/'flutter_assets');shutil.copy2(a.runtime_template/'data/icudtl.dat',data/'icudtl.dat')
for f in a.runtime_template.glob('*.dll'):shutil.copy2(f,bundle/f.name)
for f in a.runtime_template.glob('*LICENSE*'):shutil.copy2(f,bundle/f.name)
shutil.copy2(r/'client/brand/client-windows.ico',build/'xio.ico');shutil.copy2(r/'tooling/cross-platform/windows.manifest',build/'windows.manifest')
source=(r/'tooling/cross-platform/windows_runner.cpp').read_text().replace('L"XIO"','L"XIO Client"').replace('XIOClient019','XIOClient0224');(build/'runner.cpp').write_text(source)
resource=(r/'tooling/cross-platform/windows.rc').read_text().replace('0,19,0,5001','0,22,4,5013').replace('0.19.0','0.22.4').replace('"XIO\\0"','"XIO Client\\0"');(build/'windows.rc').write_text(resource)
run(['x86_64-w64-mingw32-windres','windows.rc','windows-res.o'],cwd=build)
run(['x86_64-w64-mingw32-g++','-std=c++17','-O2','-municode','-mwindows','-static-libgcc','-static-libstdc++','-I'+str(a.engine_cache/'release'),'runner.cpp','windows-res.o',a.engine_cache/'libflutter_windows.a','-lole32','-lshell32','-o',bundle/'XIOClient.exe'],cwd=build)
# Private compiler prefix prevents interference with another Wine session.
env=dict(os.environ,WINEPREFIX=str(a.wine_prefix.resolve()),WINEDEBUG='-all',WINEDLLOVERRIDES='mscoree,mshtml=')
win=lambda p:'Z:'+str(p.resolve()).replace('/','\\')
run(['xvfb-run','-a','wine',a.engine_cache/'debug/gen_snapshot.exe','--deterministic','--snapshot_kind=app-aot-elf','--elf='+win(data/'app.so'),'--strip',win(dill)],env=env,timeout=180)
(bundle/'libexec').mkdir(exist_ok=True);run([a.go,'build','-trimpath','-ldflags=-s -w','-o',bundle/'libexec/xio-tunnel.exe','./cmd/xio-desktop'],cwd=r/'protocol/rivet',env=dict(os.environ,GOOS='windows',GOARCH='amd64',CGO_ENABLED='0'))
for name in ['wintun.dll','WINTUN-LICENSE.txt']:shutil.copy2(a.runtime_template/'libexec'/name,bundle/'libexec'/name)
for name in ['LICENSE','COPYRIGHT','THIRD-PARTY-0.22.md']:shutil.copy2(r/name,bundle/name)
for lang in ['ru','en']:shutil.copy2(r/f'client/README.{lang}.md',bundle/f'README.{lang}.md')
out=r/'releases/client-0.22.4';out.mkdir(exist_ok=True)
with zipfile.ZipFile(out/'XIO-Client-0.22.4-windows-x64.zip','w',zipfile.ZIP_DEFLATED) as z:
 for f in bundle.rglob('*'):
  if f.is_file():z.write(f,'XIOClient/'+f.relative_to(bundle).as_posix())
print('Windows client cross-build packaged. Native Windows/driver acceptance NOT_EXECUTED.')
