#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Package Windows AOT on Linux using a matching prebuilt Windows runner and Wine.
Use a native Windows build for driver, UAC and installer validation.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,time,zipfile
p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,required=True);p.add_argument('--gen-snapshot',type=Path,required=True);p.add_argument('--wine-prefix',type=Path,required=True);a=p.parse_args()
r=Path(__file__).resolve().parents[2];work=r/'.build-support/windows-cross';work.mkdir(parents=True,exist_ok=True)
version=re.search(r'^version: ([0-9.]+)',(r/'app/pubspec.yaml').read_text(),re.M).group(1)
env=dict(os.environ,WINEPREFIX=str(a.wine_prefix.resolve()),WINEDEBUG='-all')
win=lambda path:'Z:'+str(path.resolve()).replace('/','\\')
def run(cmd,**kwargs):return subprocess.run(cmd,check=True,capture_output=True,**kwargs)
def kernel(entry,name):
 start=time.time();assets=work/name/'assets'
 run(['flutter','build','bundle','--release','--target-platform=windows-x64','--target='+str(entry),'--asset-dir='+str(assets)],cwd=r/'app')
 latest=max((r/'app/.dart_tool/flutter_build').glob('*/app.dill'),key=lambda path:path.stat().st_mtime)
 assert latest.stat().st_mtime>=start,'Kernel generation did not produce a fresh snapshot'
 return latest,assets
def stage(name,entry):
 dill,assets=kernel(entry,name)
 target=work/name/'XIO';shutil.rmtree(target,ignore_errors=True);shutil.copytree(a.runner.resolve(),target)
 shutil.rmtree(target/'data/flutter_assets');shutil.copytree(assets,target/'data/flutter_assets');(target/'data/app.so').unlink(missing_ok=True)
 run(['xvfb-run','-a','wine',str(a.gen_snapshot.resolve()),'--deterministic','--snapshot_kind=app-aot-elf','--elf='+win(target/'data/app.so'),'--strip',win(dill)],env=env,timeout=180)
 return target
probe=stage('probe',r/'tooling/cross-platform/check-windows-target.dart')
proof=r/'verification/update-022-windows-extraction.json';proof.unlink(missing_ok=True)
probe_env=dict(env,XIO_KERNEL_CHECK_OUTPUT=win(proof))
run(['xvfb-run','-a','wine',str(probe/'XIO.exe')],env=probe_env,timeout=150)
result=json.loads(proof.read_text());assert result['passed'] and result['isWindows'],result
bundle=stage('production',r/'app/lib/main.dart')
for name in ['LICENSE','COPYRIGHT','CHANGELOG.md','THIRD-PARTY-0.21.md','THIRD-PARTY-0.22.md']:shutil.copy2(r/name,bundle/name)
out=r/f'releases/XIO-{version}-windows-x64.zip';part=out.with_suffix('.zip.part')
with zipfile.ZipFile(part,'w',zipfile.ZIP_DEFLATED) as z:
 for f in sorted(bundle.rglob('*')):
  if f.is_file():z.write(f,'XIO/'+f.relative_to(bundle).as_posix())
part.replace(out)
probe_env['XIO_KERNEL_CHECK_ARCHIVE']=win(out)
run(['xvfb-run','-a','wine',str(probe/'XIO.exe')],env=probe_env,timeout=150)
result=json.loads(proof.read_text());assert result['passed'] and result['archiveExtractionPassed'],result
result['archiveSha256']=hashlib.file_digest(out.open('rb'),'sha256').hexdigest()
proof.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'file':out.name,'kernelTarget':'windows-x64','probe':result}))
