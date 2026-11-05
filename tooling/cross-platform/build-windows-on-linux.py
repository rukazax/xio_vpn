#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Package Windows AOT on Linux using a matching prebuilt Windows runner and Wine.
Use a native Windows build for driver, UAC and installer validation.

Версия в PE-ресурсе `XIO.exe` здесь **производная от app/pubspec.yaml**: готовый
раннер (`--runner`) приходит из прошлой сборки и без перепроштамповки несёт
версию того выпуска (в 0.24.2 так и вышло — exe 0.24.1+5018 внутри пакета
0.24.2+5019). Шаг `pe-version.py --stamp` заменяет FILEVERSION/PRODUCTVERSION
в ресурсе VERSIONINFO и тут же читает его обратно; расхождение — ошибка сборки.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,subprocess,sys,time,zipfile
p=argparse.ArgumentParser();p.add_argument('--runner',type=Path,required=True);p.add_argument('--gen-snapshot',type=Path,required=True);p.add_argument('--wine-prefix',type=Path,required=True);p.add_argument('--release-zip',action='store_true',help='дополнительно собрать плоский XIO-Full-<ver>-windows-x64.zip для выпуска');a=p.parse_args()
r=Path(__file__).resolve().parents[2];work=r/'.build-support/windows-cross';work.mkdir(parents=True,exist_ok=True)
match=re.search(r'^version: ([0-9]+\.[0-9]+\.[0-9]+)(?:\+([0-9]+))?',(r/'app/pubspec.yaml').read_text(),re.M)
version=match.group(1);pe_version=version+'+'+(match.group(2) or '0');pe_quad=version+'.'+(match.group(2) or '0')
version_tool=r/'tooling/cross-platform/pe-version.py'
env=dict(os.environ,WINEPREFIX=str(a.wine_prefix.resolve()),WINEDEBUG='-all')
win=lambda path:'Z:'+str(path.resolve()).replace('/','\\')
def run(cmd,**kwargs):return subprocess.run(cmd,check=True,capture_output=True,**kwargs)
def read_pe_version(exe):return json.loads(run([sys.executable,str(version_tool),str(exe),'--json'],text=True).stdout)
def stamp_exe(exe):
 assert version_tool.exists(),f'нет {version_tool}: перепроштамповка PE-версии невозможна'
 assert exe.exists(),f'в раннере нет {exe.name}: нечего штамповать'
 run([sys.executable,str(version_tool),str(exe),'--stamp','--version',pe_version],text=True)
 seen=read_pe_version(exe)
 assert seen['FileVersion']==pe_version and seen['fileVersion']==pe_quad,seen
 return seen
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
 return target,stamp_exe(target/'XIO.exe')
probe,probe_pe=stage('probe',r/'tooling/cross-platform/check-windows-target.dart')
proof=r/'verification/update-022-windows-extraction.json';proof.unlink(missing_ok=True)
probe_env=dict(env,XIO_KERNEL_CHECK_OUTPUT=win(proof))
run(['xvfb-run','-a','wine',str(probe/'XIO.exe')],env=probe_env,timeout=150)
result=json.loads(proof.read_text());assert result['passed'] and result['isWindows'],result
bundle,bundle_pe=stage('production',r/'app/lib/main.dart')
for name in ['LICENSE','COPYRIGHT','CHANGELOG.md','THIRD-PARTY-0.21.md','THIRD-PARTY-0.22.md']:shutil.copy2(r/name,bundle/name)
out=r/f'releases/XIO-{version}-windows-x64.zip';part=out.with_suffix('.zip.part')
with zipfile.ZipFile(part,'w',zipfile.ZIP_DEFLATED) as z:
 for f in sorted(bundle.rglob('*')):
  if f.is_file():z.write(f,'XIO/'+f.relative_to(bundle).as_posix())
part.replace(out)
if a.release_zip:
 # Плоский ZIP выпуска — та же раскладка, что у Invoke-WindowsStep в tools/release/build-all.ps1:
 # без CHANGELOG/THIRD-PARTY/.last_build_id, но с native_assets.json в корне.
 flat=r/f'releases/XIO-Full-{version}-windows-x64.zip';flat_part=flat.with_suffix('.zip.part')
 drop={'CHANGELOG.md','THIRD-PARTY-0.21.md','THIRD-PARTY-0.22.md','data/flutter_assets/.last_build_id'}
 with zipfile.ZipFile(flat_part,'w',zipfile.ZIP_DEFLATED) as z:
  for f in sorted(bundle.rglob('*')):
   if f.is_file() and f.relative_to(bundle).as_posix() not in drop:z.write(f,f.relative_to(bundle).as_posix())
  z.write(bundle/'data/flutter_assets/NativeAssetsManifest.json','native_assets.json')
 flat_part.replace(flat)
probe_env['XIO_KERNEL_CHECK_ARCHIVE']=win(out)
run(['xvfb-run','-a','wine',str(probe/'XIO.exe')],env=probe_env,timeout=150)
result=json.loads(proof.read_text());assert result['passed'] and result['archiveExtractionPassed'],result
result['archiveSha256']=hashlib.file_digest(out.open('rb'),'sha256').hexdigest()
result['peVersion']=bundle_pe['FileVersion'];result['peFileVersion']=bundle_pe['fileVersion']
proof.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'file':out.name,'kernelTarget':'windows-x64','peVersion':bundle_pe['FileVersion'],'probe':result}))
