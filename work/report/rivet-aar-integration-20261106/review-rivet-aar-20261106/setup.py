from pathlib import Path
import hashlib,json,shutil,tarfile,zipfile,struct,subprocess,os
b=Path('/srv/archives/agent-review-rivet-aar-20261106'); old=Path('/srv/archives/agent-android-compile-preflight-20261106'); author=Path('/srv/archives/agent-rivet-aar-20261106')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
expected='7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c'
a=b/'rivet-fresh-595def6a-allabi.aar'; assert sha(a)==expected and a.stat().st_size==36548360
assert sha(b/'source-595.tar')=='27148ceb51225e5f60894952e469a116ede930e41a310ee342c8192edd95b904'
for d in ['home','tmp','xdg/cache','xdg/config','xdg/data','pub-cache','logs','payload']: (b/d).mkdir(parents=True,exist_ok=True)
s=b/'src'; s.mkdir()
with tarfile.open(b/'source-595.tar') as t:t.extractall(s,filter='data')
pre={str(p.relative_to(s)):sha(p) for p in sorted(s.rglob('*')) if p.is_file()}
(b/'source-pre.json').write_text(json.dumps(pre,indent=2))
native={k:v for k,v in pre.items() if k.startswith(('protocol/','vendor/','tools/','tooling/'))}
oldpre=json.loads((old/'source-pre.json').read_text()); assert native=={k:v for k,v in oldpre.items() if k.startswith(('protocol/','vendor/','tools/','tooling/'))}
assert all(sha(author/'src'/k)==v for k,v in native.items())
assert sha(author/'source-main-595def6a.tar')==sha(b/'source-595.tar')
assert sha(author/'artifacts/rivet-fresh-595def6a-allabi.aar')==expected
z=zipfile.ZipFile(a); names=z.namelist(); assert len(names)==len(set(names)); assert z.testzip() is None
libs={'arm64-v8a':(2,183,'990c84db1bb4142dcf68e1f112317d00b794719713f26680293eb1997b217ecd'),'armeabi-v7a':(1,40,'18ac04444292b0e4a37b7d0a1b05105a5de13905cd5f2652df2e706e5c592ff1'),'x86_64':(2,62,'ddb62423c7d4049ba860315f0b69f108b601897a4b6a82297687b58e08955cd6')}
assert set(n for n in names if n.startswith('jni/'))=={f'jni/{abi}/libgojni.so' for abi in libs}
entries={}
for abi,(cls,machine,digest) in libs.items():
 name=f'jni/{abi}/libgojni.so'; data=z.read(name)
 assert data[:4]==b'\x7fELF' and data[4]==cls and data[5]==1
 et,em=struct.unpack_from('<HH',data,16); assert et==3 and em==machine
 assert hashlib.sha256(data).hexdigest()==digest
 p=b/'payload'/f'{abi}-libgojni.so'; p.write_bytes(data)
 r=subprocess.run(['readelf','-h','-l','-n',str(p)],text=True,capture_output=True); assert r.returncode==0
 (b/'logs'/f'{abi}-readelf.txt').write_text(r.stdout+r.stderr)
 entries[name]={'sha256':digest,'bytes':len(data),'elfClass':cls,'e_type':et,'e_machine':em}
c=z.read('classes.jar'); assert hashlib.sha256(c).hexdigest()=='8f1849333170c09c3e874c740bfc932a89adb177f454d131cf7caa86d5741400'
(b/'payload/classes.jar').write_bytes(c)
manifest=z.read('AndroidManifest.xml').decode(); assert 'android:minSdkVersion="26"' in manifest
r=subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/javap','-classpath',str(b/'payload/classes.jar'),'app.xio.mobile.Mobile'],text=True,capture_output=True,env=dict(os.environ,HOME=str(b/'home'),TMPDIR=str(b/'tmp')));assert r.returncode==0
for m in ['cancelConnect()','stopWithTimeout(long)','connectPolicyTimeout(java.lang.String, app.xio.mobile.Protector, long, java.lang.String)','connectionPolicyMode(java.lang.String)']:assert m in r.stdout
(b/'logs/javap-Mobile.txt').write_text(r.stdout+r.stderr)
shutil.copy2(a,s/'app/android/app/libs/rivet.aar')
# Reuse only verifier-owned dependency cache; fresh SDK tooling and plugin outputs.
(b/'gradle').symlink_to(old/'gradle',target_is_directory=True)
f=b/'flutter'; f.mkdir()
for p in Path('/opt/flutter').iterdir():
 if p.name!='packages':(f/p.name).symlink_to(p,target_is_directory=p.is_dir())
(f/'packages').mkdir()
for p in Path('/opt/flutter/packages').iterdir():
 if p.name!='flutter_tools':(f/'packages'/p.name).symlink_to(p,target_is_directory=p.is_dir())
ft=f/'packages/flutter_tools';ft.mkdir()
for p in Path('/opt/flutter/packages/flutter_tools').iterdir():
 if p.name!='gradle':(ft/p.name).symlink_to(p,target_is_directory=p.is_dir())
shutil.copytree('/opt/flutter/packages/flutter_tools/gradle',ft/'gradle',ignore=shutil.ignore_patterns('build','.gradle','.kotlin'))
shutil.copytree(old/'integration_test',b/'integration_test',ignore=shutil.ignore_patterns('build','.gradle','.dart_tool'))
assert pre['app/pubspec.lock']==oldpre['app/pubspec.lock']
m=json.loads((old/'fresh-src/app/.flutter-plugins-dependencies').read_text())
for group in m['plugins'].values():
 for item in group:
  assert item['name']=='integration_test';item['path']=str(b/'integration_test')+'/'
(s/'app/.flutter-plugins-dependencies').write_text(json.dumps(m))
(s/'app/android/local.properties').write_text(f'sdk.dir=/opt/android-sdk\nflutter.sdk={f}\nflutter.versionName=0.24.2\nflutter.versionCode=5019\n')
proof={'commit':'595def6ab24590002458c0a5fa4f8020d5c8a86f','archiveSha256':sha(b/'source-595.tar'),'authorArchiveEqual':True,'actualAuthorNativeFilesEqualToGitArchive':len(native),'historicalNativeInputsEqual':True,'aarSHA256':sha(a),'aarBytes':a.stat().st_size,'zipCRC':'PASS','uniqueEntries':names,'entries':entries,'classesSHA256':hashlib.sha256(c).hexdigest(),'manifest':manifest,'javapExit':r.returncode,'gomobileRebuiltByVerifier':False}
(b/'logs/independent-input-payload-check.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof,indent=2))
