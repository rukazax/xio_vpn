#!/usr/bin/env python3
from pathlib import Path
import subprocess,zipfile,hashlib,json,struct,re
r=Path(__file__).resolve().parent.parent;sdk=Path.home()/'Android/Sdk/build-tools/36.0.0';records=[]
for abi in ['arm64-v8a','armeabi-v7a','x86_64']:
 p=r/f'app/build/app/outputs/flutter-apk/app-{abi}-release.apk'
 def call(args):return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True).stdout
 badging=call([sdk/'aapt','dump','badging',p]);assert "versionCode='5000'" in badging and "targetSdkVersion:'36'" in badging and "sdkVersion:'26'" in badging
 signature=call([sdk/'apksigner','verify','--verbose','--print-certs',p]);assert 'Verified using v2 scheme (APK Signature Scheme v2): true' in signature
 call([sdk/'zipalign','-c','-P','16','4',p]);call(['python3',r/'tools/check-android-launcher.py',p]);call(['python3',r/'tools/check-native-payload.py',p])
 aligns=[]
 with zipfile.ZipFile(p) as z:
  assert 'assets/flutter_assets/assets/x1o-server.tar' not in z.namelist()
  for n in z.namelist():
   if not n.endswith('.so'):continue
   raw=z.read(n);wide=raw[4]==2;off=struct.unpack_from('<Q' if wide else '<I',raw,32 if wide else 28)[0];size,count=struct.unpack_from('<HH',raw,54 if wide else 42);fmt='<IIQQQQQQ' if wide else '<IIIIIIII'
   values=[struct.unpack_from(fmt,raw,off+i*size)[-1] for i in range(count) if struct.unpack_from('<I',raw,off+i*size)[0]==1]
   assert min(values)>=(16384 if wide else 4096),n;aligns.append({'library':n,'minLoadAlignment':min(values)})
 old=r/f'releases/XIO-0.17.0-android-{abi}.apk';oldsize=old.stat().st_size
 record={'abi':abi,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'oldBytes':oldsize,'reductionPercent':round(100*(oldsize-p.stat().st_size)/oldsize,2),'versionCode':5000,'minSdk':26,'targetSdk':36,'signatureVerified':True,'zipalign16KiB':True,'nativeLibraries':aligns};records.append(record)
(r/'verification/android-release-018.json').write_text(json.dumps(records,indent=2)+'\n');print(json.dumps(records,indent=2))
