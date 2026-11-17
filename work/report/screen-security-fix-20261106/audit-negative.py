import pathlib,tarfile,hashlib
r=pathlib.Path('/srv/archives/agent-screen-security-fix-20261106')
with tarfile.open(r/'baseline-app.tar') as t:
 count=0
 for m in t.getmembers():
  if not m.isfile(): continue
  expected=t.extractfile(m).read()
  if m.name=='app/lib/core.dart':
   old=b'if (!Platform.isAndroid && !Platform.isIOS) return;'
   assert expected.count(old)==1
   expected=expected.replace(old,b'if (defaultTargetPlatform != TargetPlatform.android && !Platform.isIOS) return;')
  assert (r/'baseline-instrumented'/m.name).read_bytes()==expected,m.name
  count+=1
 print('PASS: instrumented baseline',count,'files exactly equal original archive except ONE explicitly TEST-ONLY platform gate substitution')
 print('Negative fixture SHA256',hashlib.sha256((r/'baseline-instrumented/app/test/screen_security_test.dart').read_bytes()).hexdigest())
