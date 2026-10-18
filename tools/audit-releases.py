#!/usr/bin/env python3
from pathlib import Path
import base64,hashlib,json,re,tarfile,zipfile,os
r=Path(__file__).resolve().parent.parent
secrets=[v.encode() for k,v in os.environ.items() if k.startswith("X1O_AUDIT_SECRET_") and len(v)>6]
p=r/'.signing/signing.properties'
if p.exists():
 for line in p.read_text().splitlines():
  if 'password' in line.lower() and '=' in line:
   v=line.split('=',1)[1].strip().encode()
   if len(v)>8: secrets.append(v)
private_roots=[r/'.build-support/vps-private',r/'.build-support/server-vm',*(r/'.build-support').glob('lab*')]
for credential_file in [r/'.build-support/vps-private/rv-password', r/'.signing/key-password']:
 if credential_file.exists():
  value=credential_file.read_bytes().strip()
  if len(value)>6: secrets.append(value)
for p in [p for folder in private_roots for p in folder.rglob('*.conf')]:
 for line in p.read_text().splitlines():
  if line.lower().startswith('privatekey'): secrets.append(line.split('=',1)[1].strip().encode())
for p in [folder/'defines.json' for folder in private_roots if (folder/'defines.json').exists()]:
 data=json.loads(p.read_text())
 for k,v in data.items():
  if isinstance(v,str) and 'config' in k.lower() and len(v)>24:
   secrets.append(v.encode())
   try:
    decoded=base64.b64decode(v,validate=True)
    if b'PrivateKey' in decoded:
     secrets.append(decoded)
     for line in decoded.splitlines():
      if line.lower().startswith(b'privatekey'): secrets.append(line.split(b'=',1)[1].strip())
   except ValueError: pass
# Also guard lab multi-protocol files; these must never enter releases.
for folder in private_roots:
 for p in [*folder.rglob('*.x1o'), *folder.rglob('*.xio')]:
  raw=p.read_bytes();secrets.append(raw)
  if raw.startswith((b'x1o://', b'xio://')):
   payload=raw[6:];payload+=b'='*((-len(payload))%4)
   bundle=json.loads(base64.urlsafe_b64decode(payload))
   access=bundle.get('adminAccess',{})
   if isinstance(access.get('key'),str): secrets.append(access['key'].encode())
   for config in bundle.get('configs',{}).values():
    for line in config.splitlines():
     if line.lower().startswith('privatekey'): secrets.append(line.split('=',1)[1].strip().encode())
# Portable server exports contain deliberately transferable credentials.
for folder in private_roots:
 for p in folder.rglob('*.xio'):
  raw=p.read_bytes()
  if raw.startswith(b'xio-server://'):
   data=json.loads(base64.urlsafe_b64decode(raw[13:]+b'='*((-len(raw[13:]))%4)))
   for v in data.get('credentials',{}).values():
    if isinstance(v,str) and len(v)>6: secrets.append(v.encode())
# Fixture SSH keys are private even though they are not production credentials.
for p in (r/'.build-support').glob('lab*/ssh.json'):
 for k,v in json.loads(p.read_text()).items():
  if isinstance(v,str) and 'private' in k.lower() and len(v)>24: secrets.append(v.encode())
for folder in private_roots:
 for p in folder.glob('id_ed25519'):
  secrets.append(p.read_bytes())
# RIVET uses opaque per-device credentials in JSON, never WireGuard PrivateKey lines.
for folder in private_roots:
 for p in folder.rglob('*.json'):
  try:
   value=json.loads(p.read_text())
   if isinstance(value,dict):
    for key in ['secret','entryToken']:
     item=value.get(key)
     if isinstance(item,str) and len(item)>20:secrets.append(item.encode())
  except (ValueError,UnicodeError):pass
 for p in folder.rglob('*.xio'):
  raw=p.read_bytes()
  if raw.startswith((b'xio://',b'x1o://')):
   try:
    data=json.loads(base64.urlsafe_b64decode(raw[6:]+b'='*((-len(raw[6:]))%4)))
    for proto,config in data.get('configs',{}).items():
     if proto.startswith('rivet-'):
      value=json.loads(config)
      for key in ['secret','entryToken']:secrets.append(value[key].encode())
   except (ValueError,KeyError):raise AssertionError('Invalid private RIVET fixture')
# New engine fixtures may contain credentials inside nested, serialized JSON.
# Inspect them without printing values or treating public user IDs as secrets.
def engine_credentials(value, path=()):
 if isinstance(value,dict):
  for k,v in value.items():
   if isinstance(v,str) and (k.lower() in {'password','authkey','privatekey','secret','entrytoken','admintoken'} or (k=='id' and 'vnext' in path and 'users' in path)):
    if len(v)>12:secrets.append(v.encode())
    if k.lower()=='password':
     secrets.extend(part.encode() for part in v.split(':') if len(part)>16)
   engine_credentials(v,(*path,k))
 elif isinstance(value,list):
  for v in value:engine_credentials(v,path)
 elif isinstance(value,str):
  if value.lstrip().startswith(('{','[')):
   try:engine_credentials(json.loads(value),path)
   except ValueError:pass
  for block in re.findall(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----([\s\S]*?)-----END (?:[A-Z]+ )?PRIVATE KEY-----',value):
   secrets.extend(line.strip().encode() for line in block.splitlines() if len(line.strip())>=32)
for folder in private_roots:
 for p in folder.rglob('*.json'):
  try:engine_credentials(json.loads(p.read_text()))
  except (ValueError,UnicodeError):pass
 for p in folder.rglob('*.xio'):
  raw=p.read_bytes()
  if raw.startswith((b'xio://',b'x1o://')):
   engine_credentials(json.loads(base64.urlsafe_b64decode(raw[6:]+b'='*((-len(raw[6:]))%4))))
report=[]
for p in sorted((r/'releases').glob('*')):
 if os.environ.get('XIO_AUDIT_VERSION') and os.environ['XIO_AUDIT_VERSION'] not in p.name: continue
 if p.suffix in ('.apk','.zip'):
  with zipfile.ZipFile(p) as z:
   assert z.testzip() is None
   for item in z.infolist():
    if p.suffix=='.zip': assert not set(Path(item.filename).parts)&{'.signing','.build-support','.dart_tool','.gradle'}
    d=z.read(item)
    assert not any(s in d for s in secrets), 'Credential detected; archive withheld'
 elif p.name.endswith('.tar.gz'):
  with tarfile.open(p) as z:
   for item in z:
    assert not item.name.startswith('/') and '..' not in Path(item.name).parts
    if item.isfile():
     d=z.extractfile(item).read()
     assert not any(s in d for s in secrets), 'Credential detected; archive withheld'
 else: continue
 report.append({'file':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
for metadata in [r/'verification/BUILD-INFO-0.1.json', r/'verification/BUILD-INFO.json']:
 if metadata.exists():
  info=json.loads(metadata.read_text())
  name='x1o-'+info['version']+'-android.apk'
  apk=next((x for x in report if x['file']==name),None)
  if apk: assert apk['sha256']==info['androidApkSha256']
for metadata in (r/'verification').glob('android-apks-*.json'):
 for expected in json.loads(metadata.read_text()):
  actual=next((x for x in report if x['file']==expected['file']),None)
  if actual: assert actual['sha256']==expected['sha256']
(r/'releases/SHA256SUMS').write_text(''.join(x['sha256']+'  '+x['file']+'\n' for x in report))
(r/('verification/release-archive-audit-'+re.search(r'^version: ([0-9]+\.[0-9]+(?:\.[0-9]+)?)',(r/'app/pubspec.yaml').read_text(),re.M).group(1)+'.json')).write_text(json.dumps({'archives':report,'integrity':True,'privateDirectoriesExcluded':True,'knownCredentialScan':'passed','scope':'Known local signing passwords and fixture credentials; not a general secret detection guarantee'},indent=2)+'\n')
print(json.dumps(report,indent=2));print('Integrity, known credential scan and APK evidence binding passed')
