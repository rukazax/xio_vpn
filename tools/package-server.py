#!/usr/bin/env python3
from pathlib import Path
import tarfile,gzip,hashlib,json,argparse
from native_fingerprint import fingerprint
root=Path(__file__).resolve().parent.parent
parser=argparse.ArgumentParser();parser.add_argument('--native-source-root',type=Path);args=parser.parse_args()
native_root=args.native_source_root or root
binary=root/'vendor-server/amneziawg-go-linux-amd64'
expected='fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==expected
metadata=json.loads((root/'vendor-metadata/rivet-build.json').read_text())
assert hashlib.sha256((root/'vendor-server/xio-rivet-linux-amd64').read_bytes()).hexdigest()==metadata['serverSha256'],'Rebuild RIVET server'
assert fingerprint(native_root)==metadata['sourceSha256'],'Native sources changed; run tools/build-rivet.py'
for name,key in [('xio-xray-linux-amd64','xrayServerSha256'),('xio-cloak-linux-amd64','cloakServerSha256')]:
 assert hashlib.sha256((root/'vendor-server'/name).read_bytes()).hexdigest()==metadata[key],'Native server mismatch'
assert hashlib.sha256((root/'app/android/app/libs/rivet.aar').read_bytes()).hexdigest()==metadata['androidAarSha256'],'RIVET AAR mismatch'

# Fixed gzip and tar timestamps make the reviewed bundle reproducible.
with (root/'app/assets/x1o-server.tar.gz').open('wb') as raw, gzip.GzipFile(filename='',fileobj=raw,mode='wb',mtime=0) as compressed, tarfile.open(fileobj=compressed,mode='w') as archive:
 for source,name in [(root/'server/managed/dualstack.py','dualstack.py'),(root/'server/managed/client_api.py','client_api.py'),(root/'server/managed/admin.py','admin.py'),(root/'server/managed/stack.py','stack.py'),(root/'server/managed/network_stack.py','network_stack.py'),(root/'server/managed/mesh_stack.py','mesh_stack.py'),(root/'server/managed/mesh-pins.json','mesh-pins.json'),*[(p,'xio_vici/'+p.name) for p in sorted((root/'server/managed/xio_vici').iterdir()) if p.is_file() and (p.suffix=='.py' or p.name=='LICENSE')],(root/'vendor-server/xio-xray-linux-amd64','xraygateway'),(root/'vendor-server/xio-cloak-linux-amd64','cloak'),(binary,'amneziawg-go'),(root/'vendor-server/xio-rivet-linux-amd64','rivet'),(root/'server/managed/rivet-setup.py','rivet-setup.py')]:
  entry=archive.gettarinfo(str(source),arcname=name);entry.uid=entry.gid=0;entry.uname=entry.gname='';entry.mtime=0
  with source.open('rb') as data:archive.addfile(entry,data)
vici=root/'app/assets/xio_vici';vici.mkdir(exist_ok=True)
for p in (root/'server/managed/xio_vici').iterdir():
 if p.is_file() and (p.suffix=='.py' or p.name=='LICENSE'):(vici/p.name).write_bytes(p.read_bytes())
for source,target in [('admin.py','xio-admin.py'),('stack.py','xio-stack.py'),('network_stack.py','xio-network-stack.py'),('mesh_stack.py','xio-mesh-stack.py'),('mesh-pins.json','mesh-pins.json')]:
 (root/'app/assets'/target).write_bytes((root/'server/managed'/source).read_bytes())
(root/'app/assets/xio-bootstrap.sh').write_bytes((root/'server/managed/bootstrap.sh').read_bytes())
(root/'app/assets/xio-server-update.py').write_bytes((root/'server/managed/update.py').read_bytes())
(root/'app/assets/xio-server-release.json').write_text(json.dumps({'schema':1,'recipeVersion':24,'sha256':hashlib.sha256((root/'app/assets/x1o-server.tar.gz').read_bytes()).hexdigest()})+'\n')
print('Packaged owned installer with pinned AWG and RIVET server binaries')
