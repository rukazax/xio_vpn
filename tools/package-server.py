#!/usr/bin/env python3
from pathlib import Path
import tarfile,hashlib,json
from native_fingerprint import fingerprint
root=Path(__file__).resolve().parent.parent
binary=root/'vendor-server/amneziawg-go-linux-amd64'
expected='fc1a1f9fae43cd8b8a4ac969b49bf80db9ed8d536d935166286cad53fcf34c9a'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==expected
metadata=json.loads((root/'vendor-metadata/rivet-build.json').read_text())
assert hashlib.sha256((root/'vendor-server/xio-rivet-linux-amd64').read_bytes()).hexdigest()==metadata['serverSha256'],'Rebuild RIVET server'
assert fingerprint(root)==metadata['sourceSha256'],'Native sources changed; run tools/build-rivet.py'
for name,key in [('xio-xray-linux-amd64','xrayServerSha256'),('xio-cloak-linux-amd64','cloakServerSha256')]:
 assert hashlib.sha256((root/'vendor-server'/name).read_bytes()).hexdigest()==metadata[key],'Native server mismatch'
assert hashlib.sha256((root/'app/android/app/libs/rivet.aar').read_bytes()).hexdigest()==metadata['androidAarSha256'],'RIVET AAR mismatch'

with tarfile.open(root/'app/assets/x1o-server.tar.gz','w:gz') as archive:
 for source,name in [(root/'server/managed/admin.py','admin.py'),(root/'server/managed/stack.py','stack.py'),(root/'server/managed/network_stack.py','network_stack.py'),(root/'server/managed/mesh_stack.py','mesh_stack.py'),(root/'server/managed/mesh-pins.json','mesh-pins.json'),*[(p,'xio_vici/'+p.name) for p in sorted((root/'server/managed/xio_vici').iterdir()) if p.is_file() and (p.suffix=='.py' or p.name=='LICENSE')],(root/'vendor-server/xio-xray-linux-amd64','xraygateway'),(root/'vendor-server/xio-cloak-linux-amd64','cloak'),(binary,'amneziawg-go'),(root/'vendor-server/xio-rivet-linux-amd64','rivet'),(root/'server/managed/rivet-setup.py','rivet-setup.py')]:
  entry=archive.gettarinfo(str(source),arcname=name);entry.uid=entry.gid=0;entry.uname=entry.gname='';entry.mtime=0
  with source.open('rb') as data:archive.addfile(entry,data)
vici=root/'app/assets/xio_vici';vici.mkdir(exist_ok=True)
for p in (root/'server/managed/xio_vici').iterdir():
 if p.is_file() and (p.suffix=='.py' or p.name=='LICENSE'):(vici/p.name).write_bytes(p.read_bytes())
for source,target in [('admin.py','xio-admin.py'),('stack.py','xio-stack.py'),('network_stack.py','xio-network-stack.py'),('mesh_stack.py','xio-mesh-stack.py'),('mesh-pins.json','mesh-pins.json')]:
 (root/'app/assets'/target).write_bytes((root/'server/managed'/source).read_bytes())
(root/'app/assets/xio-bootstrap.sh').write_bytes((root/'server/managed/bootstrap.sh').read_bytes())
print('Packaged owned installer with pinned AWG and RIVET server binaries')
