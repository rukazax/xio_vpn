#!/usr/bin/env python3
"""Restore the pinned MPL-2.0 Xray module and apply the reviewed local patch."""
from pathlib import Path
import argparse,hashlib,json,shutil,subprocess
r=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--go',default='go');args=p.parse_args()
module='github.com/amnezia-vpn/amnezia-xray-core@v1.260728.0'
target=r/'vendor/xray';expected=json.loads((r/'patches/xray/SHA256.json').read_text())
if not (target/'go.mod').exists():
 record=json.loads(subprocess.check_output([args.go,'mod','download','-json',module],cwd=r.parent,text=True))
 if record.get('Error'):raise SystemExit('Pinned Xray module download failed')
 shutil.copytree(record['Dir'],target,dirs_exist_ok=True)
 for item in [target,*target.rglob('*')]:item.chmod(0o755 if item.is_dir() else 0o644)
 subprocess.run(['patch','-p1','--batch','-i',str(r/'patches/xray/xhttp-synchronization.patch')],cwd=target,check=True)
 for name in ['shadowsocks','wireguard']:
  (target/'infra/conf'/f'{name}.go').rename(target/'infra/conf'/f'{name}.go.disabled')
 shutil.copy2(r/'patches/xray/README.md',target/'XIO-CHANGES.md')
for name,digest in expected.items():
 assert hashlib.sha256((target/name).read_bytes()).hexdigest()==digest,'Unexpected Xray source; do not overwrite local changes'
print('Pinned Xray compatibility patch verified')
