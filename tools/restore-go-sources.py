#!/usr/bin/env python3
"""Verify supplied source archives and seed Go's standard download cache.
Does not change go.mod, source files or global Go settings.
"""
from pathlib import Path
import hashlib,json,subprocess,shutil,argparse
p=argparse.ArgumentParser();p.add_argument('--go',default='go');a=p.parse_args()
r=Path(__file__).resolve().parent.parent;src=r/'vendor/go-source-cache'
cache=Path(subprocess.check_output([a.go,'env','GOMODCACHE'],text=True).strip())/'cache/download'
rows=json.loads((src/'MANIFEST.json').read_text())
for row in rows:
 f=src/row['path'];assert hashlib.sha256(f.read_bytes()).hexdigest()==row['sha256'],row['module']
 out=cache/Path(row['path']).parent;out.mkdir(parents=True,exist_ok=True)
 for ext in ['.zip','.info','.mod','.ziphash']:
  source=f.with_name(f.name[:-4]+ext)
  if source.exists():shutil.copyfile(source,out/source.name)
print(f'Verified and restored {len(rows)} module source archives')
