"""Verify every final tested application file against index (or supplied commit)."""
import hashlib
from pathlib import Path
import subprocess
import sys
root=Path(__file__).resolve().parents[3]
evidence=Path(__file__).resolve().parent
revision=sys.argv[1] if len(sys.argv)>1 else ''
lines=(evidence/'tested-recovery-app.sha256').read_text().splitlines()
assert len(lines)==528
for line in lines:
 expected,path=line.split('  ',1)
 data=subprocess.check_output(['git','-C',str(root),'show',revision+':'+path])
 assert hashlib.sha256(data).hexdigest()==expected,path
print('PASS: all 528 final tested application files equal '+(revision or 'index'))
