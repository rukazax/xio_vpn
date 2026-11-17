"""Verify this new freeze against index or a supplied commit (no tests run)."""
from pathlib import Path
import hashlib, subprocess, sys
root=Path(__file__).resolve().parents[4]
evidence=Path(__file__).resolve().parent
revision=sys.argv[1] if len(sys.argv)>1 else ''
lines=(evidence/'tested-app.sha256').read_text().splitlines()
assert len(lines)==529
for line in lines:
 expected,path=line.split('  ',1)
 data=subprocess.check_output(['git','-C',str(root),'show',revision+':'+path])
 assert hashlib.sha256(data).hexdigest()==expected,path
print('PASS: all 529 final tested files equal '+(revision or 'index'))
