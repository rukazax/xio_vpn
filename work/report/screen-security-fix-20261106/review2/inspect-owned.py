import pathlib, hashlib, json, sys
final = '--final' in sys.argv
r=pathlib.Path('/srv/archives/agent-screen-security-fix-20261106')
print('OWN_PROCESSES')
for p in pathlib.Path('/proc').iterdir():
 if p.name.isdigit():
  try:
   if str((p/'cwd').resolve()).startswith(str(r)):
    print(p.name,(p/'cmdline').read_bytes().replace(bytes([0]),b' ').decode(errors='replace'))
  except (OSError, RuntimeError): pass
logs=r/('logs-review2-final' if final else 'logs-review2')
print('EXITS',json.dumps({p.name:p.read_text().strip() for p in logs.glob('*.exit')},sort_keys=True))
for name in ['targeted.txt','full-suite.txt','client-mode.txt','analyze.txt']:
 p=logs/name
 if p.exists(): print(name,'\n'.join(p.read_text(errors='replace').splitlines()[-8:]))
lines=(r/('tested-review2-final-app.sha256' if final else 'tested-review2-app.sha256')).read_text().splitlines()
bad=[]
for line in lines:
 h,p=line.split('  ',1)
 if hashlib.sha256((r/p).read_bytes()).hexdigest()!=h: bad.append(p)
print('LIVE_HASHES',len(lines),'MISMATCHES',bad)
