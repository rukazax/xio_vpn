#!/usr/bin/env python3
"""Prove the AAR surface: per-ABI native libs, classes.jar hash, javap API, presence/absence of methods."""
from pathlib import Path
import hashlib, json, subprocess, zipfile, tempfile, shutil

B = Path('/srv/archives/agent-rivet-aar-20261106')
METHODS = ['cancelConnect', 'stopWithTimeout', 'connectPolicyTimeout']
CLASS = 'app.xio.mobile.Mobile'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def inspect(aar, label, outdir):
    outdir = outdir / label
    outdir.mkdir(parents=True, exist_ok=True)
    z = zipfile.ZipFile(aar)
    names = z.namelist()
    jni = sorted(n for n in names if n.startswith('jni/'))
    classes_jar = outdir / f'{label}-classes.jar'
    with z.open('classes.jar') as src, open(classes_jar, 'wb') as dst:
        shutil.copyfileobj(src, dst)
    natives = {}
    for n in jni:
        data = z.read(n)
        natives[n] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
        (outdir / n.replace('/', '_')).write_bytes(data)
    javap = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/javap', '-classpath',
                            str(classes_jar), CLASS], capture_output=True, text=True)
    (outdir / f'{label}-javap.txt').write_text(javap.stdout + javap.stderr)
    api = {m: (f' {m}(' in javap.stdout) for m in METHODS}
    return {
        'aar': str(aar),
        'aarSha256': sha(aar),
        'aarBytes': aar.stat().st_size,
        'aarEntryCount': len(names),
        'classesJarSha256': sha(classes_jar),
        'classesJarBytes': classes_jar.stat().st_size,
        'nativeLibs': natives,
        'abis': sorted({n.split('/')[1] for n in jni}),
        'javapExit': javap.returncode,
        'javapClass': CLASS,
        'methodPresent': api,
        'javapOutputSaved': str(outdir / f'{label}-javap.txt'),
        'aarEntryList': home_path(names),
    }


def home_path(names):
    keep = [n for n in names if not n.endswith('/')]
    return keep


report = {'schema': 1, 'methods': METHODS}
fresh = B / 'fresh-binding/rivet.aar'
assert fresh.is_file(), 'fresh AAR missing'
report['fresh'] = inspect(fresh, 'fresh', B / 'artifacts/surface')
stale = B / 'artifacts/stale-rivet-cfc336c9.aar'
report['stale'] = inspect(stale, 'stale', B / 'artifacts/surface')
(B / 'logs/aar-surface.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != 'aarEntryList'}
                  for k, v in report.items() if isinstance(v, dict)}, indent=2))
