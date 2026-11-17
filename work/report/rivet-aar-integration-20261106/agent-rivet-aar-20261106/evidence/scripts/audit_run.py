#!/usr/bin/env python3
"""Per-run audit of a successful compile: BuildConfig identity, compiled class manifest."""
from pathlib import Path
import hashlib, json, sys, shutil

B = Path('/srv/archives/agent-rivet-aar-20261106')
S = B / 'src'
name, mode = sys.argv[1], sys.argv[2]
app = S / 'app'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


bc = app / 'build/app/generated/source/buildConfig/debug/app/xio/xio/BuildConfig.java'
text = bc.read_text()
expected = {'full': ('false', 'app.xio.xio'), 'client': ('true', 'app.xio.client')}[mode]
assert f'CLIENT_ONLY = {expected[0]}' in text, text
assert f'APPLICATION_ID = "{expected[1]}"' in text, text
shutil.copy2(bc, B / f'logs/{name}-BuildConfig.java')

classes = {str(p.relative_to(app)): sha(p)
           for root in [app / 'build/app/tmp/kotlin-classes/debug',
                        app / 'build/app/intermediates/javac/debug']
           for p in root.rglob('*.class')}
assert classes
(B / f'logs/{name}-compiled-classes.json').write_text(json.dumps(classes, indent=2))
main = app / 'build/app/tmp/kotlin-classes/debug/app/xio/xio/MainActivity.class'
assert main.is_file()
shutil.copy2(main, B / f'logs/{name}-MainActivity.class')
print(json.dumps({'run': name, 'mode': mode, 'applicationId': expected[1],
                  'clientOnly': expected[0], 'compiledClasses': len(classes),
                  'buildConfigSha256': sha(bc), 'mainActivitySha256': sha(main)}, indent=2))
