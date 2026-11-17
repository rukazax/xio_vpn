#!/bin/bash
# TEST-ONLY baseline reachability instrumentation, NOT the pristine baseline.
# Exactly one dart:io platform gate is replaced by the Flutter test platform.
set -u
cd /srv/archives/agent-screen-security-fix-20261106
export HOME="$PWD/home" TMPDIR="$PWD/tmp" XDG_CACHE_HOME="$PWD/cache" XDG_CONFIG_HOME="$PWD/xdg" XDG_DATA_HOME="$PWD/xdg/data" PUB_CACHE="$PWD/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH=/opt/flutter/bin:$PATH
mkdir baseline-instrumented
cd baseline-instrumented
tar -xf ../baseline-app.tar
python3 - <<'PY'
from pathlib import Path
p = Path('app/lib/core.dart')
s = p.read_text()
old = 'if (!Platform.isAndroid && !Platform.isIOS) return;'
assert s.count(old) == 1
s = s.replace(old, 'if (defaultTargetPlatform != TargetPlatform.android && !Platform.isIOS) return;')
p.write_text(s)
PY
cd app
flutter pub get --offline > ../../logs/instrumented-pub.txt 2>&1
echo $? > ../../logs/instrumented-pub.exit
flutter test --no-pub --concurrency=1 --reporter=expanded test/screen_security_test.dart > ../../logs/red-instrumented.txt 2>&1
echo $? > ../../logs/red-instrumented.exit
