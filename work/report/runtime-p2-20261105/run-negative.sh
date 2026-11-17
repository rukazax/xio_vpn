#!/usr/bin/env bash
set -euo pipefail
root=/srv/archives/agent-runtime-p2-20261105
export TMPDIR="$root/tmp"
export PUB_CACHE=/root/.pub-cache
export FLUTTER_SUPPRESS_ANALYTICS=true
cd "$root/app"
cp lib/core.dart "$root/evidence/core.corrected.dart"
trap 'cp "$root/evidence/core.corrected.dart" lib/core.dart' EXIT
python3 - <<'PY'
from pathlib import Path
p = Path('lib/core.dart')
s = p.read_text()
old = 'if (_disposed || epoch != _statusEpoch) return;'
assert s.count(old) == 2
s = s.replace(old, 'if (_disposed) return;')
old = 'if (!_disposed && epoch == _statusEpoch) {'
assert s.count(old) == 1
s = s.replace(old, 'if (!_disposed) {')
p.write_text(s)
PY
set +e
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/negative-epoch.log"
rc=${PIPESTATUS[0]}
set -e
printf 'epoch-removal regression exit: %s (expected 1)\n' "$rc" | tee "$root/evidence/negative-epoch-result.log"
test "$rc" -eq 1
cp "$root/evidence/core.corrected.dart" lib/core.dart
python3 - <<'PY'
from pathlib import Path
p = Path('lib/core.dart')
s = p.read_text()
old = '    _desired = false;\n    _watchdog?.cancel();\n    _watchdog = null;\n    _watchdogMisses = 0;\n'
assert s.count(old) == 1
s = s.replace(old, '    _desired = false;\n')
p.write_text(s)
PY
set +e
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s --name 'disconnect owns watchdog cancellation' test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/negative-watchdog.log"
rc=${PIPESTATUS[0]}
set -e
printf 'watchdog-cancellation removal regression exit: %s (expected 1)\n' "$rc" | tee "$root/evidence/negative-watchdog-result.log"
test "$rc" -eq 1
cp "$root/evidence/core.corrected.dart" lib/core.dart
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/restored-regression.log"
cmp lib/core.dart "$root/evidence/core.corrected.dart"
