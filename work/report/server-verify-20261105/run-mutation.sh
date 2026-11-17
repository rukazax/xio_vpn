#!/usr/bin/env bash
set -euo pipefail
root=/srv/archives/agent-server-verify-20261105
export TMPDIR="$root/tmp"
export PUB_CACHE=/root/.pub-cache
export FLUTTER_SUPPRESS_ANALYTICS=true
cd "$root/app"
cp lib/managed_service.dart "$root/evidence/managed_service.corrected.dart"
trap 'cp "$root/evidence/managed_service.corrected.dart" lib/managed_service.dart' EXIT
python3 - <<'PY'
from pathlib import Path
p = Path('lib/managed_service.dart')
text = p.read_text()
old = '    await verifyUpdateArchive(local, archiveBytes);'
assert text.count(old) == 1
p.write_text(text.replace(old, '    verifyUpdateArchive(local, archiveBytes);'))
PY
set +e
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/managed_update_verification_test.dart 2>&1 | tee "$root/evidence/missing-await-mutation.log"
rc=${PIPESTATUS[0]}
set -e
printf 'missing-await mutation test exit: %s (expected 1)\n' "$rc" | tee "$root/evidence/mutation-result.log"
test "$rc" -eq 1
cp "$root/evidence/managed_service.corrected.dart" lib/managed_service.dart
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded test/managed_update_verification_test.dart 2>&1 | tee "$root/evidence/restored-regression.log"
