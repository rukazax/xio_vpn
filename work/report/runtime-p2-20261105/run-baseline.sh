#!/usr/bin/env bash
set -euo pipefail
root=/srv/archives/agent-runtime-p2-20261105
export TMPDIR="$root/tmp"
export PUB_CACHE=/root/.pub-cache
export FLUTTER_SUPPRESS_ANALYTICS=true
cd "$root/app"
/opt/flutter/bin/flutter --version 2>&1 | tee "$root/evidence/flutter-version.log"
/opt/flutter/bin/flutter pub get --offline 2>&1 | tee "$root/evidence/pub-get.log"
/opt/flutter/bin/dart format test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/format.log"
set +e
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/baseline-regression.log"
rc=${PIPESTATUS[0]}
set -e
printf 'baseline regression exit: %s (expected 1)\n' "$rc" | tee "$root/evidence/baseline-result.log"
test "$rc" -eq 1
