#!/usr/bin/env bash
set -euo pipefail
root=/srv/archives/agent-runtime-p2-20261105
export TMPDIR="$root/tmp"
export PUB_CACHE=/root/.pub-cache
export FLUTTER_SUPPRESS_ANALYTICS=true
cd "$root/app"
/opt/flutter/bin/dart format test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/format-final.log"
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/status_lifecycle_test.dart test/status_poll_idle_test.dart test/background_polling_test.dart test/watchdog_interval_test.dart test/connection_users_test.dart 2>&1 | tee "$root/evidence/focused-tests.log"
/opt/flutter/bin/dart analyze lib/core.dart test/status_lifecycle_test.dart 2>&1 | tee "$root/evidence/analyze.log"
