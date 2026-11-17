#!/bin/bash
set -eu
base=/srv/archives/agent-split-routing-fixes-20261106
mkdir -p "$base"/{baseline,final,home,tmp}
cp -a --reflink=auto /srv/archives/audit-client-full-20261105/pub-cache "$base/pub-cache"
tar -xf "$base/base-app.tar" -C "$base/baseline"
tar -xf "$base/base-app.tar" -C "$base/final"
tar -xf "$base/overlay.tar" -C "$base/final"
cp "$base/final/app/test/routing_contract_invariants_test.dart" "$base/baseline/app/test/"
export HOME="$base/home" TMPDIR="$base/tmp" PUB_CACHE="$base/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
cd "$base/baseline/app"
/opt/flutter/bin/flutter --no-version-check pub get --offline > "$base/baseline-pub.log" 2>&1
set +e
/opt/flutter/bin/flutter --no-version-check test --no-pub --no-test-assets --concurrency=1 --reporter expanded --timeout 15s --name '65 distinct|97 answers|128 manual|empty and partial|failed native|failed clear|old gated' test/routing_contract_invariants_test.dart > "$base/baseline-negative.log" 2>&1
printf '%s\n' "$?" > "$base/baseline-exit.txt"
set -e
cd "$base/final/app"
/opt/flutter/bin/flutter --no-version-check pub get --offline > "$base/final-pub.log" 2>&1
set +e
/opt/flutter/bin/flutter --no-version-check test --no-pub --no-test-assets --concurrency=1 --reporter expanded --timeout 30s test/routing_contract_invariants_test.dart test/routing_domains_test.dart test/status_lifecycle_test.dart test/status_poll_idle_test.dart test/background_polling_test.dart test/watchdog_interval_test.dart test/connection_users_test.dart test/fallback_budget_test.dart > "$base/initial-tests.log" 2>&1
code=$?
printf '%s\n' "$code" > "$base/initial-exit.txt"
exit "$code"
