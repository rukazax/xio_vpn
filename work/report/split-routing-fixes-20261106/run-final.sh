#!/bin/bash
set -eu
base=/srv/archives/agent-split-routing-fixes-20261106
tar -xf "$base/overlay.tar" -C "$base/final"
tar -xf "$base/assets.tar" -C "$base/final"
export HOME="$base/home" TMPDIR="$base/tmp" PUB_CACHE="$base/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
cd "$base/final/app"
/opt/flutter/bin/cache/dart-sdk/bin/dart format lib/core.dart lib/routing_domains.dart test/routing_contract_invariants_test.dart test/routing_resolution_completeness_test.dart test/split_domains_store_test.dart test/connection_users_test.dart > "$base/format.log" 2>&1
cp test/routing_contract_invariants_test.dart "$base/baseline/app/test/"
set +e
(cd "$base/baseline/app" && /opt/flutter/bin/flutter --no-version-check test --no-pub --no-test-assets --concurrency=1 --reporter expanded --timeout 15s --name '65 distinct|97 answers|128 manual|empty and partial|failed native|failed clear|old gated' test/routing_contract_invariants_test.dart) > "$base/baseline-negative.log" 2>&1
negative=$?
printf '%s\n' "$negative" > "$base/baseline-exit.txt"
set -e
test "$negative" -ne 0
/opt/flutter/bin/flutter --no-version-check test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/routing_contract_invariants_test.dart test/routing_resolution_completeness_test.dart test/split_domains_store_test.dart test/routing_domains_test.dart test/status_lifecycle_test.dart test/status_poll_idle_test.dart test/background_polling_test.dart test/watchdog_interval_test.dart test/connection_users_test.dart test/fallback_budget_test.dart > "$base/final-tests.log" 2>&1
/opt/flutter/bin/cache/dart-sdk/bin/dart analyze lib/core.dart lib/routing_domains.dart test/routing_contract_invariants_test.dart test/routing_resolution_completeness_test.dart test/split_domains_store_test.dart test/connection_users_test.dart > "$base/analyze.log" 2>&1
python3 "$base/validate_native.py"
printf 'FINAL bounded validation exit0\n'
