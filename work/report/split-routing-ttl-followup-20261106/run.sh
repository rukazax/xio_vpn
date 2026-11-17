#!/bin/bash
set -eu
base=/srv/archives/agent-split-routing-ttl-followup-20261106
mkdir -p "$base"/{final,home,tmp}
if [ ! -d "$base/pub-cache" ]; then cp -a --reflink=auto /srv/archives/agent-split-routing-fixes-20261106/pub-cache "$base/pub-cache"; fi
tar -xf "$base/base.tar" -C "$base/final"
tar -xf "$base/overlay.tar" -C "$base/final"
export HOME="$base/home" TMPDIR="$base/tmp" PUB_CACHE="$base/pub-cache" TTL_ROOT="$base" CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
cd "$base/final/app"
/opt/flutter/bin/flutter --no-version-check pub get --offline > "$base/pub.log" 2>&1
files='lib/core.dart lib/routing_domains.dart test/routing_contract_invariants_test.dart test/routing_resolution_completeness_test.dart test/routing_native_clock_test.dart test/split_domains_store_test.dart test/connection_users_test.dart'
/opt/flutter/bin/cache/dart-sdk/bin/dart format $files > "$base/format.log" 2>&1
/opt/flutter/bin/flutter --no-version-check test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/routing_contract_invariants_test.dart test/routing_resolution_completeness_test.dart test/routing_native_clock_test.dart test/split_domains_store_test.dart test/routing_domains_test.dart test/status_lifecycle_test.dart test/status_poll_idle_test.dart test/background_polling_test.dart test/watchdog_interval_test.dart test/connection_users_test.dart test/fallback_budget_test.dart > "$base/tests.log" 2>&1
/opt/flutter/bin/cache/dart-sdk/bin/dart analyze $files > "$base/analyze-final.log" 2>&1
/opt/flutter/bin/cache/dart-sdk/bin/dart format --output=none --set-exit-if-changed $files > "$base/format-check.log" 2>&1
python3 "$base/validate_native.py"
python3 "$base/record-source.py"
printf 'TTL follow-up final checks exit0\n'
