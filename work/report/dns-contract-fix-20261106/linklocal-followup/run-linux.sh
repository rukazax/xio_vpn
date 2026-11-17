#!/bin/bash
set -eu
b=/srv/archives/agent-dns-contract-fix-20261106
export HOME="$b/home" XDG_DATA_HOME="$b/home/data" TMPDIR="$b/tmp" PUB_CACHE="$b/pub-cache"
export CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH="/opt/flutter/bin:$PATH"
cd "$b/source/app"
run() { printf '\nUTC %s COMMAND:' "$(date -u +%FT%TZ)"; printf ' %q' "$@"; printf '\n'; set +e; "$@"; rc=$?; set -e; echo "EXIT=$rc"; return "$rc"; }
if [ "$1" = baseline ]; then
  run flutter --no-version-check test --no-pub --no-test-assets --concurrency=1 --reporter expanded test/dns_contract_test.dart --name 'DNS (rejects every|accepts non-link-local)'
else
  run dart format --output=none --set-exit-if-changed lib/managed_models.dart test/dns_contract_test.dart
  run flutter --no-version-check analyze --no-pub lib/managed_models.dart lib/app_settings.dart lib/core.dart lib/managed_service.dart lib/subclients.dart test/dns_contract_test.dart test/app_settings_test.dart
  run flutter --no-version-check test --no-pub --concurrency=1 --reporter expanded test/dns_contract_test.dart test/app_settings_test.dart test/managed_models_test.dart test/account_access_test.dart test/native_profile_readiness_test.dart test/domain_host_test.dart test/install_domain_security_test.dart test/server_address_test.dart test/managed_update_verification_test.dart test/l10n_test.dart
fi
