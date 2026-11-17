#!/bin/bash
set -eu
BASE=/srv/archives/agent-account-vault-fix-20261105
export HOME="$BASE/home" XDG_DATA_HOME="$BASE/home/data" TMPDIR="$BASE/tmp"
export PUB_CACHE="$BASE/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export PATH="/opt/flutter/bin:$PATH"
# Trust only the preinstalled SDK for this process; never edit user git config.
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
cd "$BASE/source/app"
run() {
  printf '\nUTC %s COMMAND:' "$(date -u +%FT%TZ)"
  printf ' %q' "$@"
  printf '\n'
  set +e
  "$@"
  result=$?
  set -e
  echo "EXIT=$result"
  return "$result"
}
run flutter --version
run flutter pub get --offline
export XIO_VAULT_TEST_ROOT="$BASE/$1"
mkdir -p "$XIO_VAULT_TEST_ROOT/home" "$XIO_VAULT_TEST_ROOT/data"
export HOME="$XIO_VAULT_TEST_ROOT/home" XDG_DATA_HOME="$XIO_VAULT_TEST_ROOT/data"
if [ "$1" = baseline ]; then
  run flutter test --no-pub --reporter expanded test/account_vault_desktop_test.dart --plain-name 'AccountVault real desktop roundtrip and protected modes'
elif [ "$1" = related ]; then
  run flutter test --no-pub --reporter expanded test/account_access_test.dart test/native_cascade_journal_test.dart test/desktop_adapter_test.dart
else
  run dart format --output=none --set-exit-if-changed lib/credentials.dart test/account_vault_desktop_test.dart test/credential_id_test.dart
  run flutter analyze --no-pub lib/credentials.dart test/account_vault_desktop_test.dart test/credential_id_test.dart
  run flutter test --no-pub --reporter expanded --dart-define=XIO_CLIENT_ONLY="$2" test/account_vault_desktop_test.dart test/credential_id_test.dart
fi
