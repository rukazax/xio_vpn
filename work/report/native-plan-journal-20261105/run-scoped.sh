#!/bin/sh
set -eu
root=/srv/archives/snapshots/native-plan-20261105
mkdir -p "$root/tmp"
export TMPDIR="$root/tmp" PATH=/opt/flutter/bin:$PATH FLUTTER_SUPPRESS_ANALYTICS=true PUB_CACHE=/root/.pub-cache
cd "$root/app"
dart format lib/native_cascade_plan.dart test/native_cascade_plan_test.dart lib/native_cascade_journal.dart test/native_cascade_journal_test.dart > "$root/combined-format.log" 2>&1
dart analyze --fatal-infos lib/native_cascade_plan.dart test/native_cascade_plan_test.dart lib/native_cascade_journal.dart test/native_cascade_journal_test.dart lib/managed_service.dart test/managed_update_verification_test.dart > "$root/combined-analyze.log" 2>&1
flutter test --no-pub --concurrency=1 --reporter expanded test/native_cascade_plan_test.dart test/native_cascade_journal_test.dart test/cascade_identity_test.dart test/cascade_servers_test.dart test/managed_update_verification_test.dart test/install_domain_security_test.dart > "$root/combined-tests.log" 2>&1
printf 'COMBINED_PLAN_AND_UPDATE_PASS\n'
