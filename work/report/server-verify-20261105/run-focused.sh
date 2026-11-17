#!/usr/bin/env bash
set -euo pipefail
root=/srv/archives/agent-server-verify-20261105
export TMPDIR="$root/tmp"
export PUB_CACHE=/root/.pub-cache
export FLUTTER_SUPPRESS_ANALYTICS=true
cd "$root/app"
/opt/flutter/bin/flutter --version 2>&1 | tee "$root/evidence/flutter-version.log"
/opt/flutter/bin/flutter pub get --offline 2>&1 | tee "$root/evidence/pub-get.log"
/opt/flutter/bin/dart format test/managed_update_verification_test.dart 2>&1 | tee "$root/evidence/format.log"
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded test/managed_update_verification_test.dart test/install_domain_security_test.dart 2>&1 | tee "$root/evidence/focused-tests.log"
/opt/flutter/bin/dart analyze lib/managed_service.dart test/managed_update_verification_test.dart 2>&1 | tee "$root/evidence/analyze.log"
