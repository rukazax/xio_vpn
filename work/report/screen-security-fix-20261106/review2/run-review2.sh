#!/bin/bash
set -u
cd /srv/archives/agent-screen-security-fix-20261106
export HOME="$PWD/home" TMPDIR="$PWD/tmp" XDG_CACHE_HOME="$PWD/cache" XDG_CONFIG_HOME="$PWD/xdg" XDG_DATA_HOME="$PWD/xdg/data" PUB_CACHE="$PWD/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH=/opt/flutter/bin:$PATH
mkdir -p logs-review2
echo $$ > logs-review2/wrapper.pid
sha256sum -c tested-review2-app.sha256 > logs-review2/source-before.txt 2>&1
echo $? > logs-review2/source-before.exit
cd app
dart format --output=none --set-exit-if-changed lib/core.dart test/screen_security_review_regression_test.dart > ../logs-review2/format.txt 2>&1
echo $? > ../logs-review2/format.exit
flutter test --no-pub --concurrency=1 --reporter=expanded test/screen_security_test.dart test/screen_security_review_regression_test.dart test/app_settings_test.dart test/l10n_test.dart test/status_poll_idle_test.dart > ../logs-review2/targeted.txt 2>&1
echo $? > ../logs-review2/targeted.exit
flutter test --no-pub --concurrency=1 --reporter=expanded > ../logs-review2/full-suite.txt 2>&1
echo $? > ../logs-review2/full-suite.exit
flutter test --no-pub --concurrency=1 --reporter=expanded --dart-define=XIO_CLIENT_ONLY=true test/screen_security_test.dart test/screen_security_review_regression_test.dart test/app_settings_test.dart test/client_only_test.dart > ../logs-review2/client-mode.txt 2>&1
echo $? > ../logs-review2/client-mode.exit
flutter analyze --no-pub > ../logs-review2/analyze.txt 2>&1
echo $? > ../logs-review2/analyze.exit
cd ..
sha256sum -c tested-review2-app.sha256 > logs-review2/source-after.txt 2>&1
echo $? > logs-review2/source-after.exit
echo complete > logs-review2/wrapper.complete
