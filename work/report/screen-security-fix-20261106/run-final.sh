#!/bin/bash
set -u
cd /srv/archives/agent-screen-security-fix-20261106
export HOME="$PWD/home" TMPDIR="$PWD/tmp" XDG_CACHE_HOME="$PWD/cache" XDG_CONFIG_HOME="$PWD/xdg" XDG_DATA_HOME="$PWD/xdg/data" PUB_CACHE="$PWD/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH=/opt/flutter/bin:$PATH
sha256sum -c tested-app.sha256 > logs/source-before.txt 2>&1
echo $? > logs/source-before.exit
cd app
dart format --output=none --set-exit-if-changed lib/app_settings.dart lib/core.dart lib/client_policy.dart test/app_settings_test.dart test/screen_security_test.dart > ../logs/format-final.txt 2>&1
echo $? > ../logs/format-final.exit
flutter test --no-pub --concurrency=1 --reporter=expanded > ../logs/full-suite.txt 2>&1
echo $? > ../logs/full-suite.exit
flutter test --no-pub --concurrency=1 --reporter=expanded --dart-define=XIO_CLIENT_ONLY=true test/screen_security_test.dart test/app_settings_test.dart test/client_only_test.dart > ../logs/client-mode.txt 2>&1
echo $? > ../logs/client-mode.exit
flutter analyze --no-pub > ../logs/final-analyze.txt 2>&1
echo $? > ../logs/final-analyze.exit
cd ..
sha256sum -c tested-app.sha256 > logs/source-after.txt 2>&1
echo $? > logs/source-after.exit
