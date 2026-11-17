#!/bin/bash
set -u
cd /srv/archives/agent-screen-security-fix-20261106
export HOME="$PWD/home" TMPDIR="$PWD/tmp" XDG_CACHE_HOME="$PWD/cache" XDG_CONFIG_HOME="$PWD/xdg" XDG_DATA_HOME="$PWD/xdg/data" PUB_CACHE="$PWD/pub-cache" CI=true FLUTTER_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
export PATH=/opt/flutter/bin:$PATH
cd app
flutter --version > ../logs/version.txt 2>&1
flutter pub get --offline > ../logs/pub-get.txt 2>&1
echo $? > ../logs/pub-get.exit
flutter test --no-pub --concurrency=1 --reporter=expanded test/screen_security_test.dart > ../logs/red.txt 2>&1
echo $? > ../logs/red.exit
flutter analyze --no-pub > ../logs/baseline-analyze.txt 2>&1
echo $? > ../logs/baseline-analyze.exit
