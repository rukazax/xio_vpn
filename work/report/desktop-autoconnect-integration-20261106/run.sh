#!/bin/bash
set -u
R=/srv/archives/agent-desktop-autoconnect-review-20261106/integration-1e24
export HOME=$R/home TMPDIR=$R/tmp TMP=$R/tmp TEMP=$R/tmp XDG_CACHE_HOME=$R/cache XDG_DATA_HOME=$R/data XDG_CONFIG_HOME=$R/config
export PUB_CACHE=/srv/archives/agent-desktop-autoconnect-review-20261106/cache/pub
export FLUTTER_SUPPRESS_ANALYTICS=true CI=true GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
unset XIO_LIVE_INSTALL XIO_LIVE_SSH XIO_VPS_INSTALL XIO_ASSET_AUDIT XIO_CAPTURE_IMAGES XIO_DESKTOP_PRIVATE_BUNDLE XIO_RELEASE_DIR XIO_VAULT_TEST_ROOT TTL_ROOT XIO_WINDOWS_SCRIPT_EXPORT XIO_WINDOWS_TEST_ROOT
cd "$R"
sha256sum candidate.tar > evidence/archive.sha256
tar xf candidate.tar
cd app
find lib test assets -type f -print0 | sort -z | xargs -0 sha256sum > ../evidence/pre.sha256
sha256sum pubspec.yaml pubspec.lock analysis_options.yaml >> ../evidence/pre.sha256
/opt/flutter/bin/flutter --version > ../evidence/sdk.log 2>&1
/opt/flutter/bin/flutter pub get --offline > ../evidence/pub.log 2>&1
p=$?;echo $p > ../evidence/pub.exit;if [ $p != 0 ];then exit $p;fi
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter=expanded --dart-define=XIO_CLIENT_ONLY=true test/desktop_autoconnect_test.dart test/legal_consent_test.dart test/background_probe_plan_test.dart test/fallback_budget_test.dart test/status_lifecycle_test.dart test/routing_contract_invariants_test.dart test/routing_domains_test.dart test/dns_contract_test.dart > ../evidence/client.log 2>&1
echo $? > ../evidence/client.exit
/opt/flutter/bin/flutter analyze --no-pub > ../evidence/analyze.log 2>&1
echo $? > ../evidence/analyze.exit
printf '%q ' /opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter=expanded test/*_test.dart > ../evidence/full-command.txt
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter=expanded test/*_test.dart > ../evidence/full.log 2>&1
echo $? > ../evidence/full.exit
cp ../probes.dart test/review_c6_probe_test.dart
{ printf "import 'package:flutter_test/flutter_test.dart';\n"; cat lib/desktop_engine.dart ../adapter_tail.txt; } > lib/review_adapter_test.dart
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter=expanded test/review_c6_probe_test.dart lib/review_adapter_test.dart > ../evidence/probes.log 2>&1
echo $? > ../evidence/probes.exit
sha256sum lib/review_adapter_test.dart test/review_c6_probe_test.dart > ../evidence/probes.sha256
sha256sum -c ../evidence/pre.sha256 > ../evidence/post.log 2>&1
echo $? > ../evidence/post.exit
