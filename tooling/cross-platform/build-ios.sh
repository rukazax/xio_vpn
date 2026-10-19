#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'Build requires macOS with Xcode and iOS SDK.' >&2; exit 1; }
: "${XIO_APPLE_TEAM_ID:?Set XIO_APPLE_TEAM_ID to your registered Apple Developer Team ID}"
: "${XIO_IOS_EXPORT_OPTIONS:?Set XIO_IOS_EXPORT_OPTIONS to your approved ExportOptions.plist}"
XIO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
command -v flutter >/dev/null;command -v go >/dev/null;xcodebuild -version
XIO_STAGE=$(mktemp -d "${TMPDIR:-/tmp}/xio-ios.XXXXXX")
trap 'rm -rf "$XIO_STAGE"' EXIT
mkdir -p "$XIO_STAGE/app"
rsync -a --exclude=build --exclude=.dart_tool --exclude=Pods --exclude=ephemeral --exclude=Flutter.framework --exclude=App.framework "$XIO_ROOT/app/" "$XIO_STAGE/app/"
# The test-only plugin must never be shipped with the production app.
python3 - "$XIO_STAGE/app/pubspec.yaml" <<'PY'
import sys
p=sys.argv[1];s=open(p).read();s=s.replace('  integration_test:\n    sdk: flutter\n','');open(p,'w').write(s)
PY
export PATH="$(go env GOPATH)/bin:$PATH"
command -v gomobile >/dev/null || go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
command -v gobind >/dev/null || go install golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
gomobile init
mkdir -p "$XIO_STAGE/app/ios/Frameworks"
(cd "$XIO_ROOT/protocol/rivet" && gomobile bind -target=ios,iossimulator -iosversion=15.0 -o "$XIO_STAGE/app/ios/Frameworks/XIORivet.xcframework" ./apple)
# Team is supplied at build time; no publisher identity or provisioning profile is invented.
python3 - "$XIO_STAGE/app/ios/Runner.xcodeproj/project.pbxproj" "$XIO_APPLE_TEAM_ID" <<'PY'
import sys,re
p,team=sys.argv[1:];assert re.fullmatch('[A-Z0-9]{10}',team)
s=open(p).read();s=s.replace('CODE_SIGN_STYLE = Automatic;',f'CODE_SIGN_STYLE = Automatic;\n DEVELOPMENT_TEAM = {team};');open(p,'w').write(s)
PY
(cd "$XIO_STAGE/app" && flutter pub get && flutter build ipa --release --export-options-plist="$XIO_IOS_EXPORT_OPTIONS")
mkdir -p "$XIO_ROOT/releases/ios019"
cp "$XIO_STAGE/app/build/ios/ipa/"*.ipa "$XIO_ROOT/releases/ios019/"
echo 'IPA copied to releases/ios019. Validate entitlements and install on a registered device/TestFlight before distributing.'
