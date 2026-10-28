#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Compile both app targets without signing; Simulator is a UI smoke test, not a VPN test.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo 'Requires macOS, Xcode and the iOS SDK; Windows/WSL is not supported.' >&2; exit 64; }
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT="$ROOT/.build-support/ios-ci"
for tool in flutter go xcodebuild xcrun python3 rsync; do command -v "$tool" >/dev/null; done
mkdir -p "$OUT"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/xio-ios-check.XXXXXX")
ENVIRONMENT=NOT_RUN
FRAMEWORK=NOT_RUN
DEVICE=NOT_RUN
SIMULATOR_BOOT=NOT_RUN
SIMULATOR_APP=NOT_RUN
UDID=''
finish() {
  rc=$?
  trap - EXIT
  python3 - "$OUT/result.json" "$rc" "$ENVIRONMENT" "$FRAMEWORK" "$DEVICE" "$SIMULATOR_BOOT" "$SIMULATOR_APP" "${GITHUB_SHA:-local}" <<'PY'
import datetime, json, sys
path, rc, environment, framework, device, boot, app, revision = sys.argv[1:]
with open(path, 'w') as output:
    json.dump(dict(at=datetime.datetime.now(datetime.timezone.utc).isoformat(), revision=revision,
                   exitCode=int(rc), environment=environment, nativeFramework=framework,
                   unsignedDeviceCompile=device, simulatorBoot=boot, simulatorAppLaunch=app,
                   signing='NOT_PERFORMED', physicalIPhoneVPN='NOT_TESTED',
                   simulatorDoesNotValidateNetworkExtensionVPN=True), output, indent=2)
    output.write('\n')
PY
  if [[ -n "$UDID" ]]; then xcrun simctl shutdown "$UDID" >/dev/null 2>&1 || true; fi
  rm -rf "$STAGE"
  exit "$rc"
}
trap finish EXIT
{
  sw_vers
  xcodebuild -version
  xcodebuild -showsdks
  flutter --version
  go version
  xcrun --sdk iphoneos --show-sdk-version
  xcrun --sdk iphonesimulator --show-sdk-version
} | tee "$OUT/environment.txt"
ENVIRONMENT=PASS
mkdir -p "$STAGE/app"
rsync -a --exclude=build --exclude=.dart_tool --exclude=Pods --exclude=ephemeral --exclude=Flutter.framework --exclude=App.framework "$ROOT/app/" "$STAGE/app/"
# Keep the production copy isolated, as in build-ios.sh. Do not edit the source checkout.
python3 - "$STAGE/app/pubspec.yaml" <<'PY'
import sys
path = sys.argv[1]
with open(path) as source: content = source.read()
content = content.replace('  integration_test:\n    sdk: flutter\n', '')
with open(path, 'w') as output: output.write(content)
PY
export PATH="$(go env GOPATH)/bin:$PATH"
MOBILE_VERSION=v0.0.0-20261011034528-197770444867
go install "golang.org/x/mobile/cmd/gomobile@$MOBILE_VERSION"
go install "golang.org/x/mobile/cmd/gobind@$MOBILE_VERSION"
gomobile init
mkdir -p "$STAGE/app/ios/Frameworks"
(cd "$ROOT/protocol/rivet" && gomobile bind -target=ios,iossimulator -iosversion=15.0 -o "$STAGE/app/ios/Frameworks/XIORivet.xcframework" ./apple)
test -f "$STAGE/app/ios/Frameworks/XIORivet.xcframework/Info.plist"
FRAMEWORK=PASS
(cd "$STAGE/app" && flutter pub get && flutter build ios --release --no-codesign)
DEVICE_APP="$STAGE/app/build/ios/iphoneos/Runner.app"
test -f "$DEVICE_APP/Runner"
test -f "$DEVICE_APP/PlugIns/PacketTunnel.appex/PacketTunnel"
file "$DEVICE_APP/Runner" "$DEVICE_APP/PlugIns/PacketTunnel.appex/PacketTunnel" | tee "$OUT/device-binaries.txt"
DEVICE=PASS
(cd "$STAGE/app" && flutter build ios --simulator --debug --no-codesign)
SIM_APP="$STAGE/app/build/ios/iphonesimulator/Runner.app"
test -f "$SIM_APP/Runner"
xcrun simctl list devices available -j > "$OUT/available-devices.json"
# Only select a shut-down, available iPhone so cleanup never shuts down an existing session.
UDID=$(python3 - "$OUT/available-devices.json" <<'PY'
import json, sys
with open(sys.argv[1]) as source: devices = json.load(source)['devices']
phones = [d for runtime, rows in devices.items() if 'iOS' in runtime for d in rows
          if d.get('isAvailable') and d.get('state') == 'Shutdown' and d.get('name', '').startswith('iPhone')]
if not phones: raise SystemExit('No available shut-down iPhone Simulator runtime; smoke test is BLOCKED.')
print(phones[0]['udid'])
PY
)
xcrun simctl boot "$UDID"
python3 - "$UDID" <<'PY'
import subprocess, sys
subprocess.run(['xcrun', 'simctl', 'bootstatus', sys.argv[1], '-b'], check=True, timeout=240)
PY
SIMULATOR_BOOT=PASS
xcrun simctl install "$UDID" "$SIM_APP"
xcrun simctl launch --terminate-running-process "$UDID" app.xio.client | tee "$OUT/simulator-launch.txt"
python3 - "$UDID" "$OUT/simulator.png" <<'PY'
import pathlib, subprocess, sys, time
# A bounded render settling period inside this smoke test, not a background polling loop.
time.sleep(6)
services = subprocess.run(['xcrun', 'simctl', 'spawn', sys.argv[1], 'launchctl', 'list'],
                          capture_output=True, text=True, check=True, timeout=30).stdout
pathlib.Path(sys.argv[2]).with_name('simulator-services.txt').write_text(services)
if not any('app.xio.client' in line and line.split()[0].isdigit() for line in services.splitlines()):
    raise SystemExit('XIO did not remain running after launch; Simulator smoke test FAILED.')
subprocess.run(['xcrun', 'simctl', 'io', sys.argv[1], 'screenshot', sys.argv[2]], check=True, timeout=30)
PY
SIMULATOR_APP=PASS
echo 'PASS: unsigned app and PacketTunnel compiled; iPhone Simulator booted and app launch/screenshot captured.'
echo 'NOT CHECKED: signing, provisioning, installation on a physical iPhone, real VPN traffic or App Store acceptance.'
