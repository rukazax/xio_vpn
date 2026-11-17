#!/bin/bash
# Pure JVM proof for the Android native policy work. No Android, no device, no network.
# Usage: run-pure.sh <repo-root> [<evidence-dir>]
set -u
root=${1:?repo root}
evidence=${2:-$root/work/report/android-native-policy-20261106/evidence}
src="$root/app/android/app/src"
classes=$(mktemp -d)
mkdir -p "$evidence"
java_files=$(find "$src/main/java/app/xio/xio" -name '*.java')
test_files=$(find "$src/test/java/app/xio/xio" -name '*.java')
# shellcheck disable=SC2086
javac -nowarn -d "$classes" $java_files $test_files > "$evidence/javac.log" 2>&1
javac_rc=$?
echo "$javac_rc" > "$evidence/javac.exit"
if [ "$javac_rc" != 0 ]; then
  echo "javac failed; see $evidence/javac.log"
  exit 1
fi
status=0
for name in ConnectionBudgetTest BackgroundVerificationOptionsTest PolicyWireTest PolicyJournalTest PolicyAdmissionTest BootTileAdmissionTest RecoveryLivenessTest LegacyDisplayTest UnicodeWhitespaceTest; do
  java -cp "$classes" "app.xio.xio.$name" > "$evidence/$name.log" 2>&1
  rc=$?
  echo "$rc" > "$evidence/$name.exit"
  [ "$rc" = 0 ] || status=1
done
java -cp "$classes" app.xio.xio.ServiceDownWiringTest "$src/main/kotlin/app/xio/xio" > "$evidence/ServiceDownWiringTest.log" 2>&1
echo $? > "$evidence/ServiceDownWiringTest.exit"
[ "$(cat "$evidence/ServiceDownWiringTest.exit")" = 0 ] || status=1
java -cp "$classes" app.xio.xio.PolicyWiringTest "$src/main/kotlin/app/xio/xio" "$src/main/java/app/xio/xio" > "$evidence/PolicyWiringTest.log" 2>&1
echo $? > "$evidence/PolicyWiringTest.exit"
[ "$(cat "$evidence/PolicyWiringTest.exit")" = 0 ] || status=1
rm -rf "$classes"
if [ "$status" = 0 ]; then echo "PURE NATIVE POLICY TESTS PASS"; else echo "PURE NATIVE POLICY TESTS FAILED"; fi
exit "$status"
