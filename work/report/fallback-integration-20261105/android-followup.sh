#!/usr/bin/env bash
set -eu
base=/srv/archives/agent-fallback-integration-finalize-20261105
export HOME=$base/home TMPDIR=$base/tmp
mkdir -p "$base/c3-before-android-correction"
tar -xf "$base/c3-android.tar" -C "$base/c3-before-android-correction"
tar -xf "$base/android-followup.tar" -C "$base/candidate"
cd "$base/candidate/app/android/app/src"
javac -d "$base/java-classes" main/java/app/xio/xio/ConnectionBudget.java main/java/app/xio/xio/PublicationLease.java test/java/app/xio/xio/ConnectionBudgetTest.java test/java/app/xio/xio/ServiceDownWiringTest.java > "$base/evidence/java-corrected.log" 2>&1
printf 'corrected javac exit=0\n' >> "$base/evidence/java-corrected.log"
set +e
java -cp "$base/java-classes" app.xio.xio.ServiceDownWiringTest "$base/c3-before-android-correction/app/android/app/src/main/kotlin/app/xio/xio" > "$base/evidence/c3-child-scope-negative.log" 2>&1
code=$?
set -e
printf 'c3 child-scope actual-source invariant exit=%s (expected1)\n' "$code" >> "$base/evidence/c3-child-scope-negative.log"
if [ "$code" != 1 ];then exit 91;fi
java -cp "$base/java-classes" app.xio.xio.ConnectionBudgetTest >> "$base/evidence/java-corrected.log" 2>&1
printf 'original budget invariants exit=0\n' >> "$base/evidence/java-corrected.log"
java -cp "$base/java-classes" app.xio.xio.ServiceDownWiringTest "$base/candidate/app/android/app/src/main/kotlin/app/xio/xio" >> "$base/evidence/java-corrected.log" 2>&1
printf 'corrected actual source wiring + production lease/fallback/cancel-owner invariants exit=0\n' >> "$base/evidence/java-corrected.log"
printf 'ANDROID FOLLOWUP EXIT 0\n'
