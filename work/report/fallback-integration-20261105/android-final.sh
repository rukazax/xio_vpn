#!/usr/bin/env bash
set -eu
base=/srv/archives/agent-fallback-integration-finalize-20261105
root=$base/final-android
export HOME=$base/home TMPDIR=$base/tmp
mkdir -p "$root/app/android/app" "$base/java-final-classes" "$base/owner-before-correction"
tar -xf "$base/owner-before-correction.tar" -C "$base/owner-before-correction"
mkdir -p "$base/replacement-before-correction" "$base/replacement-old-classes"
tar -xf "$base/replacement-before-correction.tar" -C "$base/replacement-before-correction"
cp -a "$base/candidate/app/android/app/src" "$root/app/android/app/"
tar -xf "$base/android-final.tar" -C "$root"
cd "$root/app/android/app/src"
javac -d "$base/java-final-classes" main/java/app/xio/xio/ConnectionBudget.java main/java/app/xio/xio/PublicationLease.java test/java/app/xio/xio/ConnectionBudgetTest.java test/java/app/xio/xio/ServiceDownWiringTest.java > "$base/evidence/java-corrected-final.log" 2>&1
printf 'final corrected javac exit=0\n' >> "$base/evidence/java-corrected-final.log"
java -cp "$base/java-final-classes" app.xio.xio.ConnectionBudgetTest >> "$base/evidence/java-corrected-final.log" 2>&1
java -cp "$base/java-final-classes" app.xio.xio.ServiceDownWiringTest "$root/app/android/app/src/main/kotlin/app/xio/xio" >> "$base/evidence/java-corrected-final.log" 2>&1
printf 'final original budget + actual-source/production gate/fallback/cancel-owner exit=0\n' >> "$base/evidence/java-corrected-final.log"
set +e
java -cp "$base/java-final-classes" app.xio.xio.ServiceDownWiringTest "$base/c3-before-android-correction/app/android/app/src/main/kotlin/app/xio/xio" > "$base/evidence/c3-child-scope-negative-final.log" 2>&1
code=$?
set -e
printf 'c3 child-scope final source invariant exit=%s (expected1)\n' "$code" >> "$base/evidence/c3-child-scope-negative-final.log"
[ "$code" = 1 ]
set +e
java -cp "$base/java-final-classes" app.xio.xio.ServiceDownWiringTest "$base/owner-before-correction/app/android/app/src/main/kotlin/app/xio/xio" > "$base/evidence/obsolete-cleanup-source-negative.log" 2>&1
code=$?
set -e
printf '00e4 obsolete cleanup source invariant exit=%s (expected1)\n' "$code" >> "$base/evidence/obsolete-cleanup-source-negative.log"
[ "$code" = 1 ]
set +e
java -cp "$base/java-final-classes" app.xio.xio.ServiceDownWiringTest "$base/replacement-before-correction/app/android/app/src/main/kotlin/app/xio/xio" > "$base/evidence/replacement-source-negative.log" 2>&1
code=$?
set -e
printf '5b replacement unique publication source invariant exit=%s (expected1)\n' "$code" >> "$base/evidence/replacement-source-negative.log"
[ "$code" = 1 ]
javac -d "$base/replacement-old-classes" "$base/replacement-before-correction/app/android/app/src/main/java/app/xio/xio/ConnectionBudget.java" "$base/replacement-before-correction/app/android/app/src/main/java/app/xio/xio/PublicationLease.java" "$base/ReviewReplacementPublicationInvariant.java"
set +e
java -cp "$base/replacement-old-classes" app.xio.xio.ReviewReplacementPublicationInvariant "$base/replacement-before-correction/app/android/app/src/main/kotlin/app/xio/xio/MainActivity.kt" > "$base/evidence/replacement-actual-old-gate-negative.log" 2>&1
code=$?
set -e
printf 'I immutable actual5b gate + source replacement invariant exit=%s (expected1)\n' "$code" >> "$base/evidence/replacement-actual-old-gate-negative.log"
[ "$code" = 1 ]
printf 'FINAL EXACT ANDROID SOURCE EXIT 0\n'
