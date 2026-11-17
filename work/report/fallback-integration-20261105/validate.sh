#!/usr/bin/env bash
set -u
base=/srv/archives/agent-fallback-integration-finalize-20261105
export HOME=$base/home TMPDIR=$base/tmp
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
export GOCACHE=$base/gocache GOMODCACHE=$base/gomodcache
GO=/opt/go1.27.3/bin/go
cd "$base/baseline/protocol/rivet" || exit 90
cp "$base/baseline_invariants_test.go" internal/desktop/baseline_invariants_test.go
"$GO" test -p 1 -count=1 -v -timeout 30s -run '^TestBaselineInvariant' ./internal/desktop > "$base/evidence/baseline-invariants.log" 2>&1
code=$?; printf 'baseline desired invariants exit=%s (expected 1)\n' "$code" | tee -a "$base/evidence/baseline-invariants.log"
if [ "$code" != 1 ]; then exit 91; fi
cd "$base/candidate/protocol/rivet" || exit 92
/opt/go1.27.3/bin/gofmt -w internal/desktop/setup_lease.go internal/desktop/setup_lease_test.go internal/desktop/setup_network_linux_test.go internal/desktop/setup_network_windows_test.go internal/desktop/sharing.go internal/desktop/runtime.go internal/desktop/network_common.go internal/desktop/network_linux.go internal/desktop/network_windows.go internal/desktop/sharing_linux.go internal/desktop/sharing_windows.go
"$GO" test -p 1 -count=1 -v -timeout 60s ./internal/desktop > "$base/evidence/desktop-all.log" 2>&1
code=$?; printf 'desktop all exit=%s\n' "$code" | tee -a "$base/evidence/desktop-all.log"
if [ "$code" != 0 ]; then exit 93;fi
"$GO" test -p 1 -count=1 -run '^$' -timeout 30s ./cmd/xio-desktop > "$base/evidence/desktop-command-compile.log" 2>&1
code=$?; printf 'command compile exit=%s\n' "$code" | tee -a "$base/evidence/desktop-command-compile.log"
if [ "$code" != 0 ]; then exit 94;fi
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 "$GO" test -p 1 -c -o "$base/desktop-windows.test.exe" ./internal/desktop > "$base/evidence/windows-crosscompile.log" 2>&1
code=$?; printf 'Windows compile-only exit=%s; NOT EXECUTED\n' "$code" | tee -a "$base/evidence/windows-crosscompile.log"
if [ "$code" != 0 ]; then exit 95;fi
sha256sum "$base/desktop-windows.test.exe" >> "$base/evidence/windows-crosscompile.log"
cd "$base/candidate/app/android/app/src" || exit 96
javac -d "$base/java-classes" main/java/app/xio/xio/ConnectionBudget.java main/java/app/xio/xio/PublicationLease.java test/java/app/xio/xio/ConnectionBudgetTest.java test/java/app/xio/xio/ServiceDownWiringTest.java > "$base/evidence/java.log" 2>&1
code=$?;printf 'javac exit=%s\n' "$code" >> "$base/evidence/java.log"
if [ "$code" != 0 ];then exit 97;fi
java -cp "$base/java-classes" app.xio.xio.ServiceDownWiringTest "$base/baseline/app/android/app/src/main/kotlin/app/xio/xio" > "$base/evidence/android-baseline-negative.log" 2>&1
code=$?;printf 'baseline service-source invariant exit=%s (expected 1)\n' "$code" >> "$base/evidence/android-baseline-negative.log"
if [ "$code" != 1 ];then exit 98;fi
java -cp "$base/java-classes" app.xio.xio.ConnectionBudgetTest >> "$base/evidence/java.log" 2>&1
code=$?;printf 'original Java budget exit=%s\n' "$code" >> "$base/evidence/java.log"
if [ "$code" != 0 ];then exit 99;fi
java -cp "$base/java-classes" app.xio.xio.ServiceDownWiringTest "$base/candidate/app/android/app/src/main/kotlin/app/xio/xio" >> "$base/evidence/java.log" 2>&1
code=$?;printf 'candidate service-source + production gate exit=%s\n' "$code" >> "$base/evidence/java.log"
if [ "$code" != 0 ];then exit 100;fi
printf 'VALIDATION CHAIN EXIT 0\n'
