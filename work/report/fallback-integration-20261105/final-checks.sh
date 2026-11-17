#!/usr/bin/env bash
set -eu
base=/srv/archives/agent-fallback-integration-finalize-20261105
export HOME=$base/home TMPDIR=$base/tmp
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
export GOCACHE=$base/gocache GOMODCACHE=$base/gomodcache
cd "$base/candidate/protocol/rivet"
/opt/go1.27.3/bin/go test -p 1 -count=10 -v -timeout 60s -run '^TestSetup' ./internal/desktop > "$base/evidence/setup-repeat10.log" 2>&1
printf 'setup repeat10 exit=0\n' >> "$base/evidence/setup-repeat10.log"
/opt/go1.27.3/bin/go test -race -p 1 -count=1 -v -timeout 60s -run '^TestSetup' ./internal/desktop > "$base/evidence/setup-race.log" 2>&1
printf 'setup race exit=0\n' >> "$base/evidence/setup-race.log"
cd "$base/candidate/app/android/app/src"
javac -d "$base/java-classes" main/java/app/xio/xio/ConnectionBudget.java main/java/app/xio/xio/PublicationLease.java test/java/app/xio/xio/ConnectionBudgetTest.java test/java/app/xio/xio/ServiceDownWiringTest.java > "$base/evidence/java-final.log" 2>&1
printf 'javac final exit=0\n' >> "$base/evidence/java-final.log"
java -cp "$base/java-classes" app.xio.xio.ConnectionBudgetTest >> "$base/evidence/java-final.log" 2>&1
printf 'original Java budget final exit=0\n' >> "$base/evidence/java-final.log"
java -cp "$base/java-classes" app.xio.xio.ServiceDownWiringTest "$base/candidate/app/android/app/src/main/kotlin/app/xio/xio" >> "$base/evidence/java-final.log" 2>&1
printf 'production gate + source-entry final exit=0\n' >> "$base/evidence/java-final.log"
printf 'FINAL CHECK CHAIN EXIT 0\n'
