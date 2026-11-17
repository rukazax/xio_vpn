#!/bin/sh
set -eu
base=/srv/archives/agent-fallback-finish-20261105
export TMPDIR=$base/tmp GOCACHE=$base/gocache GOMODCACHE=$base/gomodcache GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
cd "$base"
cp protocol/rivet/mobile/lifecycle.go evidence/lifecycle.before-epoch-negative
cp ConnectionBudget.java evidence/ConnectionBudget.before-cancel-negative
trap 'cp evidence/lifecycle.before-epoch-negative protocol/rivet/mobile/lifecycle.go; cp evidence/ConnectionBudget.before-cancel-negative ConnectionBudget.java' EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('protocol/rivet/mobile/lifecycle.go');s=p.read_text();old='return !s.closed && s.retirementPending && s.retiredDone == done && s.retiredSession == session && s.recoveryID == retirementID';assert old in s;s=s.replace(old,'return !s.closed && s.retirementPending').replace('retirementID := s.recoveryID','_ = s.recoveryID');p.write_text(s)
p=Path('ConnectionBudget.java');s=p.read_text();old='this.clock = clock; this.deadline = deadline; this.parent = parent;\n        this.cancelled = new AtomicBoolean();';assert old in s;s=s.replace(old,'this.clock = clock; this.deadline = deadline; this.parent = null;\n        this.cancelled = parent.cancelled;');p.write_text(s)
PY
set +e
(cd protocol/rivet && /opt/go1.27.3/bin/go test -p 1 -count=1 -run '^TestRecoveryOldRetirementObserver' -v -timeout 30s ./mobile) > evidence/go-epoch-negative.log 2>&1
go_code=$?
javac -d java-classes ConnectionBudget.java ConnectionBudgetTest.java > evidence/java-child-negative.log 2>&1
compile_code=$?
java -cp java-classes app.xio.xio.ConnectionBudgetTest >> evidence/java-child-negative.log 2>&1
java_code=$?
set -e
cat evidence/go-epoch-negative.log
cat evidence/java-child-negative.log
printf 'negative Go=%s JavaCompile=%s JavaRun=%s (expected 1,0,1)\n' "$go_code" "$compile_code" "$java_code"
test "$go_code" -ne 0
test "$compile_code" -eq 0
test "$java_code" -ne 0
cp evidence/lifecycle.before-epoch-negative protocol/rivet/mobile/lifecycle.go
cp evidence/ConnectionBudget.before-cancel-negative ConnectionBudget.java
javac -d java-classes ConnectionBudget.java ConnectionBudgetTest.java > evidence/java-budget-final-v3.log 2>&1
java -cp java-classes app.xio.xio.ConnectionBudgetTest >> evidence/java-budget-final-v3.log 2>&1
cat evidence/java-budget-final-v3.log
