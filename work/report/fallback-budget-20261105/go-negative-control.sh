#!/bin/sh
set -eu
base=/srv/archives/agent-fallback-finish-20261105
export TMPDIR=$base/tmp GOCACHE=$base/gocache GOMODCACHE=$base/gomodcache GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2
cd "$base/protocol/rivet"
cp mobile/mobile.go "$base/evidence/mobile.go.before-negative"
cp mobile/reconnect_policy.go "$base/evidence/reconnect_policy.go.before-negative"
trap 'cp "$base/evidence/mobile.go.before-negative" mobile/mobile.go; cp "$base/evidence/reconnect_policy.go.before-negative" mobile/reconnect_policy.go' EXIT
python3 - <<'PY'
from pathlib import Path
p=Path('mobile/mobile.go'); s=p.read_text();s=s.replace('s.hooks.dial(ctx, dialCtx, cfg, p, left)','s.hooks.dial(dialCtx, dialCtx, cfg, p, left)');s=s.replace('beginStop(s, "failed")\n\t\t\treturn','// negative: silently abandon IO owner\n\t\t\treturn');s=s.replace('beginStop(s, "failed")\n\t\t\t\treturn','// negative: silently abandon IO owner\n\t\t\t\treturn');p.write_text(s)
p=Path('mobile/reconnect_policy.go');s=p.read_text().replace('hooks.dial(parent, dialCtx, candidate, p, phase)','hooks.dial(dialCtx, dialCtx, candidate, p, phase)');p.write_text(s)
PY
set +e
/opt/go1.27.3/bin/go test -p 1 -count=1 -run '^TestRecovery(StartupWinner|RecoveredWinner|Terminal)' -v -timeout 30s ./mobile > "$base/evidence/go-negative-control.log" 2>&1
code=$?
set -e
cat "$base/evidence/go-negative-control.log"
printf 'negative control exit=%s (expected nonzero)\n' "$code"
test "$code" -ne 0
