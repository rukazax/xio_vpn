#!/bin/bash
set -eu
b=/srv/archives/agent-dns-contract-fix-20261106
export HOME="$b/home" TMPDIR="$b/tmp" GOMAXPROCS=2 GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
export GOCACHE="$b/gocache" GOMODCACHE="$b/gomodcache"
cd "$b/source/protocol/rivet"
printf 'UTC %s COMMAND: go test -p 1 -count=1 -v -timeout 30s -run ^TestDNSSettingNativeContract$ ./internal/desktop\n' "$(date -u +%FT%TZ)"
set +e
/opt/go1.27.3/bin/go test -p 1 -count=1 -v -timeout 30s -run '^TestDNSSettingNativeContract$' ./internal/desktop
rc=$?
echo "EXIT=$rc"
exit "$rc"
