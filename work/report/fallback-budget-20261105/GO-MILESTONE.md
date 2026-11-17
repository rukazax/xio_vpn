# Go lifecycle milestone (continuation)

Scope: mobile policy/monitor/IO ownership and minimal RIVET establishment-vs-lifetime API separation. Existing worktree changes preserved. No payloads, bindings, release metadata or system/network/tunnel actions.

## Tests

Own Debian snapshot `/srv/archives/agent-fallback-finish-20261105`, copied offline from inactive predecessor scratch. Initial process inspection found no running prior go/flutter/dart/javac jobs. Environment: `TMPDIR=$base/tmp GOCACHE=$base/gocache GOMODCACHE=$base/gomodcache GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2`.

`/opt/go1.27.3/bin/go test -p 1 -count=1 -run '^TestRecovery' -v -timeout 30s ./mobile`: exit 0, 12 tests PASS (7 inherited + 5 new). See [log](go-recovery-finish.log).

Independent review repro was read before adaptation; original SHA256 `7d093f71edc3af2034b95a519c4665d71758252acbb002d760d585f65671b0cd`. Reviewer scratch never edited.

Negative controls applied ONLY in own snapshot, with EXIT trap restoring sources: feed establishment context as retained lifetime; remove terminal IO beginStop calls. Four new regressions fail for the exact independent findings, exit 1 expected. [Log](go-negative-control.log), [script](go-negative-control.sh). Control harness exit 0 means expected test failures observed, not product tests passing.

## Source SHA256 at milestone

- internal/rivet/client.go: e87a7120ede8c3dbc097be42b09ee5b183f2aa184b1faac9ec8515458dd40f57
- mobile/mobile.go: a2d4d2bf6372670ee012f8d5314eb99efd3eef9e15da7f3f8243dde23acb2948
- mobile/lifecycle.go: 0f28d7b7af1c0dff3eebe8b28f639bc143ea062c87bc172923048bccd3ccc8fc
- mobile/reconnect_policy.go: 26d55fbe7d744250def920c2cb0e70c0c9171abb3a66de2f1f486fd548fc552b
- mobile/reconnect_policy_test.go: e5aedbc22770a3019001e04222ea2ca922571059dc86dee7971ecbcb9cbbad84
- mobile/lifecycle_regression_test.go: ee07bcc6bd74f36608f1b3f3a3d8b5b1ef961424347b8c0dff9e4429a5adaa2c

## Remaining gates

This is deterministic pure session/clock/stdlib-pipe evidence, not real-transport integration or physical 30-second acceptance. AAR/JNI/native desktop helper still need rebuild; shipped assets DO NOT implement new policy/cancel/stop exports. Android full typecompile/APK and Ubuntu/Windows packaged integration remain gates; Apple deferred. Dart/Android/desktop continuation remains in progress in the same exclusive worktree.
