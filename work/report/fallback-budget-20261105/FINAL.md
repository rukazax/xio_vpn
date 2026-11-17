# Fallback budget: bounded source closure, 2026-11-05

## Scope and disposition

Branch `agent/fallback-budget-20261105`, initial HEAD `b6b54153017d0c64952a897eb3ff60c7a556ba8d`. Existing modifications were retained and completed, not reset/stashed/deleted. Only this assigned worktree and an independent Debian test snapshot were written. No push, merge, publication, installation, phone action, real tunnel, route/service operation or security-policy bypass was performed.

Milestones:
- `9a72afe`: bounded native recovery, lifetime/establishment separation, ownership/join regressions.
- `a01a052`: actual H3-carrier revocation and retirement time inside first recovery round.
- `435de09`: exact retirement-epoch fencing, including atomic validation plus stop publication.
- `61b6943`: frozen Dart/Android/desktop source and final evidence.
- Following evidence-only closure normalizes the hash manifest to LF; source hashes remain unchanged. Source-only `git diff --check` passes. Verbatim raw logs retain their original whitespace; a whole-report diff check consequently reports log-output whitespace, not source defects.

Approved final source hashes: [24-file SHA256 manifest](<work/report/fallback-budget-20261105/final-source-sha256.txt>). Earlier Go evidence and initial source hashes: [milestone report](<work/report/fallback-budget-20261105/GO-MILESTONE.md>).

## Implemented behavior

- Explicit typed runtime `ConnectionPolicy.automatic` (default) / `selectedOnly`; preferred protocol remains ordering, not manual mode. Captured Android plans carry the policy; restoration validates it and strict mode only tries the selected candidate. Unsupported/malformed intent fails; no old-JNI automatic downgrade.
- One monotonic foreground round capped at 30 seconds, including candidates, permission waiting, verification and cleanup. Only remaining relative milliseconds cross Dart/Java/Go boundaries. Cleanup that has not joined reserves activation rather than reporting a clean disconnect.
- Revocable Dart operation/status/reconnect epochs, owned probe-client closure, and fenced disposed/obsolete success/error/finally notifications. Identical native recovery polls cannot renew the same lease; stages/round count are bounded.
- Android monotonic budgets, permission/activity destruction cancellation, CAS-delivered callbacks, deadline/epoch rechecks for posted success and notifications. Phase JNI work stays off UI. Tile refresh change is only its posted publication guard.
- Java child budgets inherit parent revocation, but canceling one failed child does NOT revoke automatic fallback's parent round. A confirmed shared-token negative control demonstrates the previous failure.
- Native recovery is at most three 30-second rounds with 5/15-second cooldowns; selected transport is first, automatic switches only after failure, strict never switches. Winning sessions outlive establishment leases. Terminal IO revokes active evidence, preserves caller sink/FD ownership, and joins accepted IO before releasing reservation.
- Failed-carrier retirement consumes the first recovery lease. Old canceled retirement observers are fenced to exact session/done channel/recovery ID in the same critical section that marks stop; an invalid observer does not consume `stopOnce`.
- H3 CONNECT cancellation closes actual owned QUIC/transport/packet resources, not only the retained request context. Setup watch detaches only after successful authentication; lifetime watch remains.
- Desktop admission/cleanup are deadline-bounded; timed-out cleanup retains the original runtime mutex until joined. Credential/helper/auth waiting consumes serialized remaining durations; queued activation is generation-fenced. Late DNS results cannot add routes after revocation. Status preserves the actually recovered transport.

## Final observed checks

All executable checks ran in `/srv/archives/agent-fallback-finish-20261105` on Debian using existing cached dependencies only. Go environment: `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2`, with `TMPDIR`, `GOCACHE`, `GOMODCACHE` in that independent snapshot. Flutter used that snapshot's `PUB_CACHE`, `CI=true`, and suppressed analytics.

| Check | Result | Evidence |
|---|---|---|
| Exact original Flutter 19 + new budget/lifecycle 9 | **28 PASS**, exit 0 after final brace-only fixes | [post-style test log](<work/report/fallback-budget-20261105/flutter-final-poststyle28.log>) |
| Scoped Flutter analyzer (5 items) | **No issues**, exit 0 | [clean analyzer log](<work/report/fallback-budget-20261105/flutter-analyze-clean.log>) |
| Pure Java budget/callback/fallback helper | **PASS**, javac 0 / java 0 | [final Java log](<work/report/fallback-budget-20261105/java-budget-final-v3.log>) |
| Pure Go carrier / mobile recovery / desktop selection | **3 + 15 + 13 = 31 PASS**, exit 0 | [frozen Go log](<work/report/fallback-budget-20261105/go-final-frozen.log>) |
| Delayed old-retirement observer regression | **10 consecutive PASS**, exit 0 | [repeat log](<work/report/fallback-budget-20261105/go-epoch-repeat10.log>) |
| Linux desktop command compile-only | exit 0, no selected tests | [command compile log](<work/report/fallback-budget-20261105/go-desktop-command-final.log>) |
| Windows amd64 desktop test cross-compile | exit 0; binary NOT executed or installed | [Windows compile/hash log](<work/report/fallback-budget-20261105/go-windows-final.log>) |

Commands (executed from the snapshot's app / protocol module as applicable):

```sh
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s \
 test/status_lifecycle_test.dart test/status_poll_idle_test.dart \
 test/background_polling_test.dart test/watchdog_interval_test.dart \
 test/connection_users_test.dart test/fallback_budget_test.dart
/opt/flutter/bin/flutter analyze --no-pub lib/core.dart lib/connection_attempt.dart \
 lib/desktop_engine.dart test/fallback_budget_test.dart test/status_lifecycle_test.dart
javac -d "$base/java-classes" "$base/ConnectionBudget.java" "$base/ConnectionBudgetTest.java"
java -cp "$base/java-classes" app.xio.xio.ConnectionBudgetTest
/opt/go1.27.3/bin/go test -p 1 -count=1 -v -timeout 30s \
 -run '^(TestSourceNoNetwork|TestRecovery|TestDesktopPolicy|TestAWGPeerKeySinglePeerOnly|TestPrepareEndpointsKeepsEveryCandidate|TestAWGPendingDisconnectCancelsBeforeRuntimeLock|TestAWGActivationMissingCandidatesFailsClosed|TestPacketAdapterKeepsBatchesAndVirtioHeadroom)' \
 ./internal/rivet ./mobile ./internal/desktop
/opt/go1.27.3/bin/go test -p 1 -count=10 -v -timeout 30s \
 -run '^TestRecoveryOldRetirementObserver' ./mobile
/opt/go1.27.3/bin/go test -p 1 -count=1 -run '^$' -timeout 30s ./cmd/xio-desktop
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 /opt/go1.27.3/bin/go test -p 1 -c \
 -o "$base/evidence/desktop-policy-windows-final.test.exe" ./internal/desktop
```

## Honest negative controls and prior failures

- Original lifetime/terminal-IO negative controls: four intended regression failures, test exit 1, source restored; [log](<work/report/fallback-budget-20261105/go-negative-control.log>), [script](<work/report/fallback-budget-20261105/go-negative-control.sh>).
- Removing retirement-identity checks makes the old canceled observer kill newer recovery ID 2: intended test exit 1; [log](<work/report/fallback-budget-20261105/go-epoch-negative.log>).
- Restoring the shared Java child/root cancel token compiles (exit 0) but automatic fallback fails with CleanupIncomplete/Expired (java exit 1); [log](<work/report/fallback-budget-20261105/java-child-negative.log>).
- Both latest controls restore their source via EXIT trap; final positive Go/Java checks ran afterward. [Control script](<work/report/fallback-budget-20261105/epoch-java-negative-controls.sh>).
- Earlier test invocation included two nonexistent test paths and exited 1; corrected exact selection passed. Earlier analyzer invocations exited 1 for style INFOs, not test failures; [first analyzer](<work/report/fallback-budget-20261105/flutter-analyze-first.log>) and [format-induced analyzer](<work/report/fallback-budget-20261105/flutter-analyze-second.log>). Unrelated whole-file formatting was removed, then only the scoped brace diagnostics were fixed. Final clean analyzer and 28-test rerun are recorded above.

## Independent review and remaining acceptance gates

Parent relayed that reviewer H's unchanged localhost H3 setup/lifetime/deadline fixture passed on exact `a01a052`, and the S1 winner survived setup cancellation. This implementer did not run real-transport integration. H subsequently confirmed a delayed-retirement-observer P2 on that commit; `435de09` fixes it with the regression and negative control above. Independent recheck of the exact final epoch fix remains the reviewer's acceptance, not this self-report.

**Not done / not claimed:**
- Native AAR/JNI/helper assets rebuilt or packaged; APK/full Kotlin integration/type compilation against new JNI exports; physical Android permission/airplane/recovery/battery acceptance.
- Packaged Ubuntu/Windows privileged helper, UAC, real routes, devices, native network interfaces or actual 30-second physical behavior. Windows test binary was cross-compiled only; WDAC/SAC was not bypassed.
- Apple implementation/build/testing (explicitly deferred).
- Visible Auto/selected-only UI and persistent user-preference design. The existing typed public runtime policy and captured strict Android native plan are ready; parent owns that separate UX/settings work before claiming manual UX complete. No profile/managed/DNS/cascade schema or ConfigVault synchronization changes were introduced.
- No full protocol suite, broad real transport integration, race detector, signing or release acceptance is implied by these focused tests.

Generated tar archives and inherited application helper scripts remain untracked and untouched, not staged as deliverables. No cleanup/deletion of valuable inherited work was performed.
