# Runtime P2: stale native status / watchdog ownership

## Scope and reproduced defect

- Branch `agent/runtime-p2-20261105`, base `a751864a38fe755018b716f6b42e6964fcac890b`; isolated worktree `work/agent-runtime-p2-20261105`. Inherited GPT-6.1 Sol retained.
- Production change is **only** the coordinated lifecycle regions of [core.dart](../../../app/lib/core.dart#L740-L744), plus the new [status lifecycle regression](../../../app/test/status_lifecycle_test.dart). No persistence, profiles, cascade, UI, managed services/models, native binaries, DNS, deployment or server source edits.
- A pending native status read could complete after disconnect and republish the old tunnel's active status/active profile. An old failure could replace the completed teardown state with “unknown”. Reads started *during* teardown had the same problem.
- Disposing canceled the timer but did not fence its in-flight read: an **identical** late status could re-arm the periodic watchdog without notifying; a changed status/error could notify a disposed controller. Baseline fake-clock evidence shows native status reads increasing from 2 to 3 after disposal.
- Before production edits, the initial nine-case regression produced **1 pass / 8 failures**, including wrong active profile (`awg1` instead of `awg2`), used-after-dispose errors, stale teardown state and timer resurrection. [Baseline evidence](baseline-regression.log).

## Bounded fix

1. An in-memory epoch is advanced at admitted [connect](../../../app/lib/core.dart#L2056-L2090), [disconnect entry and completion](../../../app/lib/core.dart#L2176-L2208), and [dispose](../../../app/lib/core.dart#L2393-L2406). The completion increment also invalidates polls admitted while teardown was pending, including failed teardown.
2. [Status reads](../../../app/lib/core.dart#L2212-L2257) capture the epoch and reject stale success **and** stale errors. Their `finally` only synchronizes watchdog / notifies if still current and alive. Disposed reads, including queued `fresh` reads, never call the native channel.
3. Disconnect now cancels/reset its own watchdog immediately: discarding an old poll must not leave timer cleanup dependent on that poll's `finally`.
4. Dispose revokes desired-connection ownership before canceling timers; new connect/disconnect requests against the disposed store return without native calls. This does not cancel every other already-running operation (see gaps).

This is a stale-publication/resource-ownership fix, not a replacement connection state machine or a native Internet-readiness claim.

## Deterministic coverage

The final regression contains **11 cases**: late success/failure after completed disconnect; success/failure from reads admitted during teardown; late success/failure and queued fresh reads after dispose; stale status during a new activation versus current fresh verification; equal-status disposal/watchdog resurrection after 20 fake seconds; explicit disconnect/watchdog ownership after 30 fake seconds and timer invariants; failed native teardown; current success/error and unchanged-status notification dedup.

All native responses are fake MethodChannel replies controlled by completers. Timer advances use Flutter's fake clock. The test store overrides persistence, split sync and tunnel verification; its successful verifier is **a fixture only**, not network evidence. No endpoint is resolved, socket dialed, VPN activated or phone accessed by these new tests. The existing focused tests additionally retain status coalescing, background UI polling, cadence, stalled fake-probe fallback, and UI coverage.

## Commands and results

Canonical Debian snapshot: `/srv/archives/agent-runtime-p2-20261105`; Flutter `/opt/flutter`, Flutter **3.47.7**, Dart **3.13.5**. App sources came from `git archive HEAD app` at the stated base, then only the two scoped source files were overlaid. `TMPDIR` was placed inside the snapshot on `/srv/archives` (root had only 5.8 GiB available). No heavy/final builds.

Executed phase scripts: [initial baseline](run-baseline.sh) (before source edits), [negative controls with guaranteed restoration](run-negative.sh), [final focused checks](run-fixed.sh). All outer scripts exited 0; expected failing child exits are recorded explicitly.

```bash
/opt/flutter/bin/flutter pub get --offline
/opt/flutter/bin/dart format test/status_lifecycle_test.dart
/opt/flutter/bin/flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s \
  test/status_lifecycle_test.dart test/status_poll_idle_test.dart \
  test/background_polling_test.dart test/watchdog_interval_test.dart \
  test/connection_users_test.dart
/opt/flutter/bin/dart analyze lib/core.dart test/status_lifecycle_test.dart
```

| Check | Result | Evidence |
|---|---|---|
| Initial baseline before production edits, initial 9 cases | exit 1 expected; 1 pass / 8 fail | [baseline](baseline-regression.log), [exit](baseline-result.log) |
| Epoch-removal negative control, final 11 cases | exit 1 expected; 4 pass / 7 fail | [mutation](negative-epoch.log), [exit](negative-epoch-result.log) |
| Remove only explicit disconnect watchdog cancellation | exit 1 expected; selected test fails on pending periodic timer | [mutation](negative-watchdog.log), [exit](negative-watchdog-result.log) |
| Restore exact corrected source | exit 0; 11/11 pass; `cmp` confirms restoration | [restored](restored-regression.log) |
| Final focused suite (5 files) | exit 0; **19/19 pass** | [focused](focused-tests.log) |
| Targeted analysis | exit 0; no issues | [analysis](analyze.log) |
| New regression formatting | exit 0 | [format](format-final.log) |
| Offline dependencies / SDK | exit 0 | [dependencies](pub-get.log), [versions](flutter-version.log) |

One development-only focused run initially failed because widget-test timer invariants run **before** `addTearDown`: the positive live-connect fixture needed explicit disposal inside the body. The fixture was corrected, not production behavior relaxed; [initial cleanup-order failure](focused-initial-test-cleanup.log) is retained. A separate disconnect test intentionally relies on this invariant to prove teardown itself cancels its timer. Subsequent 18/18 and final 19/19 runs passed. Logs are preserved with LF/trailing-whitespace normalization only.

The final Windows source bytes match the tested Debian bytes:

```text
f52f31f851b39ea441ab6e45c5d5f61feeca60ce4be0d1a69609bd784a718b23  app/lib/core.dart
3c6c8e95db6eb39bad1de85e86cd8606c34f808b6456bf00800fb3c386886964  app/test/status_lifecycle_test.dart
```

`git diff --check` passed. The temporary 180 MB local transfer archive was removed only after inspecting its exact owned absolute path; it is not committed. The remote isolated snapshot is retained for review.

## Source gaps / not acceptance

- **Global automatic fallback <=30 seconds remains unimplemented/unproven.** Foreground [connect](../../../app/lib/core.dart#L2095-L2168) grants each candidate `protocolTimeoutSeconds`, subtracting native-reported `connectMillis` only within that attempt; no single global deadline surrounds all candidates. Channel invocations and some surrounding work are not bounded by that Dart budget. Android [tile controller](../../../app/android/app/src/main/kotlin/app/xio/xio/VpnControlService.kt#L30-L46) likewise loops up to 16 candidates with a per-candidate 5–60 second setting. The fake 20/30-second lifecycle advances above are **not** fallback-deadline proof.
- **Explicit manual-only protocol policy is not this base's legacy preference setting.** [Candidate planning](../../../app/lib/core.dart#L1301-L1350) always adds same-endpoint variants then other profiles; [settings UI](../../../app/lib/workspace_ui.dart#L913-L927) says “priority protocol”, not “only this protocol”. A future manual mode must explicitly filter the plan and background behavior; existing preference alone must not be relabeled as that promise.
- **Native reconnect policy also needs manual intent.** Canonical [Rivet monitor](../../../protocol/rivet/mobile/mobile.go#L165-L203) alternates H3/S1 on even reconnect attempts (including attempt zero) and retries without a total deadline. Dart filtering alone cannot enforce manual-only native reconnect. This is source inspection, not signed-APK/binary provenance or a reproduced real fallback result. No native policy was changed here.
- Inspected native teardown/cancellation paths: [Rivet stop](../../../protocol/rivet/mobile/mobile.go#L206-L230), [packet flow](../../../protocol/rivet/mobile/packetflow.go), [Xray wrapper](../../../protocol/rivet/mobile/xray.go), [AWG registry](../../../protocol/rivet/mobile/awg_registry.go#L87-L173), [heap reclaim](../../../protocol/rivet/mobile/reclaim.go) and its [existing tests](../../../protocol/rivet/mobile/reclaim_test.go). No additional native leak was deterministically reproduced; no Go/TUN/heap plateau test was run. This patch proves timer ownership, **not** Android PSS/continuous peak/native heap stability.
- The epoch fences **status publication**, not every outstanding future: already-running activation, save, verification or DNS/watchdog continuation cancellation still needs separate coverage/ownership. An indefinitely hung native status call is not canceled; coalesced/fresh readers can still wait on it. Disconnect still returns while `busy` (existing semantics), so this is not an activation-cancel feature.
- No real phone/airplane/network configuration/VPN/VPS actions, Windows unsigned client execution, system/SAC policy changes, release build/signing, publication or main merges occurred. LAN SSH/SCP and offline standard Linux Flutter checks only. No IPv4/IPv6 profile-family, native-readiness, AWG binary-pin or managed-helper changes.
- Interface-up, fixture handshakes and mock verifier results do **not** establish a working secure Internet path, fallback correctness, leak freedom, restoration or throughput. Actual final signed Full/Client APK memory/flight/fallback acceptance remains **PENDING**, owned by the parent.
