# C5 — background website verification respects typed opt-in

**Follow-up:** the original `8021435` candidate below had a nonpositive-handshake boundary defect. The [sentinel-positivity follow-up](<work/report/background-probe-fix-20261106/sentinel-followup/REPORT.md>) and its hash manifest supersede the helper/test bytes and test counts below. Parent must independently replay that new commit; this original report is retained as history, not acceptance.

Base: `c3d9a594ecce4921a88d73e3b453ebaa6b1e0d73`; exclusive branch `agent/background-probe-fix-20261106`. **Candidate for independent parent/H review, not self-accepted. Do not merge this branch alone.** Its base contains N work explicitly UNACCEPTED when assigned; parent must first accept/merge N's final ownership/cancellation follow-up, then preserve both changes. No N follow-up was cherry-picked/rebased here. N also edits controller attempt ownership/cleanup; parent must retain its exact-child cleanup when combining the adjacent hunks.

## Implementation and upgrade contract

- [Actual saveNativePlan serialization:1399–1416](<app/lib/core.dart#L1399-L1416>) now sends `siteCheckEnabled` as a JSON boolean. The only additional seam is optional `androidForTesting`; omitted production calls retain `Platform.isAndroid`. No DNS/routing/settings/other core sections changed.
- [Strict native options:16–18](<app/android/app/src/main/java/app/xio/xio/BackgroundVerificationOptions.java#L16-L18>) enables website HTTP **only** for `Boolean.TRUE`. Missing/null/non-boolean values, including string `"true"`, are privacy-conservative false; no `JSONObject.optBoolean` coercion.
- [Actual controller reader/call:53–76](<app/android/app/src/main/kotlin/app/xio/xio/VpnControlService.kt#L53-L76>) uses those options after existing consent admission and after native connect. False never evaluates the website URL or invokes the injected combined website probe. It still polls the existing native handshake with the same `started - 2000` freshness tolerance and SAME attempt deadline, with cancellation/deadline checks before/after reads/waits and before accepting success ([helper:21–39](<app/android/app/src/main/java/app/xio/xio/BackgroundVerificationOptions.java#L21-L39>)). Missing handshake expires/fails, not success.
- True keeps the existing HTTPS URI validation and calls the **unchanged** combined [ConnectionProbe](<app/android/app/src/main/kotlin/app/xio/xio/ConnectionProbe.kt>) once per verification attempt. Its redirects/HTTPS failure/fresh-handshake semantics remain intact. Only the existing attempt remainder is passed; no new timeout, lease, budget renewal, fallback mode, cleanup or lifecycle policy was introduced.
- Native VPN authentication/handshake/keepalive and endpoint resolution are not website HTTP consent. Opt-out does not mean zero VPN protocol traffic, nor does a native handshake prove Internet/HTTPS reachability. No external reachability/device claim is made.
- **Upgrade:** an old saved native plan has no flag, even if the separate app setting was true. The new controller treats that plan as website-off until opening/refreshing the app re-saves a typed flag. The old runtime did not know this flag and is not retroactively claimed fixed. No implicit true migration or settings-UI change.

Production changes are confined to the linked serialization method, native controller website-conditional wiring, and the new pure helper. [MainActivity](<app/android/app/src/main/kotlin/app/xio/xio/MainActivity.kt>), [ConnectionBudget](<app/android/app/src/main/java/app/xio/xio/ConnectionBudget.java>), [ConnectionProbe](<app/android/app/src/main/kotlin/app/xio/xio/ConnectionProbe.kt>), Engine/lifecycle/routing/fallback/DNS/native-Go/desktop implementation are unchanged. Exact local source hashes are in [manifest](<work/report/background-probe-fix-20261106/source-sha256.txt>); uploaded Linux source bytes match [remote manifest](<work/report/background-probe-fix-20261106/remote-source-sha256.txt>).

## Tests: baseline qualification and fixed results

| Check | Result / evidence |
|---|---|
| Exact-c3 native controller source wiring | RED: 2 failures, 1 pass; unconditional probe/no strict options. [Baseline wiring log](<work/report/background-probe-fix-20261106/baseline-wiring.log>). This is source-level, not Android runtime reproduction. |
| Qualified Linux actual Dart method/channel baseline | RED: 2 failures (`null` not boolean for false/true), 1 pass (platform gate). [Full baseline log](<work/report/background-probe-fix-20261106/baseline-dart-linux.log>). Baseline is **c3 + ONLY the test platform seam**, not byte-exact c3; see [seam patch](<work/report/background-probe-fix-20261106/baseline-test-seam.patch>) and [baseline hashes](<work/report/background-probe-fix-20261106/baseline-hashes.txt>). The test implementation is not mocked; only the platform channel is intercepted. |
| Fixed Dart channel payload + original fallback-budget suite | GREEN: 12 tests (3 new payload/platform tests + 9 original budget tests), exit0. [Full log](<work/report/background-probe-fix-20261106/fixed-dart-linux.log>). |
| Original injected opt-in foreground website failure/fallback regression | GREEN: 1 test, exit0; late first result cannot replace successful fallback. [Log](<work/report/background-probe-fix-20261106/original-site-probe-linux.log>). |
| Pure production Java helper | GREEN: 29 deterministic checks, exit0; [test](<app/android/app/src/test/java/app/xio/xio/BackgroundVerificationOptionsTest.java>) / [log](<work/report/background-probe-fix-20261106/fixed-jvm.log>). |
| Original ConnectionBudget JVM test | GREEN, exit0, same [log](<work/report/background-probe-fix-20261106/fixed-jvm.log>). |
| Actual controller entrypoint wiring | GREEN: 3/3; [test](<tools/test_background_probe_wiring.py>) / [log](<work/report/background-probe-fix-20261106/fixed-wiring.log>). Verifies tile and restore enter this controller, strict reader, existing consent ordering, actual gate after native connect, and remaining-budget fence. Not just an unused helper test. |
| Cached Kotlin2.2.21 + API36/JVM17 compile | GREEN, exit0: actual changed controller + unchanged combined probe + production Java helper; [log](<work/report/background-probe-fix-20261106/api36-compile.log>). Unchanged Android collaborators are compile-only signatures ([fixture](<work/report/background-probe-fix-20261106/CompileOnlyAndroidCollaborators.kt>)); this is NOT full app linkage or Android runtime execution. [Replay script](<work/report/background-probe-fix-20261106/compile-api36.ps1>). |
| Scoped Linux Dart analyzer | GREEN, exit0: no issues in actual touched source/new test. [Log](<work/report/background-probe-fix-20261106/scoped-analyze-linux.log>). |
| Scoped formatter | New test is formatted; changed saveNativePlan region is formatter-identical, exit0 ([scoped log](<work/report/background-probe-fix-20261106/scoped-method-format.log>)). Whole-core check exits1 on **pre-existing out-of-scope** formatting ([diff](<work/report/background-probe-fix-20261106/core-format-existing.diff>)); deliberately not reformatted to avoid DNS/routing/other-owner changes. |

The helper checks cover missing/false/string-true/string-false/number/object inputs; opt-out zero probe calls even when the injected probe would throw; delayed/absent native handshake; cancelled root/child before HTTP, cancellation while waiting or reading, cancellation/expiry after opt-in probe; true one combined probe, exact error propagation, unchanged remaining budget and existing candidate fallback. All clocks/probes/handshake waits are injected: no real sockets or sleeping in this JVM test. Native JSON integration is source/compile-checked at `JSONObject.opt`; raw-value parsing is executed in the JVM helper test, not claimed as a device JSON-runtime test.

The [Dart regression:13–65](<app/test/background_probe_plan_test.dart#L13-L65>) calls the real method and captures `saveConnectionPlan` arguments for false/true, asserting boolean type plus unchanged site/IDs/timeout/policy/round fields, and tests an explicit false host-platform gate without replacing the serializer; the omitted production platform default is unchanged in source.

## Environment stops and limits retained honestly

1. Windows Flutter test attempt stopped **before tests** because SAC/WDAC blocked `impellerc.exe` ([log](<work/report/background-probe-fix-20261106/baseline-dart.log>)). This is an ENVIRONMENT STOP, not functional baseline RED.
2. Windows scoped analyzer similarly stopped **before analysis** on blocked `dartaotruntime.exe` ([log](<work/report/background-probe-fix-20261106/scoped-analyze.log>)). No retry, executable rename/unblock/allowlist, security-policy change or bypass was attempted. Linux analysis is separate platform validation, not Windows acceptance.
3. Debian existing SDK/cache were copied read-only from the established installation into ONLY `/srv/archives/agent-background-probe-fix-20261106`; all HOME/PUB_CACHE/TMP/build writes were owned there. Initial copied-SDK Git ownership check stopped startup with128 ([log](<work/report/background-probe-fix-20261106/linux-offline-dependencies.log>)); only the owned copy's ownership was normalized, with no global Git exception or shared SDK/cache edits. Retry resolved dependencies with `--offline` ([log](<work/report/background-probe-fix-20261106/linux-offline-dependencies-retry.log>)); later tests use `--no-pub`.
4. No APK build/install, phone/ADB action, live VPN, external HTTP/DNS/website probe, OS route/network/policy mutation, server action, release artifact regeneration or SAC bypass. Authorized LAN SSH/SCP was used only for the owned offline test workspace. No full suite, packet capture, Android consent/revoke/restore runtime or shipped-binary linkage acceptance is claimed.

## Replay commands

Run under the corresponding owned source/cache locations; do not use another worker's active cache. Relevant Linux commands actually used:

```sh
export HOME="$OWN/cache/home" PUB_CACHE="$OWN/cache/pub" TMPDIR="$OWN/tmp" CI=true
export FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
"$OWN/cache/flutter/bin/flutter" --suppress-analytics pub get --offline
"$OWN/cache/flutter/bin/flutter" --suppress-analytics test --no-pub \
  test/background_probe_plan_test.dart test/fallback_budget_test.dart --reporter expanded
"$OWN/cache/flutter/bin/flutter" --suppress-analytics test --no-pub \
  test/connection_users_test.dart --plain-name 'stalled probe falls back' --reporter expanded
"$OWN/cache/flutter/bin/cache/dart-sdk/bin/dart" analyze \
  lib/core.dart test/background_probe_plan_test.dart
```

Pure JVM checks use existing JDK21 `javac --release 17`, compiling the production budget/options plus both test mains into the owned output, then run `app.xio.xio.BackgroundVerificationOptionsTest` and `app.xio.xio.ConnectionBudgetTest`. Production wiring test uses `python3 -B tools/test_background_probe_wiring.py` (WSL Python in this run). Scoped source/test/report whitespace checks passed. An all-staged-files whitespace check exits2 on raw Windows CRLF/tool output blank-line spaces and patch context; those evidence bytes are retained rather than rewritten. Large archive/cache/class outputs are local evidence only, not staged release artifacts. Containing commit ID and SHA256 manifest accompany the parent handoff; independent acceptance remains with parent/H.
