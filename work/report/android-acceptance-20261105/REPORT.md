# Android final-APK acceptance harness preparation

## Scope / delivery

- Inherited GPT-6.1 Sol runtime retained, no model switch.
- New worktree `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-android-acceptance-20261105` and branch `agent/android-acceptance-20261105`, created only after confirming the path/branch did not exist.
- Base `a751864a38fe755018b716f6b42e6964fcac890b`.
- New [harness](../../../tools/acceptance/android_acceptance.py), [mocked tests](../../../tools/acceptance/test_android_acceptance.py), [operator runbook](../../../tools/acceptance/README.android.md), and this scoped report/evidence only. No shared Dart, native source, assets, builder/deploy scripts or parent/sibling worktree edits.

**Final real-device Android acceptance remains PENDING.** No final signed APK pins were supplied for this preparation task. Test versionCode/digests are synthetic fixtures, not release identity claims. No source revision is inferred from an installed APK.

## Implemented boundaries

1. **Exact identity gate:** explicit Full/Client package, versionCode, final signed artifact SHA256 and trusted certificate SHA256. Verify local bytes/package/version/signature, explicit device serial/user 0, installed package/UID isolation, then pull only the installed base APK and independently verify the same byte digest/package/version/cryptographic signer. Splits, shared UIDs, remote path traversal, missing/ambiguous metadata and mismatches reject before device mutation. No trust-on-first-use pins from the installed experimental5019 APK. The known `33c911...` prefix is insufficient and invalid as a digest.
2. **COLLECT-ONLY default:** app-only, multi-process PSS KiB extraction/sum and bounded PID+exclusive-UID-scoped native log reads; no app process means explicit absence, not app launch. Unknown memory output fails rather than falsely reporting zero. Strict full-message allowlists emit only event/protocol enums and timestamps. Raw logs/metadata, private sentinel strings, SSID/BSSID/IPs, profiles, credentials and keys are not stored; the device identifier is hashed. Both initial and final installed-APK gates are required.
3. **Opt-in observations:** `--exercise` plus interactive consent, exact identity rechecks after consent and before each action, then manual disconnect/connect/fallback markers. Host-monotonic timing includes the operator action/confirmation; exactly 30 seconds is in-budget, >30 rejects, and prompts time out. App PSS/native events are sampled at boundaries. These are explicitly `operator_only_not_network_validation`; they never produce a VPN PASS.
4. **Restoration:** radio methods are disarmed by default. Only after opt-in, successful gate and persisted recovery journal are radio controls armed. An additional `--airplane-cycle` flag permits a three-second airplane cycle (refused if already on); actual airplane readback is checked. Prior airplane/WiFi bits and sanitized WiFi enabled/associated booleans are restored/read back before operator prompts and in `finally` after failures/timeouts/interrupts. Both controls get independent attempts/retries; failed restoration rejects and preserves recovery evidence. The armed capability is cleared even if restoration fails. Already-correct states are not gratuitously rewritten. Other device/app settings are never changed.
5. **Screenshot boundary:** no screencap, UI dump, screenshot permission/privacy-setting change, app focus or input-injection capability exists. A foreground check cannot exclude private overlays. Separately authorized, reviewed app-only screenshots belong to the parent after final APK identity is established, not to an automatic capture of the current screen.

The [native manifest](../../../app/android/app/src/main/AndroidManifest.xml#L98-L105) exposes no shell-callable disconnect/status service. The [native controller](../../../app/android/app/src/main/kotlin/app/xio/xio/VpnControlService.kt#L20-L54) and [activity](../../../app/android/app/src/main/kotlin/app/xio/xio/MainActivity.kt#L447-L462) were inspected to avoid inventing an unsupported debug API or changing native code. The harness deliberately uses manual observations rather than claiming it can independently validate VPN state through an absent API.

## Commands / results

Run on this Windows worktree with existing bundled **Python 3.12.14**, standard library only:

```powershell
$python = 'C:\Users\er-ka\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe'
& $python --version
& $python -m unittest discover -s tools/acceptance -p 'test_android_acceptance.py' -v
& $python tools/acceptance/android_acceptance.py --help
& $python -m py_compile tools/acceptance/android_acceptance.py tools/acceptance/test_android_acceptance.py
git diff --check
```

- Unit tests: **28/28 PASS**, exit 0; [mock test log](mock-tests.log). All adb/SDK/device replies are mocks. The tests execute no real adb command, installation, radio toggle, app focus or capture.
- CLI help: exit 0; [help log](cli-help.log). Committed log copies normalize Windows line endings to LF only.
- `py_compile`: exit 0.
- `git diff --check`: exit 0; staged whitespace validation also required before commit.
- Generated Python bytecode caches were excluded from the deliverable and removed only after verifying their exact owned absolute path.
- No dependency installation, Debian use, heavy build, system-policy change, publication, main merge or release operation.

Coverage includes good Full/Client identities; stale local/installed bytes; wrong package/version/cert/serial; absent/split packages; shared UID; path traversal; unsigned/multi-signer output; private log/SSID redaction; app process/PSS scoping; absent/unknown memory; default collect-only/disarmed controls; missing opt-in; stale APK after consent; exactly-30 and >30-second observations; airplane readback/restoration ordering; failures after mutation; observer/timeout/KeyboardInterrupt recovery; prior radio preservation; and retained recovery journal on persistent restoration failure.

## Gaps / next parent actions

- **No real phone metadata, APK tool verification, app exercise, logcat, PSS, network change or screenshot was collected now.** No real VPN/fallback/latency/memory result is claimed from mocks.
- Parent must provide trusted exact final signed Full/Client APK pins, install the intended final artifact separately under its authorization, and run the read-only gate first. The current experimental installation must not be silently accepted or used to infer final source identity.
- Native Android command/output compatibility is deliberately fail-closed and still needs real final-device verification. Unsupported WiFi/adb/aapt/apksigner output is a rejection, not an excuse to bypass gates.
- Manual/UI confirmation and allowlisted native events do not independently prove secure traffic, fallback correctness, DNS/IPv6 leak freedom or throughput. Boundary PSS samples do not claim a continuous peak-memory profile. Bounded log tails can omit events.
- Restoration verifies prior setting bits and WiFi enabled/associated booleans, not exact SSID/BSSID, cellular registration, Internet reachability or VPN state. Operator must not edit app/network selection settings during an exercise. Those are not owned/read by this tool.
- Physical restoration cannot be guaranteed after USB loss, host power failure, forcible termination or an uncooperative OS. Normal/error/timeout/handled-interrupt control flow always attempts restoration; a failed/unconfirmed restore must remain failed/PENDING and be recovered from the saved journal before proceeding. The runbook includes recovery commands.
- App-only screenshots require separate safe-screen authorization/review; no current/private/unrelated screen was captured.
