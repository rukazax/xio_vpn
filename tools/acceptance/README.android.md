# Final-APK Android acceptance evidence (Full / Client)

[Harness](android_acceptance.py) · [mocked tests](test_android_acceptance.py)

**Default: COLLECT-ONLY. Final Android VPN acceptance always remains PENDING.**
This is an identity/evidence harness, not an installer, a profile importer or an
independent network-traffic validator. No phone action has been executed as part
of the mocked harness tests.

## 1. Pin the actual final signed release first

Python 3.10+ and existing Android SDK `adb`, `aapt` and `apksigner` are required.
No platform tools, packages or permissions are installed by this tool.

For EACH final Full/Client APK, the parent/release owner supplies:

- Full package `app.xio.xio` or Client package `app.xio.client`;
- exact integer versionCode;
- SHA256 of the exact **final signed artifact** from the release evidence;
- signing-certificate SHA256 from the independently trusted release signer;
- explicit authorized device serial (default USB POCO `909f194a`).

Never learn an acceptance pin from the currently installed APK. Never change pins
to make an old installation pass. In particular, an experimental build with the
same versionCode is NOT equivalent: the full byte SHA256 must match. The known
experimental5019 Full digest prefix `33c911...` is not a final artifact pin and is
not accepted as a digest. No source revision is inferred from installed bytes.

The gate hashes the local APK, checks `aapt` package/version and verifies its
single signer with `apksigner`. It then targets only the explicit serial/user 0,
checks installed package version and exclusive app UID, resolves the package APK,
pulls **only that APK** to temporary local storage, and repeats SHA/package/version/
cryptographic signer verification. Splits, ambiguous UIDs/metadata, missing tools,
unknown formats, unavailable devices and any mismatch fail closed. Temporary APK
copies are removed. No application-data files are accessed.

## 2. Default read-only collection

Example PowerShell template; replace every release pin/path with the parent's
final signed release evidence. This does NOT install or launch the app:

```powershell
python tools/acceptance/android_acceptance.py `
  --apk 'FINAL_SIGNED_FULL.apk' --package app.xio.xio `
  --version-code FINAL_INTEGER_VERSION_CODE `
  --apk-sha256 FINAL_64_LOWERCASE_HEX_APK_DIGEST `
  --cert-sha256 TRUSTED_64_LOWERCASE_HEX_CERT_DIGEST `
  --serial 909f194a `
  --adb 'C:\Users\er-ka\.dsh\bin\platform-tools\adb.exe' `
  --aapt 'EXISTING_SDK_BUILD_TOOLS\aapt.exe' `
  --apksigner 'EXISTING_SDK_BUILD_TOOLS\apksigner.bat' `
  --out 'NEW_FULL_ACCEPTANCE_EVIDENCE_DIRECTORY'
```

Run Client separately with its exact APK pins, `--package app.xio.client`, and a
separate new output directory. Reusing/overwriting an output directory is refused.

Collection samples only `dumpsys meminfo <selected package>` (default three samples,
one-second spacing). It extracts each selected-package process PID and PSS KiB,
and reports their sum, **not system RAM**. This is boundary sampling, not continuous
peak-memory profiling. If the app is not running it records that explicitly and
never launches it. Unknown PSS formats fail rather than claiming zero usage.

Native logs are read without clearing: `logcat -d`, constrained by BOTH the gated
exclusive app UID and each app PID, explicit native tags, bounded tail, and the
collection-start device timestamp. A second strict parser retains only fixed
native event codes and protocol-prefix enums; arbitrary messages, Flutter logs,
URLs, identifiers, IPs, SSIDs, keys and profile contents are discarded. Duplicate
native events are suppressed. Raw command output is never written to evidence.
The device identifier is hashed, not recorded in plaintext. Native event timestamps
are device epoch; observation durations use host monotonic time. Do not compare
those two clock domains for a 30-second verdict.

A final installed-APK gate runs again before successful collection completion.
Default collection contains **no** install/uninstall, network/radio command,
app launch/focus, input injection, clear-data, log clearing, UI dump, screencap,
settings write, profile read, shell root or system-policy change.

## 3. Explicit operator-observed runtime exercises

Only the parent should run this after installing/verifying the final signed APK
outside this harness, with an already authorized test profile/environment. Use
`--exercise` as an additional flag. There is also a required interactive `EXERCISE`
confirmation; noninteractive/EOF input fails. The tool never changes profiles,
selects a different network, blocks a server, edits app settings, clicks UI or
requests broad permissions.

The gate runs again after consent and before arming any restoration/network
commands; it also runs before each manual action. For disconnect, connect and
fallback in order:

1. Prepare only the already authorized case, then enter `READY` without acting.
2. The harness creates the monotonic start marker; manually perform that action
   in XIO, confirm its resulting UI state, then type `OBSERVED` within 30 seconds.
3. It records the observed duration, boolean `within_30s`, and the explicit label
   `operator_only_not_network_validation`. Exactly 30 seconds is in-budget;
   anything greater is rejected. Input has a 30-second timeout.
4. App-only PSS and allowlisted native logs are sampled at action boundaries.

Use an already approved fallback setup; this tool does not create an unavailable
primary or manipulate server/network policy. Missing native verification or an
unsupported foreground path is NOT automatically treated as success. UI/manual
observations, a service being active, or a route-ready event alone do not prove
secure VPN traffic, fallback correctness, DNS/IPv6 leak freedom or throughput.
The parent must supply those independent real-device checks. Successful evidence
collection still leaves `runtime_acceptance: PENDING`.

### Optional airplane exercise and restoration

Only `--exercise --airplane-cycle` AND interactive confirmation authorize the
scripted radio cycle. `--airplane-cycle` alone is rejected before device access.
The cycle is refused if airplane mode is already on, since no new transition
would be tested. Airplane mode does not necessarily disable WiFi on Android;
this is NOT automatically a demonstrated full network outage or fallback test.

Before mutation, the tool requires stable 0/1 airplane/WiFi settings plus a parsed
WiFi enabled/associated state. It writes an on-disk recovery journal containing
only those bits/booleans. It enables airplane mode, waits three seconds, verifies
the airplane bit, then restores the prior airplane and WiFi settings **before any
operator prompt**. Every armed exercise has a `finally` restoration path, including
operator cancellation/timeout, observer errors, post-mutation adb errors, Ctrl+C
and handled SIGTERM. Restoration attempts both controls independently, retries,
and verifies settings AND prior WiFi enabled/associated booleans. Already-restored
states cause no gratuitous radio writes. Raw SSID/BSSID/IP text is discarded.
Only those two controls are ever mutated; other device/app settings are untouched.

Restoration cannot be physically guaranteed after USB loss, host power loss,
forcible kill or an uncooperative OS. Such a failure must never be called PASS:
the tool rejects, records `radio_restore_failed` if possible, and keeps the
pre-mutation recovery journal. Restore using the recorded prior bits on the
explicit device, and independently verify network access before resuming:

```text
adb -s 909f194a shell cmd connectivity airplane-mode <enable-if-prior-1-else-disable>
adb -s 909f194a shell svc wifi <enable-if-prior-1-else-disable>
```

The readback proves the recorded controls and WiFi availability/association state,
not the same SSID/BSSID, cellular registration, Internet reachability or VPN state.
Do not change network selection/app settings manually during an exercise; the
harness cannot restore settings it never owns or reads. A restoration failure is
a recovery task, not a reason to bypass the gate or continue acceptance.

## 4. Screenshot privacy boundary

There is deliberately **NO screenshot or UI-dump capability**, even in exercise
mode. A foreground-package check alone cannot exclude notification/IME overlays
or a private profile screen. The harness never disables FLAG_SECURE, changes the
screenshot/privacy preference, opens other apps, captures the current private
screen, or writes a screen image. Separately authorized parent capture must show
only the intended XIO test screen with overlays cleared and no keys, profile QR,
server credentials, unrelated apps or notifications. Keep such reviewed screenshots
outside this harness's public/committed logs. Their absence is an explicit gap,
not permission to capture the current phone screen.

## 5. Tests (all mocked, no adb/device required)

```text
python -m unittest discover -s tools/acceptance -p test_android_acceptance.py -v
python tools/acceptance/android_acceptance.py --help
```

The mocks exercise exact Full/Client identities, stale local/installed bytes,
wrong package/version/cert/device/shared UID/splits, allowlisted/redacted app
telemetry, missing-process/unknown-PSS behavior, opt-in boundaries, 30-second
edge cases, restoration ordering and failures, and persistent recovery evidence.
They prove harness control flow only, not real Android compatibility or VPN PASS.
