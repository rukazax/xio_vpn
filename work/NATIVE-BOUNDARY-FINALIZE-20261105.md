# Native integration boundary — 2026-11-05 UTC

## Result and scope

Implementation commit: `2844af218e8f9a86397932fb8c7bfe4bcc9931f9`, based only on combined clean `5b38a20ae734051f275d5ed22e8cc320f48824d5`, branch `agent/native-finalize-20261105`.

**Bounded source fixes complete; not deployment/release acceptance.** Ordinary WSL Ubuntu and Debian each ran **207 tests: 206 passed, one legitimate private-kernel skip, exit 0**. Scoped Flutter ran **44 passed, exit 0**. Parent must independently review/retest before integration.

Only the four authorized runtime boundaries and corresponding tests changed. No cherry-picks, parent/other worktree modifications, routing/key/lifecycle behavior changes, privilege relaxation, bootstrap/update/packaging changes, generated release assets, installs, public-network probes, phone actions, service actions, push or merge.

## Enumerated producer contract before implementation

| Producer writes | Consumer projection |
|---|---|
| Initial configure: `prepared` | RPC accepts |
| `_apply`: `applying` → `guarded` → `applied` | RPC now accepts both transient phases as well as applied |
| `record_failure`: `preparation_failed`, `apply_failed`, `fail_closed` | All observable through inspect/RPC, without mutation |
| Remove: `removing` → `removed` | Existing behavior retained; disabled response remains minimal |
| Guard writes: exactly `unknown`, `last_installed` | Inspect projects only these strings; missing/invalid receipt guard becomes unknown; RPC accepts optional finite guard only |

[Producer inspect](<../server/managed/cascade_native.py#L802-L811>) now includes historical guard provenance. `last_installed` means **past successful installation**, not a claim that current guards exist. Live infrastructure and fresh exact-config proofs still determine readiness. No phase-to-guard inference. Legacy RPC results may omit guardState; invalid incoming RPC phase/guard produces redacted typed INVALID_RESULT.

[RPC status/capability sanitizer](<../server/managed/cascade_native_rpc.py#L189-L264>) admits the complete nine-phase set, bounds readiness age/TTL, and samples NOW once. Owner authentication, identity-before-import, typed unknown outcomes and no-automatic-remove behavior are unchanged.

[Dualstack consumer](<../server/managed/dualstack.py#L51-L79>) demotes stale/invalid evidence to false. [Dart consumer](<../app/lib/native_profile_readiness.dart#L44-L70>) rejects issuance when stale/invalid; it does not downgrade required families or fall back to proxy/direct/legacy metadata. Both retain the absent-opt-in legacy contract.

Every readiness consumer now requires: strict existing UTC timestamp parsing, observation no more than five seconds in the future, expiry strictly after NOW and observation, expiry minus observation ≤60 seconds, NOW minus observation ≤60 seconds. Existing integer-zero/opaque-string revision compatibility is deliberately retained. Current honest A already emits valid ≤60-second proofs; this is defense in depth, **not evidence of a current-A TTL exploit**.

The only existing fixture corrections are [explicit mocked lifecycle admission](<../server/managed/test_cascade_native.py#L220-L228>) in the apply-failure unit and [integer proof time](<../server/managed/test_cascade_native_review.py#L86-L106>) matching the actual producer. Production root/namespace checks and the private-kernel skip are unchanged.

## Regression coverage

[New combined Python module](<../server/managed/test_native_integration_boundary.py>) adds 11 tests (196 existing +11 =207): actual configure preparation/partial/after-guard failure → real receipt → actual inspect → actual RPC sanitizer; actual applying/guarded observations during real `_apply` with effects mocked; all phases and both guard values; legacy absence; invalid guard/phase redaction; historical guard never promoting readiness; old/far-future/long-TTL and millisecond boundaries, ±5-second skew, strict UTC/types/calendar, preserved revision compatibility, one NOW sample, actual A positive and no-proof expiry-equals-observation output. Effects remain mocked; private file persistence/owner flock are real.

[Scoped Dart tests](<../app/test/native_profile_readiness_test.dart>) replace the old two-minute positive fixture with a 31-second interval, add boundary/UTC/revision cases and reject oversized evidence at actual provisioning-bundle issuance even with proxy config supplied. Existing owner/delegated compensation, required-family no-downgrade, plan identity/hash, journal persistence and issuer tests also ran.

## Commands, exits and logs

### Honest negative baseline — before source edits

From the isolated Windows worktree, PowerShell invoked:

```text
wsl -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Users/er-ka/Documents/deepseek-harness/xio_vpn/work/agent-native-finalize-20261105/server/managed && python3 -B -m unittest discover -v -p "test_*.py"'
Ran 196 tests in 30.181s — FAILED (failures=2, skipped=1) — exit 1
```

[Baseline log](<../evidence/python-baseline.log#L200-L222>) identifies exactly the lifecycle-admission fixture and fractional-timestamp fixture. This is not described as a full pass.

### Focused and final Python

```text
# ordinary WSL; final runs use TMPDIR=/srv/archives/agent-native-finalize-20261105/tmp
python3 -B -m unittest -v test_native_integration_boundary test_cascade_native.NativeTests.test_apply_failure_retains_intent_without_unproved_guard_claim test_cascade_native_review.ReviewTests.test_live_capabilities_never_green_for_zero_mask_foreign_rule
# interim, before adding the extra actual-transient test:
Ran 12 tests in 0.493s — OK — exit 0

# full final suite, same WSL worktree/server/managed:
python3 -B -m unittest discover -v -p 'test_*.py'
Ran 207 tests in 30.212s — OK (skipped=1) — exit 0

# ordinary Debian via saved ssh debian17-root alias:
# cd /srv/archives/agent-native-finalize-20261105/source/server/managed
# TMPDIR=/srv/archives/agent-native-finalize-20261105/tmp
python3 -B -m unittest discover -v -p 'test_*.py'
Ran 207 tests in 78.970s — OK (skipped=1) — exit 0
```

Logs: [focused](<../evidence/python-focused.log>), [WSL full](<../evidence/python-final.log>), [Debian full](<../evidence/python-debian-final.log>).

The skip in both final runs is `test_actual_private_kernel_zero_mask_conflict_never_installs_reject_route`: **requires fresh private network AND mount namespaces; never mutates host**. No namespace bypass, validator disabling or actual private-kernel proof was performed.

### Offline Dart/Flutter on existing Debian SDK

All new Debian snapshot/home/cache/tmp writes are below `/srv/archives/agent-native-finalize-20261105`. Snapshot began from a Git archive of the baseline plus only authorized changed files; the final test module was synchronized afterward, and formatted Dart files were copied back before final hashing. Existing pub cache was copied into this owned root; no package installation or network download was requested.

```sh
export HOME=/srv/archives/agent-native-finalize-20261105/home
export PUB_CACHE=/srv/archives/agent-native-finalize-20261105/pub-cache
export TMPDIR=/srv/archives/agent-native-finalize-20261105/tmp
export CI=true FLUTTER_SUPPRESS_ANALYTICS=true DART_SUPPRESS_ANALYTICS=true
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/opt/flutter
cd /srv/archives/agent-native-finalize-20261105/source/app
/opt/flutter/bin/dart format lib/native_profile_readiness.dart test/native_profile_readiness_test.dart
/opt/flutter/bin/flutter --no-version-check pub get --offline
/opt/flutter/bin/flutter --no-version-check test --no-pub --reporter expanded test/native_profile_readiness_test.dart test/native_cascade_plan_test.dart test/native_cascade_journal_test.dart test/delegation_test.dart test/managed_models_test.dart
/opt/flutter/bin/dart format --output=none --set-exit-if-changed lib/native_profile_readiness.dart test/native_profile_readiness_test.dart
/opt/flutter/bin/dart analyze lib/native_profile_readiness.dart test/native_profile_readiness_test.dart
```

Flutter 3.47.7 / Dart 3.13.5. Scoped tests **44/44, exit0**; subsequent format check **zero changes, exit0**; analyzer **no issues, exit0**. Logs: [offline preparation](<../evidence/dart-prepare-retry.log>), [44 tests](<../evidence/flutter-scoped.log>), [format/analyzer](<../evidence/dart-analyze-format.log>).

An initial preparation attempt exited128 because the isolated HOME did not inherit Git's `/opt/flutter` ownership trust. [Original error](<../evidence/dart-prepare.log>) was investigated; only the per-process exact-SDK Git setting above was supplied, not global/system configuration. Initial formatting warned that flutter_lints was unresolved before offline pub resolution; the post-resolution check/analyzer passed cleanly. Pub prints its generic “Downloading packages...” stage even with `--offline`; dependencies came from the copied existing cache.

## Exact tested committed bytes

All eight changed source/test files use LF in both Git index and working tree. [Local machine-readable hashes](<../evidence/source-hashes.json>) and [independent Debian hashes](<../evidence/debian-source-sha256.log>) match exactly, after formatting and final tests. No runtime/test source edits followed these hashes.

| File | Bytes | SHA-256 |
|---|---:|---|
| [Producer](<../server/managed/cascade_native.py>) | 52297 | `c3c8922fcec2344dfebcc596a6059ece2224eb5c61a1a3e772a598eda7dfb3b3` |
| [RPC](<../server/managed/cascade_native_rpc.py>) | 19248 | `04779e10ee7ecf40833702e31773044b6490182a7b242da57290672cbac5f711` |
| [Dualstack](<../server/managed/dualstack.py>) | 28441 | `43705842a1cc7e51616a8dfef0b97c84df4c3c2860430e672ece579e1ae87667` |
| [Core fixture](<../server/managed/test_cascade_native.py>) | 17080 | `6a56d631ef1b9042dcf7508e35ff9a5f865f38aa23692edc1a89bfce3067e835` |
| [Review fixture](<../server/managed/test_cascade_native_review.py>) | 13593 | `d69acdc531c861ee5573660d9a93794940884ad70e70d09ee6b165b1c72c5590` |
| [Combined tests](<../server/managed/test_native_integration_boundary.py>) | 11020 | `ee02a964fab6d6b71571ec3d51d142f8d545a9066aa69bf15c37f2971ae40d3f` |
| [Dart parser](<../app/lib/native_profile_readiness.dart>) | 3621 | `710226a795bc03afa5e981ad69ec185302a0a8daf0dd349dcc6180a0d486da6f` |
| [Dart tests](<../app/test/native_profile_readiness_test.dart>) | 13619 | `f047b301e7321bb58ed90e72ed8616df7413a00ed56e3dcc3bd4366c0fc6f89f` |

`git diff --check` passed for implementation and final complete follow-ups. PowerShell-captured evidence was normalized from CRLF to LF only (no output-content edits) after an initial evidence whitespace check flagged carriage returns. All six background jobs were collected; none remains running.

## Explicitly not verified

No production reboot/systemd activation, live host route/firewall/sysctl change, phone/Android traffic or anti-DPI acceptance, private packet proofs, VPS/provider/Internet egress, signed Windows application execution, installer/build/package/release assets, full-app Flutter suite, live issuer networking, or Apple implementation. Scoped issuer tests use fake API/loopback/offline fixtures. Parent-owned packaging/version/assets/UI-wizard work is neither changed nor certified here. Existing reviewed prerequisite/private packet proof claims are not promoted to new production acceptance.
