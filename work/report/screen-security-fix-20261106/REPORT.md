# C7 screenshot-setting recovery and finalization

Historical first freeze (`f684fb1`): independent review subsequently found two bounded defects. See the [new follow-up freeze and results](<review2/REPORT.md>); the evidence below is preserved, not claimed as acceptance of the follow-up.

Base: `ba3566b6b2cd63ecedee8de11a5e549b5eb89958`; branch: `agent/screen-security-fix-20261106`. Prepared for independent review, not self-acceptance.

## Implementation

- Windows/Linux shared Full/Client settings disable the screenshot switch and explicitly disclose that capture blocking is not implemented.
- Android keeps persisted desired permission separate from nullable last native window-flag acknowledgement. Serialized setters/reapplications suppress superseded ACKs, preserve errors/missing-plugin as unknown, and preserve Future<void> contracts and existing callers.
- A failed save can occur after disk rename: setter tries rollback save; if rollback also fails, persistence remains unconfirmed independently of native ACK. Retry can recover.
- Native Activity requests FLAG_SECURE before Flutter startup. Background transitions invalidate prior window ACK; actual resume reapplies saved opt-in. Native success(null) acknowledges addFlags/clearFlags, NOT capture protection proof.
- Seven new messages in all 13 catalogues; prior entries and localization assertions unchanged. No Apple native files changed; no universal protection claims.

## Recovery inventory and bounded regression fix

Failed worker left 19 staged source/test/catalogue files, HEAD still base, no commit. Original remote wrapper PID 1161813 and Flutter PID 1164013 were alive: recovery did not restart the worker, duplicate tests, or overwrite running executed source. Original job ID was unavailable; completion was recovered from existing exit receipts/logs. Original full run finished with 732 passed, 18 skipped, 1 failure; Client replay passed 32/32. All original 528 executed files matched the original frozen Git index/manifest before and after.

The sole full-suite regression was the existing idle-status-poll test: redundant setForeground(true) enqueued a screenshot notification despite no lifecycle transition (widget test platform defaults to Android). Bounded one-condition fix gates screenshot lifecycle handling on `changed`. True background/resume behavior remains tested; unchanged foreground calls remain silent. Original failing logs and original manifest are preserved. A new serial recovery runner tests the new frozen bytes; no test assertion was weakened.

## Evidence and classification

Paths below are relative to this evidence directory.

- Original `logs/red.txt`: five failures. Only TWO desktop UI failures are actual baseline behavior RED. The THREE Android failures are Linux dart:io platform-seam reachability limitations, NOT proof of Android defects.
- `logs/red-instrumented.txt`: separate explicitly TEST-ONLY baseline with exactly one applyScreenSecurity platform gate replaced by defaultTargetPlatform Android. Four fail, one pass: real Store/channel default-enable-disable PASS; missing-plugin false-success and overtaking ACK RED, plus both desktop UI RED.
- `baseline-negative-test.dart.txt` preserves the exact original negative test bytes, SHA256 `7a905542026fdf80490b8805cabbcdf9b93287cebc9e5339ca104da28a271389`. Baseline archive's 527 production tracked files equal base Git bytes. Instrumented baseline's 528 files equal that archive except the single test-only gate replacement (see `negative-identity.txt`).
- `logs/green-attempt1.txt` retains earlier fixture failures (Flutter target-platform cleanup too late and lazy Client ListView navigation); corrected before final targeted GREEN.
- Original `logs/green-targeted.txt`: 38/38 (16 new real Store/widget/source checks, 9 existing settings, 13 localization). Includes Full/Client actual navigation, unsupported states, Android default/enable/disable/reload/import open-close/error/missing-plugin/real post-rename rollback/double-save failure retry/ordering/older failure/newer queue/background-resume.
- Original analyzer and final analyzer: only baseline two core INFO curly-brace findings, exit 1. No override or localization diagnostic introduced.
- `tested-app.sha256` is original 528-file manifest; `tested-recovery-app.sha256` is final recovery manifest. Historical candidate-app.tar in outer evidence is a transfer overlay, NOT final executed identity proof: core and both settings/screenshot test files differ from final index. Do not use that archive as the final candidate.

## Final recovery results

Completed serially, from final frozen Git bytes:

| Check | Result | Evidence |
|---|---|---|
| Targeted + existing idle regression | 40/40 PASS, exit 0 | [targeted log](<logs-recovery/targeted.txt>) |
| Complete Flutter suite | 733 PASS, 18 skipped, exit 0 | [full log](<logs-recovery/full-suite.txt>) |
| Client define replay | 32/32 PASS, exit 0 | [Client log](<logs-recovery/client-mode.txt>) |
| Format | 5 files, 0 changes, exit 0 | [format log](<logs-recovery/format.txt>) |
| Analyze | exit 1; same 2 baseline core INFO only | [analyzer log](<logs-recovery/analyze.txt>) |
| Executed-byte identity | all 528 files before/after PASS, exits 0 | [before](<logs-recovery/source-before.txt>), [after](<logs-recovery/source-after.txt>) |

[Final process inventory](<recovery-completed-inventory.txt>): no owned processes alive. Original wrapper completed; recovery wrapper PID 1326392 completed, local job `pwsh-3c6f2196eba44337` collected exit 0. No ongoing C7 test jobs. Unrelated jobs were neither inspected nor stopped. [Index verification](<verify-frozen.py>) compares all 528 final application files to the index or supplied commit. Source-only diff checked separately; evidence does not replace executable-source hashing.

## Isolation and limits

Remote scope exclusively `/srv/archives/agent-screen-security-fix-20261106`. Runners use owned HOME/TMP/XDG/PUB_CACHE, process-local safe.directory=/opt/flutter, complete existing assets, actual analysis options and offline dependencies. Author disclosed TWO preparatory dart-format commands before owned HOME exports: do not claim every preparatory command was isolated. No root-pub-cache writes were requested. Existing cache copy was owned (~195 MB); no extra unrelated suites or other workers were stopped.

No full Android compilation or device/capture-policy proof. New native onCreate still needs compiler/device verification. No host screenshot policy/COM/services/autostart/native VPN/phone/VPS/network/DNS/HTTP/security policy/Gateway/Kot/Terra actions. Tests use mocked MethodChannel, including success(null), not actual OS capture enforcement. Shared lifecycle source changed only for screenshot state; independent review must validate scope and native startup assumptions.
