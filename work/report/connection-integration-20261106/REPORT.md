# Combined connection ownership / website opt-out integration

## Source lineage and acceptance

- Parent before integration: `8bc78026e02b360761b57972abeb8871200b785b` (accepted vault/server fixes).
- Independently accepted N source `4d31c033c4b294f0e70360d5ab0762a6c39f24b8` merged without conflicts as `74dc06e5eeeef22df543e65532f1e8745b1ccf50`. Fresh replacement reviewer accepted only the bounded ownership/setup/publication scope; no device/JNI/Windows runtime acceptance.
- Parent independently reviewed C5 source `53837d6755fea7fe144655313a5732dd863b41b6`, including its sentinel correction after the parent's genuine negative. Merged as `303cf108decd8a9887afa3b5ea7b888c0894d833`. The controller auto-merge was inspected: only the authorized website parsing/verification changes differ from N; exact-owner cleanup and explicit publication tokens remain.
- N's failed implementation session was not resumed. Its [author report](<../fallback-integration-20261105/REPORT.md>) and39 other explicitly selected text logs/scripts/manifests were copied byte-for-byte from the frozen worktree after independent acceptance. No archive/class/binary/formatted scratch directory was added. The historical author's expectation of an evidence-only commit is superseded by this parent preservation; source commits are unchanged.
- Local independent reports remain [N review](<../../../../REVIEW-FALLBACK-FINAL-20261106.md>) and [C5 review](<../../../../REVIEW-BACKGROUND-PROBE-20261106.md>), with all earlier negative observations retained.

## Parent identity and combined replay

At merge74dc, all19 N source/test SHA256 values matched the independently reviewed [manifest](<../fallback-integration-20261105/source-sha256.txt>), and the accepted credentials (`f4fb362e…`) and server admin (`7cb3764f…`) hashes remained unchanged. Source-only diff-check passed. After C5 merge303cf:

- Combined controller SHA256 `08b691dbc71f3ee050c12e989822489db184904c21e35793c88b22787c302401`.
- Website helper SHA256 `60bc5072696a5b4cf6d1e2192dc28629eb6f1e19a4c06d909299503c20ae94e7`.
- Dart core SHA256 `4f9e5a48857025ddb9ed0a5e712a8d2758fac1afc0a44d2404d4c1e405ada9f5` (same C5 tested source).

Fresh cached JDK21 `javac --release 17` compiled actual merged production Java plus original and independent fixtures into parent-owned scratch. All seven mains exited0:

1. [Original budget](<combined-ConnectionBudgetTest.log>).
2. [Website helper44 checks](<combined-BackgroundVerificationOptionsTest.log>).
3. [Parent missing/error-handshake boundary12 cases](<combined-ReviewMissingHandshake.log>), using the unchanged [fixture](<ReviewMissingHandshake.java>).
4. [Actual service/controller source wiring](<combined-ServiceDownWiringTest.log>).
5. [Independent exact-owner cleanup](<combined-ReviewCleanupOwnerInvariant.log>), [fixture](<ReviewCleanupOwnerInvariant.java>).
6. [Independent unique publication and retirement-DOWN](<combined-ReviewPublicationFinalInvariant.log>), [fixture](<ReviewPublicationFinalInvariant.java>).
7. [Independent cancellation reservation/root/child](<combined-cancel.log>), [fixture](<ReviewCancellationOwnershipInvariant.java>).

Merged website wiring also passed3 tests with Python `-X utf8 -B` ([log](<combined-wiring.log>)). Source-only diff-check passed. Parent's combined managed job `pwsh-fdf253d8405b4f43` was collected exit0.

The [old missing-handshake negative](<missing-handshake-negative.log>) genuinely fails9/12 cases at802 with no HTTP. The first parent Python wiring run [failed](<fixed-wiring.log>) from default Windows cp1251 decoding, not product behavior; the [explicit UTF-8 replay](<fixed-wiring-utf8.log>) passed. No security control was disabled or bypassed.

## Limits

These are actual production Java/helper tests, source-wired Kotlin checks and controlled queues/native-call models—not execution of Kotlin/JNI, Android lifecycle, TUN, DNS, routing, Windows ICS/COM or a full APK. Existing desktop Linux/cross-compile and author Flutter/API36-stub evidence is preserved with its original provenance, not relabeled as a fresh parent run. No new native bindings/helpers/APKs/packages/signatures/installation/publication are claimed.

C2 DNS SDK-prefix correction and C3/C4/C8 routing provenance follow-up are still separately awaiting exact-commit independent acceptance. Further platform/settings/WebUI/ownership/provisioning findings remain open. macOS/iOS remain deferred by the owner. This integration is not release readiness.
