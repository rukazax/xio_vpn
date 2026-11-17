# C7 independent-review follow-up (new freeze)

Parent commit: `f684fb12322872b9b38b0c2f943f52558a99dc97` remains unchanged. This follow-up is not independent acceptance; parent will assign replay after the new commit.

## Independent RED retained

[Exact reviewer fixture](<reviewer_adversarial_test.dart.txt>) SHA256 `6f53aa058ce437d74ef5cf45de072775754a221298e0150376837ac6b391ff0d`; [raw RED](<adversarial.txt>) and [exit 1](<adversarial.exit>) copied read-only from reviewer evidence into this owned directory. Two failures: disposed old store completing pending save clears replacement store's window request; actual malformed preferences load claims persisted preference known. Late-background ACK and queued-not-started disposal already pass.

These are actual Store/MethodChannel API/state defects. Disposal case uses a save barrier and a replacement memory store, not evidence of a production AppStore-disposal path or physical capture vulnerability. Malformed hydration uses actual AppStore.load and owned disk file. No P2/device-protection claim is made.

## Bounded fix

Only production file changed is [core](<../../../../app/lib/core.dart>): check disposal after save and rollback awaits before state publication/native dispatch; native-dispatch entry also checks disposal; late completion/error cannot publish obsolete native state. Already-issued native operations and already-started persistence writes cannot be recalled; this change prevents new obsolete screenshot dispatch/publication and does not start rollback from a disposed owner after a pending save fails. It is not cross-store storage transaction cancellation. No global ownership registry or broad lifecycle/native framework was introduced.

Failed hydration marks screenshot preference unknown independently of native ACK; successful hydration or successful persistence can establish known state. Fresh absent preference file retains the known default. Resume/reapply cannot turn a failed-hydration preference into known merely by receiving FLAG_SECURE ACK.

[Regression tests](<../../../../app/test/screen_security_review_regression_test.dart>) include the original four reviewer scenarios plus pending save error, successful/failed rollback completion after disposal, unknown hydration through resume/native ACK, fresh absent-file default, and legitimate successful hydration: 10 total. Existing assertions unchanged. Additional reviewer UI/real-postrename probes were not duplicated here.

## Verification

First follow-up iteration: 50 targeted PASS, 743 full PASS / 18 skipped, 42 Client PASS; before/after529 hashes PASS. Analyzer had baseline two core INFO plus a nullable-return warning inherited from the copied review fixture's pending mock handler. Fixed that TEST-ONLY handler by explicitly returning null after awaiting its ACK gate. [First logs](<logs-review2/analyze.txt>), [first manifest](<tested-attempt1.sha256>), and [exact warning-iteration fixture](<warning-iteration-test.dart.txt>) are retained; fixture bytes verified against its manifest. Production guards did not change between these iterations.

Final serial replay completed:

| Check | Result | Evidence |
|---|---|---|
| Targeted including 10 new regressions | 50 PASS, exit 0 | [targeted](<logs-review2-final/targeted.txt>) |
| Complete Flutter suite | 743 PASS, 18 skipped, exit 0 | [full suite](<logs-review2-final/full-suite.txt>) |
| Client define replay | 42 PASS, exit 0 | [Client](<logs-review2-final/client-mode.txt>) |
| Format | 2 files, 0 changes, exit 0 | [format](<logs-review2-final/format.txt>) |
| Analyzer | same 2 baseline core INFO only, exit 1 | [analyzer](<logs-review2-final/analyze.txt>) |
| Source identity | all 529 before/after checks PASS, exit 0 | [before](<logs-review2-final/source-before.txt>), [after](<logs-review2-final/source-after.txt>) |

[Final owned inventory](<final-completed-inventory.txt>) has no live owned processes. Both serial test jobs (`pwsh-b7f3d8f34aa84113`, `pwsh-aaa13de6263e417a`) were collected exit 0; all preparation/identity jobs also completed. [Final index verification](<final-index-identity.txt>) passes all 529 files. Source-only whitespace/diff check passed. No background C7 work remains.

Runner uses only owned remote HOME/TMP/XDG/PUB_CACHE, existing complete assets, offline dependencies and actual analyzer options. Owned remote was idle before transfer. Final [manifest](<tested-app.sha256>) freezes all 529 Git-index application files; old 528-file freezes and original RED classifications remain historical evidence, not this candidate's manifest.

Parent reports reviewer's final f684 result is HOLD on the same two findings only. Separate actual-settings-widget malformed-load+ACK probe independently confirms the missing persistence warning; double REAL post-rename failure+retry passes. Reviewer fixture fakeasync hang was a harness issue, not a candidate failure. Those additional reviewer probes were not rerun or modified here; parent will arrange exact new-commit independent replay.

## Limits

No new native/Apple files, catalogue changes, host capture policy changes, Android compilation/device tests, production VPN/network/service/Gateway operations. Existing two baseline analyzer INFO findings must remain separately reported. All jobs and final commit identity will be reported to parent; no amend, merge or self-acceptance.
