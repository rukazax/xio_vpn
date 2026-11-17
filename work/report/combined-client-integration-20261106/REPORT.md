# Combined-client integration acceptance — 2026-11-06

## Exact accepted tree

Independent reviewer accepted `d10d4511cb1a49ab6010c4d7c10b5bc613be77ec`, following `29552212d619ae74d07f63d4cb2d323c626f6186` and integration base `ea891990997038d50c863fb07cdc27967943fcdd`. Parent fast-forwarded the integration branch to that exact D10 commit and verified no tree difference. Existing untracked build-support was untouched.

The original component acceptances did not constitute combined acceptance. The unchanged approved25-file union first found414 passes/two failures at EA891: an outdated test override of `saveNativePlan` and missing routing-message translations. The first follow-up fixed the override and routing message, but then yielded417 passes/one failure: additional missing connection messages. The complete official-parser diagnostic enumerated606 normalized literals and exactly two remaining missing keys across all13 catalogues. All negatives remain preserved: [EA891](<ea891-negative.log>), [295](<295-negative.log>), [complete remaining-key diagnostic](<295-missing-keys.log>).

Parent corrections changed only one test override signature and added three translation keys in each of13 catalogues. No runtime Dart/Android/Go/server logic or assertions changed. Static checks verified unique JSON keys, exactly the intended additions and preservation of all previous cells. Neither old candidate was amended or retroactively relabeled accepted.

## Fresh independent D10 evidence

- **418/418 pass, zero failures, zero reported skips**, unchanged approved25-file selection, Linux Flutter3.47.7/Dart3.13.5, complete assets, concurrency2: [raw log](<d10-green.log>), [selection](<d10-selection.txt>).
- Complete606-template diagnostic: **zero missing keys/cells across13 catalogues**: [log](<d10-missing-keys.log>).
- Analyzer: **zero errors/warnings, two known INFOs**, core1008/1010; **exit1**, not a clean-zero analyzer result: [raw log](<d10-analyzer.log>).
- [Command exits](<d10-results.log>), [commands](<d10-commands.log>), [original runner](<run-d10.sh>), [repair diff](<d10-repair.diff>).
- [774-file source manifest](<d10-source.sha256>) and [post-run verification](<d10-source-after.log>) match. The reviewer's13748-file source pub-cache manifest was unchanged. Archive before/after SHA256 `872fe501b21fbc1a564d4aeb3cab52b9b6c498ecf4c92a2e797d28b0b51ff3f9`.

The13 explicitly selected text evidence files here were copied byte-identically from reviewer-owned output. No archives, binaries or screenshots were added. The [complete independent report](<../../../../REVIEW-COMBINED-CLIENT-20261106.md>) preserves all historical verdicts and provenance.

Previously executed Java7/Python3, real compiled Kotlin routing/provenance, actual-Dart/actual-Kotlin coupled7, DNS4 and isolated vault7+7 remain applicable through whole-tree identity. They are **earlier executions on unchanged bytes**, not freshly rerun D10 tests, and are not added to the418 count. The union is not the entire app suite.

## Separate Android compiler result

A separate [actual Android preflight](<../../../../ANDROID-COMPILE-PREFLIGHT-20261106.md>) reports real `compileDebugKotlin` and `compileDebugJavaWithJavac` passes in Full and Client-define modes using fresh offline exact-EA891 Go bindings, real Engine/dependency classes and SDK36/Kotlin2.4/JDK21. It is NOT the earlier compile-only collaborator test.

The original committed AAR is stale: SHA256 `cfc336c936c06f0d08b73fca77768f31a23afcb7f915354e5d78e61995e27de7`, missing new mobile methods. Real negative controls fail Kotlin against that AAR. Fresh owned arm64 AAR SHA256 `fa319f5c4cd45f20db93934a2288643c507f6af08ca239e52c679560b36dee0b` supplies them and makes those failures disappear. **The committed AAR was not replaced.** The source branch therefore still requires coherent artifact generation before shipping.

Parent `git diff --exit-code EA891 HEAD -- app/lib app/android app/pubspec.yaml app/pubspec.lock protocol tools tooling vendor` passed at exact D10. This preserves applicability of the compiler input proof, conditional on regenerated bindings. The compiler excluded Dart compilation and asset stages, regenerated arm64 only, and did not validate actual separate Client manifest/assets staging, other ABIs, OpenVPN JNI, APK/AAB assembly, signing, installation or physical operation.

## Remaining boundaries

C6 desktop startup, screenshot/manual-mode behavior, WebUI contracts, MTProto resource ownership and durable provisioning/issuance remain separate work. No production VPS/services/routes/phone/security-policy change or release publication occurred here. macOS/iOS remain deferred. This is bounded client integration acceptance, not whole-product or release acceptance.
