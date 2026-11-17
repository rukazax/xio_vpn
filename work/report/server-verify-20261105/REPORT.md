# Await server archive verification before update side effects

## Scope and classification

- Worktree: `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-server-verify-20261105` (absent on initial inspection, then created).
- Branch: `agent/server-verify-20261105`; base: `d48c921bf85b4145d86be96467a6112ab4ce4c6d`.
- Inherited GPT-6.1 Sol runtime retained; no model switch.
- Production change confined to [managed_service.dart](../../../app/lib/managed_service.dart#L141-L177); new regression in [managed_update_verification_test.dart](../../../app/test/managed_update_verification_test.dart).

At the base, `ensureUpdated` discarded the Future returned by `ServerRelease.verifyArchiveOffThread`. Loading the updater program, entering local maintenance, and transferring the archive could therefore race the digest check; a mismatch failed outside the returned update Future. An initial read-only `inspect` is intentional and remains allowed.

This is a **local verification ordering / async error propagation fix**, not a demonstrated corrupted-code installation bypass. Source inspection of [the downstream updater](../../../app/assets/xio-server-update.py#L134-L160) shows a second SHA256 check before unpacking. [The update transaction](../../../app/assets/xio-server-update.py#L219-L274) calls that check before service stops and installed-file replacement (it can create its lock/staging directory first). The updater was inspected, not executed.

## Change

`ensureUpdated` now awaits `verifyUpdateArchive(local, archiveBytes)` before loading the updater asset. The small overridable boundary defaults directly to the existing manifest-pinned off-thread verifier. It lets tests hold verification pending without relying on how fast the digest isolate runs. Production constructor/callers, digest algorithm, SSH identity gate, key handling, manifest format, revision/compatibility policy, install behavior and updater program are unchanged.

## Deterministic regression

The three new tests use fake AssetBundle, SSH execution/upload and store/native-plan hooks. No real connection or updater process is created.

1. A Completer holds verification pending. The returned update Future must stay incomplete, only the manifest/read-only inspect/archive read may occur, updater-program load and upload/update must not occur, and maintenance/native-plan notifications must not occur.
2. On release, the **real off-thread verifier** hashes the good fixture archive; only acceptance permits updater load, maintenance/native-plan save, and mocked update transfer. The exact archive slice (excluding ByteData sentinels), digest and server identity reach the fake SSH update; maintenance is subsequently cleared.
3. On release with a modified archive, the real verifier rejects with StateError through the returned update Future, with no updater-program load, upload/update, maintenance transition, plan save or success log. A separate test exercises the default ManagedService without the gated subclass and checks the same mismatch behavior.

Unhandled errors remain test-zone failures, not swallowed errors. The negative control below reproduced the detached mismatch error when the await was removed.

## Environment and commands/results

Host: `debian17-root` / `192.168.88.17`; Flutter **3.47.7**, Dart **3.13.5**, existing `/opt/flutter` installation. All own Debian snapshot, generated app files, temporary files and evidence are under `/srv/archives/agent-server-verify-20261105`; `TMPDIR` points to its `tmp` directory. Existing `/root/.pub-cache` supplies offline dependencies. Root free space stayed approximately 5.9 GiB; no installs or heavy builds.

A `git archive HEAD app` snapshot from the assigned base was uploaded and overlaid with only the changed production source and new test. The local transfer tar was removed after its absolute path was verified; the remote base archive remains under the owned archive directory.

Run from the snapshot app directory, with `/opt/flutter/bin` executables:

| Command | Exit/result | Evidence |
| --- | --- | --- |
| `flutter --version` | 0; Flutter 3.47.7 / Dart 3.13.5 | [version log](flutter-version.log) |
| `flutter pub get --offline` | 0; cached dependencies resolved | [dependency log](pub-get.log) |
| `dart format test/managed_update_verification_test.dart` | 0; formatted new test | [format log](format.log) |
| `flutter test --no-pub --concurrency=1 --reporter expanded test/managed_update_verification_test.dart test/install_domain_security_test.dart` | 0; **23/23 passed** (3 new + 20 existing installer tests) | [focused tests](focused-tests.log) |
| `dart analyze lib/managed_service.dart test/managed_update_verification_test.dart` | 0; **no issues** | [analysis](analyze.log) |
| Remove only `await` at the update verification boundary, then `flutter test --no-pub --concurrency=1 --reporter expanded --timeout 30s test/managed_update_verification_test.dart` | **1, expected**; all three regression cases fail; pending update finishes early and detached digest mismatch is observed | [mutation failures](missing-await-mutation.log), [expected exit](mutation-result.log) |
| Restore the corrected source, then `flutter test --no-pub --concurrency=1 --reporter expanded test/managed_update_verification_test.dart` | 0; **3/3 passed** | [restored regression](restored-regression.log) |
| `git diff --check` | 0 | local validation |

The committed mutation-log copy removes spaces from blank lines for `git diff --check`; the raw log remains on Debian.

Reproduction scripts: [focused run](run-focused.sh), [missing-await negative control with restore trap](run-mutation.sh). The negative control retains the verification hook and removes only await, reproducing the original asynchronous ordering defect. It mutates only the owned Debian snapshot, never the local commit or parent worktree.

Final corrected local and Debian source hashes match:

```text
5cf24c17c11d21644af44f22ce5a63ae0335169e658c81e78bd6a09c48c7d17c  app/lib/managed_service.dart
95df55b466fc3b2725535a80cdfc25492eba07b2b822734b0cc90e06ca092d33  app/test/managed_update_verification_test.dart
```

## Gaps / boundaries

- No full Flutter suite: parent owns the concurrent full run. Only focused mocked tests and targeted static analysis ran here.
- No live VPS, real SSH transport, updater execution, service maintenance, deployment or end-to-end install/update was tested or performed.
- Downstream digest enforcement was source-reviewed only; no claim of independent dynamic server-side coverage.
- No Apple work, platform installation/build, publication, main merge, release, secret access or system-policy changes.
- Parent cascade Dart/l10n and sibling deployment/Windows-builder worktrees were not modified.
