# Audit fixes: Windows updater, WebUI transport and real-asset tests

Base: **664d27441e50ea83b54946e9f1001786bdc08baa**. Branch: **fix/final-audit-20261105**.

## Изменения / Changes

- Windows updater accepts the actual **flat** release ZIP and the legacy XIO/ ZIP, normalizing both into a private XIO staging directory. Mixed layouts, missing engine/AOT/executable, file-directory conflicts, Windows path aliases, links, duplicate names and raw ZIP backslashes fail before extraction writes files.
- The generated Windows transaction restores original files after copy failure, startup refusal, early exit or missing/mismatched startup acknowledgement. It stops only the replacement process before attempting rollback. If stopping/restoring cannot complete, it retains the original files and records the error rather than deleting the backup.
- Startup acknowledgement must be fresh and contain the expected version. Failure to remove a previous acknowledgement fails **before** moving the installed application. Existing backups are never overwritten. Directory moves use the non-nesting Directory.Move operation.
- WebUI admission is capped at **32 connections**, before worker creation. TLS handshakes run in admitted workers, not the accept thread; TLS timeout **5 s**, HTTP idle timeout **15 s**, absolute connection/request deadline **60 s**. The absolute deadline also stops trickled headers/body. This bounds transport resources; it is not a claim of immunity to every DoS attack.
- Release-artifact tests verify the **actual staged signed manifest** and its declared files. Historical signed fixtures remain historical protocol fixtures; they are no longer confused with the mutable published APK bytes. Missing explicitly requested artifacts fail rather than silently passing/skipping. No private signing key or replacement signature was used.

## Проверки / Verification

All following final checks passed on the corrected sources:

| Gate | Result |
|---|---|
| Flutter analyze --no-pub | No issues |
| Full Flutter, XIO_RELEASE_DIR + XIO_ASSET_AUDIT=1 | **367 passed, 8 skipped, 0 failed** |
| Explicit Client-mode | **17 passed** |
| Windows ZIP + update security target suite | **44 passed**, including actual published ZIP extraction |
| Real manifest/signature/hash/download suite | **7 passed**, real APK bytes |
| Full Python server/tools/client suite, private mount + network namespaces | **217 passed**, no deselections; includes 6 new WebUI transport tests |
| Generated transaction, native Windows PowerShell 5.1 | **10/10 passed** |
| Generated transaction, PowerShell 7 | **10/10 passed** |
| Stale-ACK negative control | Previous script fails the new removal-denial test; corrected script passes |

The eight Flutter skips are environment/live/variant gates, not exclusions of the two previously failing artifact tests. The initial corrected full run exposed those two stale-fixture failures; they were repaired by using the real signed manifest, not skipped or re-signed. Final full run includes the actual artifact gates and source-resource provenance gate.

Windows transaction cases: copy failure, startup refusal, unconfirmed exit, startup timeout, mismatched ACK, stale ACK, denied stale-ACK removal, pre-existing backup, failed stop/rollback with preserved original backup, successful replacement. Real temporary filesystem operations are used; process launching/stopping is mocked. **No unsigned XIO executable was run and no WDAC/SAC policy was changed.**

The loopback WebUI tests cover: stalled-handshake head-of-line blocking, connection-cap enforcement/recovery, failed-handshake slot release, handshake timeout, partial header/body idle timeout and an absolute deadline despite trickled bytes. Module token/log state is created only in a temporary copied-module directory, not on the production host.

## Повторение / Reproduction

```bash
cd app
export XIO_RELEASE_DIR=/path/to/downloaded/v0.24.2/assets
export XIO_ASSET_AUDIT=1
flutter analyze --no-pub
flutter test --no-pub --concurrency=1
flutter test --no-pub --dart-define=XIO_CLIENT_ONLY=true \
  test/client_only_test.dart test/client_import_test.dart test/client_theme_test.dart
```

Server system-path tests must run in a private mount/network namespace with temporary systemd/XIO directories and no host service sockets. Do **not** run privileged tests unisolated on a production server. WebUI transport tests can run unprivileged:

```bash
python3 -m pytest -q server/webui
```

For Windows, choose a **new test-only** root, export the production generator output, then run the harness under both PowerShell versions. The harness refuses mismatched roots, reparse points and existing directories without its own fixture marker.

```powershell
$env:XIO_WINDOWS_TEST_ROOT = "$env:TEMP/xio-update-test-$([guid]::NewGuid())".Replace('\','/')
$env:XIO_WINDOWS_SCRIPT_EXPORT = "$env:TEMP/xio-update-export.ps1"
# From the app directory:
flutter test --no-pub test/update_windows_test.dart
# From the repository root, native Windows PowerShell 5.1:
powershell.exe -NoProfile -File tools/test-windows-update.ps1 `
  -TemplatePath $env:XIO_WINDOWS_SCRIPT_EXPORT -Root $env:XIO_WINDOWS_TEST_ROOT
# PowerShell 7:
pwsh -NoProfile -File tools/test-windows-update.ps1 `
  -TemplatePath $env:XIO_WINDOWS_SCRIPT_EXPORT -Root $env:XIO_WINDOWS_TEST_ROOT
```

## Границы / Not completed here

**This is a tested source branch, not a new release or deployment.** Main, release tag, signed update manifest, published APK/DEB/ZIP assets and phone installation are not changed by this milestone. The Windows platform still must be added to the signed release channel. Real Windows XIO startup/VPN remains unverified because of local application-control policy.

Linux package refresh, cascade pin/address/mode fixes, iOS/macOS TLS-test failures and native build, exact release-APK phone acceptance, live flight-mode/fallback/memory tests and the rest of the project queue remain open. The old audit findings continue to describe the audited base commit; only the specifically listed source defects/gates are addressed here.
