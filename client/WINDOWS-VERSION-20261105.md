# Windows Client packaging version correction — 2026-11-05

## Scope and changes

- Branch `agent/client-winver-20261105`, isolated worktree `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-client-winver-20261105`, base `d48c921bf85b4145d86be96467a6112ab4ce4c6d`.
- Changed only [Client Windows packaging](<build_windows_on_linux.py>), added [focused regression tests](<test_windows_version.py>) and this report. Parent working tree and shared packaging files were not modified.
- Source of package and executable version is [the application pubspec](<../app/pubspec.yaml#L19>). Current `0.24.2+5019` produces `releases/client-0.24.2/XIO-Client-0.24.2-windows-x64.zip`; fixed PE versions are `0.24.2.5019`, both version strings are `0.24.2+5019`. Archive names intentionally use the semantic version, matching the existing naming convention.
- Generate a Client-specific RC rather than replacing historical numeric literals in [the shared RC](<../tooling/cross-platform/windows.rc>). Include both FileVersion and ProductVersion strings, Client product identity and `XIOClient.exe` original filename. Remove version dependence from the Client-only generated window class name.
- Reuse [the existing PE helper](<../tooling/cross-platform/pe-version.py>) unchanged. Stamp and read back **all four** fixed/string file/product version fields after compilation and again before ZIP creation. Missing, stale or unstampable metadata fails the build, including an old cached compiler output. There is no cached-runner bypass.
- Preserve Client entry point, `XIO_CLIENT_ONLY=true`, x64 Flutter target, AMD64 Go helper, private Wine prefix, Client directory/executable identity, runtime dependencies and legal/readme files. Do not turn Client into Full.
- Validate the prepared pubspec matches source; reject invalid/unrepresentable version before any process or staging writes. Create build directories after preparation (preparation creates the stage). Finish a local ZIP only after successful checks via `.zip.part` replacement.

## Commands and results

Commands run from the isolated worktree unless a directory is explicitly shown. All commands below exited **0**.

### Regression suite, Windows

```powershell
$env:XIO_CLIENT_PE_FIXTURE='C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\.build-support\windows-native\portable-client2\XIO\XIOClient.exe'
python -m unittest discover -s client -p 'test_*.py' -v
python -m py_compile client/build_windows_on_linux.py client/test_windows_version.py
git diff --check
```

Result: **26 tests run, 23 passed, 3 skipped** because the Windows token cannot create the pre-existing staging tests' directory symlink. All **9 new Windows packaging tests passed**, including the optional real-PE test. [Windows test log](<../.build-support/client-winver-evidence/client-unittest.log>).

Coverage includes current version and alternate `9.9.9+999`, omitted build normalization to `+0`, invalid/overflow versions, mismatched prepared pubspec, each of the four readback fields, early/final readback failure preventing archive creation, Client identity/architecture flags, real stale-PE stamping and versioned bytes inside a ZIP. Flutter, Go, Wine, preparation and native compilation are mocked in the packaging tests; PE operations and ZIP operations in the real-PE test are not mocked.

The existing fixture was **read/copied only**, not executed or modified. Initial embedded version: `0.23.1+5016` / `0.23.1.5016`. SHA256 remains `C54B5E7591E5A144480CE247216503405A8BE11E8E53161A487D4B486B25A1EA`.

### Lightweight Debian regressions

Inspected `/srv/archives/agent-client-winver-20261105` first: absent. Created only this owned directory, transferred a small input tar (Python sources, pubspec, helper and copied PE), extracted it there. No Flutter/Go build or service operation.

```powershell
ssh debian17-root 'cd /srv/archives/agent-client-winver-20261105 && tar -xf regression-inputs.tar && XIO_CLIENT_PE_FIXTURE=/srv/archives/agent-client-winver-20261105/.build-support/client-winver-evidence/0.24.2+5019/cached-XIOClient.exe python3 -m unittest discover -s client -p "test_*.py" -v > client-unittest-debian.log 2>&1; result=$?; echo "Client unittest Debian exit: $result"; exit "$result"'
```

Result: **26/26 passed, zero skips**, 0.146 seconds. The fixture on Debian is the already-stamped scratch copy, not an executed Windows program. [Copied Debian log](<../.build-support/client-winver-evidence/client-unittest-debian.log>); remote log `/srv/archives/agent-client-winver-20261105/client-unittest-debian.log`.

### Actual resources and independent Windows reader

Scratch location was inspected before use: absent. [Scratch evidence generator](<../.build-support/client-winver-evidence/prepare_evidence.py>) copies the real stale fixture for each version, calls the production stamp/readback function and generates the production Client RC. It verifies original fixture bytes remain unchanged. No app is run.

```powershell
python .build-support/client-winver-evidence/prepare_evidence.py 'C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\.build-support\windows-native\portable-client2\XIO\XIOClient.exe'
$rc='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\rc.exe'
$link='C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
$include='C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0'
foreach($version in @('0.24.2+5019','9.9.9+999')) {
  Push-Location (Join-Path '.build-support/client-winver-evidence' $version)
  try {
    & $rc /nologo /i "$include\um" /i "$include\shared" /fo windows.res windows.rc
    & $link /nologo /dll /noentry /machine:x64 /out:resource-only-XIOClient.exe windows.res
  } finally { Pop-Location }
}
# Run generator again to stamp/read the generated resource-only files too.
python .build-support/client-winver-evidence/prepare_evidence.py 'C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\repo-edit\.build-support\windows-native\portable-client2\XIO\XIOClient.exe'
```

```powershell
. '.build-support/client-winver-evidence/verify-independent-windows.ps1'
```

The [saved independent verifier](<../.build-support/client-winver-evidence/verify-independent-windows.ps1>) uses `System.Diagnostics.FileVersionInfo.GetVersionInfo` assertions to check FileVersion, ProductVersion and both numeric quartets for **all four files** (copied runner + generated resource-only PE, for each version). Generated RC also independently reports ProductName `XIO Client`, OriginalFilename `XIOClient.exe`. Copied legacy runner retains its original non-version identity fields; stamping does not rebrand an input binary. [Independent Windows readback JSON](<../.build-support/client-winver-evidence/independent-windows-readback.json>).

| Input/output | String file/product version | Numeric file/product version |
|---|---|---|
| Copied runner and generated resource PE, current | `0.24.2+5019` | `0.24.2.5019` |
| Copied runner and generated resource PE, alternate | `9.9.9+999` | `9.9.9.999` |

Separate direct COFF-header reads confirm original fixture and all four outputs remain AMD64 (`0x8664`): [architecture readback](<../.build-support/client-winver-evidence/architecture-readback.json>).

## Artifact locations and limitations

- Local evidence root: `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-client-winver-20261105\.build-support\client-winver-evidence` (uncommitted scratch, no release/publishing).
- Each version subdirectory contains `cached-XIOClient.exe`, `resource-only-XIOClient.exe`, generated RC, resource object, icon, manifest and helper JSON. **Resource-only PEs are test fixtures, not runnable Client builds.** Test ZIPs were temporary unittest outputs and were cleaned up; no distributable release ZIP was produced.
- Debian artifacts only under `/srv/archives/agent-client-winver-20261105`. No root-partition builds, no competing Flutter workloads.
- Intentional shared staging pin in [client/build.py](<build.py#L18-L34>) remains `0.24.2+5019`. A future real release still requires the existing reviewed pin update; alternate-version tests mock preparation deliberately and do not claim arbitrary-version staging is supported today. The Windows version/resource/naming logic itself is dynamic.
- Full Flutter AOT cross-build, actual MinGW runner compilation/linking, Windows app launch, installer, driver/UAC, VPN/network features and signing/native acceptance **NOT_EXECUTED**. RC syntax/resource generation was validated with Microsoft SDK tools, not MinGW. No Wine acceptance claim.
- SAC/WDAC was not disabled or bypassed; unsigned XIO files were never executed. No production/VPS/network changes, APK installs, secrets, release replacements, main merge or publishing.
- Parent reported a runtime execution-failure notification, but this child's visible tool transcript contained no failed execution explaining it. Work continued in the same worktree. One initial write was refused by the read-before-overwrite guard and succeeded after rereading; one optional discovery path for Visual Studio did not exist, then the actual x86 installation path was found. No build/test failures persisted.
