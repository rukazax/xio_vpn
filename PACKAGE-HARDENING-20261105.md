# Reviewed package hardening — 2026-11-05

## Scope and integration

New inspected worktree `agent-package-hardening-20261105`, branch `agent/package-hardening-20261105`, starts at `2f2211c79a3b0fc69e5bc55dab71a87cab1ae059`. Reviewed Windows prerequisite `696ed9c477904b5fd1ae415ad293b8f3c6463948` was cherry-picked as `f0604ca`; no additional Client builder changes were made. Apply the original Linux/Windows prerequisites before these hardening changes when integrating into the parent.

Changes are confined to [Linux reader](<tooling/cross-platform/linux_provenance.py>), [baseline fixture metadata](<tooling/cross-platform/test_linux_provenance.py>), [focused Linux/release tests](<tooling/cross-platform/test_package_hardening.py>), the two Linux copy regions of [release orchestration](<tools/release/build-all.ps1>), [PE helper allocation bound](<tooling/cross-platform/pe-version.py>), [focused PE tests](<tooling/cross-platform/test_pe_version_hardening.py>), and this report. Existing review worktrees and parent integration files were not modified.

## Five findings: reproduced before, fixed after

| Finding | Negative-before observation | Fix and positive-after evidence |
|---|---|---|
| Unbounded inspection | Unwatched 9,130-byte members passed both real compressed container fixtures with the member limit lowered to 913 bytes. Inner unwatched members, member counts, aggregate work, and oversized pre-yield PAX metadata also bypassed the old checks. | Streaming physical-header checks precede payload skips and GNU/PAX body processing. Expanded reads and effective PAX sizes are bounded too. Lowered-limit tests now reject these inputs; header-only reader tests prove no irrelevant body read precedes rejection. Inner/control archives receive the same checks. |
| Invalid DEBs | Arbitrary control bytes, unsupported control suffix, reordered required ar members, incomplete/duplicate control fields and duplicate control members passed. | Require the first three ar members in DEB order, recognized codec names matching bytes, valid bounded control tar and a regular metadata file with required Package/Version/Architecture/Maintainer/Description fields. Preserve trailing `_` ar extensions. Valid tiny gzip/xz/bzip2/uncompressed control fixtures and genuine `dpkg-deb` Full/Client packages pass. |
| Contradictory trees | A regular l10n ancestor alongside correct locale children passed both containers; an inner `admin.py` directory followed by its file passed after rebinding the manifest archive hash. | Track all canonical names and implicit parents, including directory entries, irrespective of order. Both cases now reject. The legitimate `/usr/bin/xio -> /opt/xio/XIO` symlink outside assets still passes. |
| Adjacent PE corruption | Actual copied stale Client runner accepted longer versions with all four readbacks correct, while changing the adjacent 1,050-byte manifest. | Reject VERSIONINFO growth beyond the original explicit data-entry allocation, before writing anything. Preserve allocation capacity after shorter stamps. Shared-helper and actual Client `stamp_runner` tests cover current valid stamps, longer clean rejection with original/copy unchanged, all other resource bytes unchanged, and valid new target-sized resources. CLI rejection returns 2. |
| Release final-file clobber | Actual AST-extracted `Invoke-LinuxStep` overwrote previous finals before rejecting stale DEB/tar on **both import and local-copy branches**. Missing second import also clobbered the first final. | Copy both candidates to unique same-directory `.part` paths, verify both, then rename finals. Exact production-function tests now preserve both previous finals on capture failure, second-copy failure, missing input, stale DEB and stale tar; no `Add-Artifact` calls occur. Success publishes both and registers two artifacts. Source inputs and an unrelated `.part` sentinel remain byte-identical. |

Before-fix Linux run: **7 test methods / 23 failing subcases**, exit 1: [negative log](<.build-support/package-hardening/packaging-before.log>). Before-fix PE run: **7 failing assertions**, exit 1: [negative PE tests](<.build-support/package-hardening/pe-before-real.log>). These are intentional reproduction failures, not ignored suite failures.

### Actual PE fixture, not an executed application

Read-only [cached Client source](<../win-release/XIOClient.exe>): SHA256 `ADED1BE2514C8B3CD4B084B9AAC5D62B14EAD2F01EE971075847FF07793722EB`, version `0.23.0+5015`, VERSIONINFO offset **71152**, allocation **736** bytes. This actual source differs from the earlier worker's C54B fixture hash; equivalence is not claimed.

Before the fix, `0.24.2+5019` preserved other resources, but `0.24.10+5020` and `0.25.0+10000` each produced a **744-byte** version resource and changed the manifest at **71888 / 1050**, despite successful four-field version readbacks: [actual corruption probe](<.build-support/package-hardening/pe-corruption-before.log>). Only temporary copies were stamped. Original source hash remained unchanged.

After the fix, current-width stamping succeeds; both longer versions and the maximal valid four-part version fail with `NoRoomError`, leaving the complete rejected copy and original byte-identical. The fresh-resource tests construct valid target-sized VERSIONINFO/resource-table bytes, including a separate adjacent manifest; they are not a compiler/native-execution provenance claim. Both the shared Full helper entry point and actual Client wrapper are tested.

## Inspection policy and real payload headroom

Per tar archive: **128 MiB** maximum individual member (watched or not), **1 GiB** aggregate declared/actual expanded work, **32,768** physical headers, **1 MiB** individual / **4 MiB** aggregate GNU/PAX metadata, and extension-chain depth **16**. Maximum compressed container is **512 MiB**; XZ decoder memory is capped at **128 MiB**. Paths are capped at 4,096 characters / 64 separators before parent tracking to avoid quadratic metadata-derived work. Sparse formats are intentionally unsupported. No compressed DEB data-member copy is retained in memory: inspection reads a bounded slice of the original file.

The reader uses stdlib streaming codecs, a physical `TarInfo` processing hook and stdlib raw XZ decompression with a memory limit. Tests exercise these hooks on bundled Windows Python 3.12 and Debian Python 3.13; future Python upgrades should rerun the focused suite.

Read-only inspection of genuine cached v0.24.2 containers under the final policy succeeded structurally: [measured budgets](<.build-support/package-hardening/genuine-linux-budgets-final.log>).

| Container | Compressed bytes | Expanded declared bytes | Members | Largest member |
|---|---:|---:|---:|---:|
| DEB | 43,981,120 | 89,353,216 | 120 | 30,826,656 |
| Portable tar | 51,124,840 | 89,444,864 | 107 | 30,826,656 |

These historical containers are **not** endorsed as matching current staged provenance; this check establishes format/limit headroom only. Current actual source capture still succeeds with **22 watched assets / 13 l10n files**, recipe **28**, version **0.24.2+5019**: [capture](<.build-support/package-hardening/capture-current-source.log>).

## Final test commands and results

From this worktree, using the requested bundled interpreter:

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
$env:XIO_CLIENT_PE_FIXTURE=(Resolve-Path '../win-release/XIOClient.exe').Path
$p='C:/Users/er-ka/.dsh/dsh-runtimes/dsh-primary-runtime/dependencies/python/python.exe'
& $p -B tooling/cross-platform/test_linux_provenance.py -v
& $p -B tooling/cross-platform/test_package_hardening.py -v
& $p -B tooling/cross-platform/test_pe_version_hardening.py -v
& $p -B client/test_windows_version.py -v
git diff --check
```

- Linux baseline: **19 run, 18 passed, 1 expected dpkg skip**: [log](<.build-support/package-hardening/tests-linux-windows.log>).
- Linux/release hardening: **13/13 passed**, including 12 actual Linux-step import/local success/failure combinations: [log](<.build-support/package-hardening/tests-hardening-windows.log>).
- PE: **4/4 passed**, known real fixture enabled: [log](<.build-support/package-hardening/tests-pe-windows.log>).
- Client prerequisite suite: **9/9 passed**, including real copied cached PE -> ZIP: [log](<.build-support/package-hardening/tests-client-windows.log>).
- Every final command above returned **0**. No skips in PE or Client suites.

The Windows release test parses the full production script and AST-extracts its actual functions unchanged. Only its disposable test process shadows the platform flag to enter the local-copy branch; `sh` build execution is stubbed. Capture, source checking, DEB/tar parsing, production copy/gate/publication statements, and positive `Add-Artifact` accounting are exercised. The test also injects explicit capture/second-copy failures. No top-level release script or build/publishing pipeline is run.

Debian inputs, source copies and `TMPDIR` are exclusively under `/srv/archives/agent-package-hardening-20261105`; no install or root-volume build cache. Commands after copying the scoped test inputs:

```sh
cd /srv/archives/agent-package-hardening-20261105/source
TMPDIR=/srv/archives/agent-package-hardening-20261105/tmp PYTHONDONTWRITEBYTECODE=1 python3 -B tooling/cross-platform/test_linux_provenance.py -v
TMPDIR=/srv/archives/agent-package-hardening-20261105/tmp PYTHONDONTWRITEBYTECODE=1 python3 -B tooling/cross-platform/test_package_hardening.py -v
```

Both return **0**: baseline **19 run / 18 passed / pwsh-only skip**; hardening **13 run / 12 passed / pwsh-only skip**. Genuine `dpkg-deb -Zxz` built tiny Full and Client fixtures which production packagers successfully gated; no package installed: [Debian log](<.build-support/package-hardening/tests-debian.log>).

## Remaining boundaries

All five reviewed findings are addressed within the assigned packaging scope. Per-file publication renames are atomic, **not** an atomic two-file transaction; a rename/I/O failure after the first successful publication can still expose a mixed pair. Capture/copy/gate failures occur before either final is touched. Future artifacts exceeding the documented limits require deliberate policy review.

No final Flutter/Go/native build, executable launch, package installation, runtime/VPN/driver acceptance, host-network change, policy bypass, server/Dart/native/CI change, publication, main merge or push. Fresh compiler output is required when a cached VERSIONINFO allocation is too small. Version/resource integrity does not prove compiled-code provenance. Parent integration must recapture source and rebuild/gate final packages after integrating its other changes; this base's provenance snapshot is not reusable for changed source.

Evidence is intentionally uncommitted under [.build-support/package-hardening](<.build-support/package-hardening/>); source/tests/report are the local deliverables. All owned background jobs were collected before handoff.
