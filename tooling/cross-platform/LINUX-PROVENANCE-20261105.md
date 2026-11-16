# Linux package provenance gate — 2026-11-05

## Scope / trace

Branch `agent/linux-package-20261105`, isolated worktree `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-linux-package-20261105`, base `a751864a38fe755018b716f6b42e6964fcac890b`. The completed Windows worktree, parent source/assets and server/cascade files were not modified.

Actual paths:

1. Full: [build-linux.sh](<../../tools/build-linux.sh>) builds the Flutter bundle, then calls [package-ubuntu.py](<package-ubuntu.py>) to create DEB and portable tar.
2. Client: [build_linux.py](<../../client/build_linux.py>) uses the isolated prepared Client app and creates both containers independently.
3. Release orchestration: Linux portions of [build-all.ps1](<../../tools/release/build-all.ps1>) either build locally or import prebuilt artifacts. Previously `Assert-DebAndTar` checked only size/magic. Imported stale files could pass without their payload being inspected.

## Gate contract / integration

New [linux_provenance.py](<linux_provenance.py>) is a stdlib-only reader: no extraction, package installation or app execution. It captures an immutable JSON digest snapshot of the **exact staged Flutter app source**, then reads the actual finished tar/DEB data container and compares its embedded bytes, not its filename.

- **Full:** whole embedded server archive SHA256, exact manifest bytes/SHA256, every artifact mirror listed in that manifest (including bootstrap/updater), complete l10n file set and individual hashes. Source capture first validates archive/manifest binding, required mirror digests, bootstrapSha256/updateSha256 bindings, archive admin/mirror consistency and actual admin/updater recipe values. Recipe is derived, not pinned to 28 in production logic.
- **Client:** complete prepared l10n file set/hashes and deliberate server exclusion. Source/bundle assets must stay in Client-only `help`, `licenses`, `l10n`, `security`, `fonts` directories. The package reader also rejects known server archive/bootstrap/updater/admin/installer/VICI payload anywhere in the container, not only the Flutter subtree. It does **not** require Full server files in Client.
- Both: reject missing/changed/extra l10n files, duplicate/unsafe paths, symlink/hardlink assets or non-directory asset ancestors, malformed/truncated DEB/ar structures and disguised container types. Unsupported compression fails closed. Packages produced here explicitly use `dpkg-deb -Zxz`, inspectable with Python 3.10+ on Windows/Linux; no new Python/native dependencies.
- Full build shell captures before Flutter. Full packager validates source/snapshot and compiled bundle before package writes, then rechecks source and **both** completed `.part` containers before renaming either final artifact.
- Client captures after intentional preparation and before Flutter (or from the explicitly selected `--prepared` tree), performs the same bundle/postbuild/source gates, and only then renames both final artifacts.
- Release local/import paths capture the current staged Full source and run the same actual-container gate on both files **before `Add-Artifact` acceptance**. Source mutation since capture also fails. Dry-run remains non-executing.
- Client Linux filenames, output directory and DEB control version now derive from that same prepared pubspec instead of stale `0.22.4`; identity/features/dependencies/architecture remain unchanged. The reviewed shared staging pin in [client/build.py](<../../client/build.py#L18-L34>) is untouched. `--prepared` deliberately treats its prepared tree as the source of truth; it is not a claim that arbitrary unreviewed staging versions are supported.

The comparison covers server payload/mirrors and l10n, not every Flutter/native compiled byte. In particular it does not reconstruct server artifacts from raw server sources or claim Dart/AOT/native code provenance. The existing server packager remains responsible for constructing the staged server payload.

## Tests / exact commands

[Regression tests](<test_linux_provenance.py>) use real tar and DEB/ar payload bytes. Fixture version `9.9.9+999` proves Client naming/control is not a replacement literal. No test executes an app binary.

Windows, from the worktree:

```powershell
python -m unittest discover -s tooling/cross-platform -p test_linux_provenance.py -v
python -m py_compile tooling/cross-platform/linux_provenance.py tooling/cross-platform/package-ubuntu.py client/build_linux.py tooling/cross-platform/test_linux_provenance.py
git diff --check
```

Result: **19 tests, 18 passed, 1 skipped** (genuine dpkg-deb fixture test requires Linux). All command exits 0. [Windows log](<../../.build-support/linux-provenance-evidence/tests-windows.log>).

The Windows suite AST-extracts the **actual** `Assert-DebAndTar`, `Read-FileHead`, `Invoke-Native` functions from the release script. It accepts matching fixtures and rejects a stale same-named DEB and stale same-named tar independently. The entire release script parses successfully through `System.Management.Automation.Language.Parser.ParseFile`.

Debian: inspected `/srv/archives/agent-linux-package-20261105` before creation (absent), created it, transferred a tiny source-only regression tar there. All fixture temporary directories use `TMPDIR` there; no root-partition build artifacts.

```powershell
ssh debian17-root 'cd /srv/archives/agent-linux-package-20261105 && tar -xf regression-inputs.tar && TMPDIR=/srv/archives/agent-linux-package-20261105 python3 -m unittest discover -s tooling/cross-platform -p test_linux_provenance.py -v > tests-debian.log 2>&1; result=$?; echo "Debian provenance suite exit: $result"; exit "$result"'
ssh debian17-root 'cd /srv/archives/agent-linux-package-20261105 && sh -n tools/build-linux.sh'
```

Result: **19 tests, 18 passed, 1 skipped** (pwsh is absent on Debian). Genuine `dpkg-deb` built tiny synthetic Full and Client fixture DEBs; production packagers then inspected those actual DEBs and matching tar files successfully. They contain placeholder executables, not rebuilt XIO. [Debian log](<../../.build-support/linux-provenance-evidence/tests-debian.log>). All command exits 0.

Regressions include good staged data, self-consistent stale recipe 27, altered archive with same recipe, manifest/bootstrap/updater/l10n byte changes, missing/extra l10n, false recipe label, source mutation during build, Client server payload exclusions, traversal/duplicates/links, wrong container, and tampering with either finished container. Both packagers fail before final output renames when a completed DEB **or** tar is altered.

## Actual published v0.24.2 cache, read-only negative proof

Read exact files in `/srv/archives/releases/v0.24.2-audit`, without modifying cache or the parent's snapshot/symlink:

- `XIO-0.24.2-ubuntu-amd64.deb`
- `XIO-0.24.2-ubuntu-x64.tar.gz`

[Audit JSON](<../../.build-support/linux-provenance-evidence/published-0242-audit.json>) records actual embedded bytes against [the base-source snapshot](<../../.build-support/linux-provenance-evidence/current-source.json>). Both containers have:

| Field | Actual cached Linux payload | Staged source at base |
|---|---|---|
| Manifest recipeVersion / inner admin.py RECIPE | **26 / 26** | 28 / 28 |
| Server archive SHA256 | `1ea3112a8a85ceda0dc667d3c3db2bca115efcf6d09037890b4c711ad18f9110` | `ae9dfdca4a1d013f18ff7d530d2f98d486ae6ddcaa4cc9a583e465c2516b2446` |
| Manifest SHA256 | `2cb0f4eb9c04fbbfb96ff071f2d2125759e48425180bd41778432030947e9ddb` | `995dece2d8944a38d7ff7ad0dedaed74db60a33fe734da8a33f5ca940f9341f1` |
| Bootstrap | matches staged source | matches |
| Updater | differs | reference |
| l10n | **all 13 files differ in BOTH DEB and tar** | exact staged reference |

This corrects the prior shorthand “recipe27 / tar-only stale translations”: this particular real cache contains recipe26, and both containers' translations differ. It does not establish which publication/build step introduced those historical bytes.

Exact direct negative CLI run on Debian (each command returns **1**, expected rejection):

```sh
cd /srv/archives/agent-linux-package-20261105
python3 tooling/cross-platform/linux_provenance.py verify --expected .build-support/linux-provenance-evidence/current-source.json /srv/archives/releases/v0.24.2-audit/XIO-0.24.2-ubuntu-amd64.deb
python3 tooling/cross-platform/linux_provenance.py verify --expected .build-support/linux-provenance-evidence/current-source.json /srv/archives/releases/v0.24.2-audit/XIO-0.24.2-ubuntu-x64.tar.gz
```

Both fail `Package asset differs from staged source: l10n/ar.json`. [DEB rejection](<../../.build-support/linux-provenance-evidence/reject-published-deb.log>), [tar rejection](<../../.build-support/linux-provenance-evidence/reject-published-tar.log>). The [read-only audit reader](<../../.build-support/linux-provenance-evidence/audit-cached.py>) additionally compared archive/manifest/bootstrap/updater/all l10n rather than stopping at the first mismatch.

Also inspected older local 0.24.1 containers read-only; both embed recipe26 and all13 l10n differ: [historical local audit](<../../.build-support/linux-provenance-evidence/cached-audit.json>). Do not confuse those with the exact v0.24.2 proof above.

## Handoff / unverified boundaries

Local evidence root: `C:\Users\er-ka\Documents\deepseek-harness\xio_vpn\work\agent-linux-package-20261105\.build-support\linux-provenance-evidence`. Remote evidence root: `/srv/archives/agent-linux-package-20261105`; remote published-cache audit log is `published-0242-audit.log`. Evidence and fixture outputs are uncommitted; only helper/integrations/tests/report are committed.

No final XIO Flutter/Go/AOT rebuild, final repackaging, installed DEB, runtime/VPN/driver acceptance, publishing, release replacement, main merge, APK operation, system/policy/security change, production/VPS/network change, macOS or iPhone work. Parent is still integrating source; final packages must be built from a **fresh** staged source capture after integration, then gated. Do not reuse this base's snapshot for changed source.

Imported DEBs using compression unsupported by the selected Python fail closed; production output is forced to xz. Inspection bounds are 128 MiB per watched asset and 512 MiB per compressed DEB data member; larger future artifacts require a reviewed limit change. Snapshot files are trusted local build inputs, not signed third-party provenance attestations. Gate acceptance cannot prove compiled native/Dart code provenance or runtime correctness. Initial release-hook fixture failure was a test stub incorrectly returning native stdout along with its exit code; replacing it with the actual production `Invoke-Native` function made both acceptance and rejection regressions pass. No production failure was bypassed.
