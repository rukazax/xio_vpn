# Native shipping wiring — 2026-11-05 UTC

Branch: `agent/native-shipping-20261105`; base: `5b38a20ae734051f275d5ed22e8cc320f48824d5`.

**Historical original implementation evidence (commit `28192d9`). Independent review subsequently found P2 rollback ownership failure; see [the corrective follow-up](<NATIVE-SHIPPING-P2-20261105.md>). Original hashes/results below describe that original revision, not independent acceptance of the current shipping branch.**

**Implementation/test handoff, not release completion.** No authoritative assets, generated server mirrors, bindings, source-hash metadata, or versions were changed. Native core/lifecycle/RPC source files were not edited.

## Implemented contracts

- [Packager](<tools/package-server.py#L29-L55>): explicitly includes all three mandatory native modules as flat members. Missing/non-regular/linked sources or linked parents fail closed, without falling back to old assets. Existing pinned native input verification, LF payload normalization, archive verification, atomic artifact publication and manifest-last format remain intact. No `fullSourceManifest` or other metadata format was altered.
- [Canonical bootstrap](<server/managed/bootstrap.sh#L69-L82>): validates **all three** source/destination paths before the first native replacement, then chmods staged modules to `0600` and uses same-filesystem atomic moves into the managed library. Invalid/missing sources, directories and live/dangling destination symlinks refuse installation. This preserves the existing **per-file** atomic installer contract; it does not claim bootstrap-wide rollback.
- [Updater](<server/managed/update.py#L135-L168>): adds the three modules to its completeness **minimum**, not a whitelist. Valid optional flat Python members remain accepted and transactional.
- Actual app contract inspection found [the app sends the entire archive](<app/lib/managed_service.dart#L168-L184>) without projection. The producer already ships `catalog/` and `cascade/`, while the prior updater admitted only `xio_vici/`. Parent explicitly authorized a bounded layout correction: exactly those three two-level roots now accept regular members, with canonical spellings and existing size/digest/duplicate/link/traversal bounds. Unknown roots, deeper paths, aliases, absolute names and non-regular entries still refuse before maintenance.
- All accepted ancillary content stays inside the updater's **managed-library transaction**, mode `0600`; it is not deployed to systemd, sysctl, tmpfiles, sbin or catalog state paths. Existing per-file backup/atomic replacement and STATE-last commit semantics remain unchanged. [Rollback cleanup](<server/managed/update.py#L307-L377>) removes only newly created, identity-matching, still-empty directories; no recursive deletion. Concurrent foreign content leaves its directory intact.
- Installing these Python support files never invokes them, activates native lifecycle units, enables cascade/native capture, probes, or restarts Rootnet. Existing unrelated bootstrap behavior (readiness/catalog and legacy cascade handling) was not changed and was **not run** by tests. Inert updater library copies do **not** imply external catalog units/services or SNI data were refreshed.

## Tests and evidence

New [shipping tests](<tools/test_native_shipping.py>) build a complete installer tar using real canonical native3/bootstrap/updater bytes and synthetic other inputs. Existing [packager fixture](<tools/test_package_server.py#L15-L20>) and [update fixture](<server/managed/test_update.py#L14-L26>) were narrowly extended to the new required set; validators were not weakened.

| Verification | Result |
|---|---|
| Native wiring baseline, production sources still unfixed | Expected exit 1: 5 tests, 20 failing subcases and 1 missing-member error; [log](<evidence/before-corrected.log>). Missing modules were omitted from generated tar; bootstrap block absent; missing-native archives reached maintenance. |
| Direct complete generated installer tar, prior layout validator | Expected exit 1: `Invalid update archive entry`; [log](<evidence/layout-before.log>). |
| Final Debian shipping + package + update + IPv6 metadata + mocked network rollback | Exit 0: **36 tests**, including **11** focused shipping tests; [log](<evidence/full-after.log>). |
| Windows packaging portability fixtures | Exit 0: **7 tests**; [log](<evidence/windows-package.log>). |
| Debian POSIX shell/Bash parse | `sh -n` and `bash -n`, both exit 0. |
| shellcheck | Skipped: not installed; no installation/download attempted. |
| Whitespace and reserved-source diff boundary | `git diff --check`, exit 0; no diffs in app/assets, metadata, native3, AppCore or version files. |

Coverage includes actual generated archive bytes, native member SHA256/mode, archive-manifest SHA256, canonical bootstrap/updater mirror SHA256, full tar direct unpack **and** full fake update (no runtime projection), optional legacy flat member acceptance, native/auxiliary/STATE replacement failure injection, old bytes/modes restoration, owned empty-directory rollback, foreign content preservation, unsafe source/destination/parent rejection before any runtime writes or service commands, and strict full-layout negatives.

One strengthened bootstrap negative test caught a transient implementation error relying on `set -e` inside a compound condition; explicit refusal fixed it and all final cases pass. Preliminary remote command quoting and Windows scratch-directory setup errors were corrected before the recorded final successful runs. No failed development run is being presented as a pass. Committed text evidence normalizes line endings/trailing whitespace only; original remote logs remain in the owned scratch tree.

## Reproduction commands

Debian checkout snapshot and **all** its scratch/cache/tmp/output live under `/srv/archives/agent-native-shipping-20261105`; Python 3.13.5. Transfer uses `scp` of owned source directories/scripts only. No package installation, external binary download, production root, service, route or kernel mutation is involved.

```sh
# Run through ssh debian17-root; working directory:
cd /srv/archives/agent-native-shipping-20261105/src
TMPDIR=/srv/archives/agent-native-shipping-20261105/tmp \
PYTHONPYCACHEPREFIX=/srv/archives/agent-native-shipping-20261105/cache \
PYTHONPATH=tools:server/managed \
python3 -m unittest -v tools/test_native_shipping.py tools/test_package_server.py \
  server/managed/test_update.py server/managed/test_update_ipv6.py \
  server/managed/test_network_delta.py
# Final exit 0, 36 tests.
sh -n server/managed/bootstrap.sh
bash -n server/managed/bootstrap.sh
# Both exit 0.

TMPDIR=/srv/archives/agent-native-shipping-20261105/tmp \
PYTHONPYCACHEPREFIX=/srv/archives/agent-native-shipping-20261105/cache \
PYTHONPATH=tools:server/managed \
python3 evidence/record_archive.py /srv/archives/agent-native-shipping-20261105/fixture-proof
# Exit 0. Retained tar is explicitly TEST-FIXTURE-NOT-A-RELEASE.
```

```powershell
# Windows, from this worktree, precreated owned evidence/tmp and evidence/cache:
$env:TEMP=(Join-Path $PWD 'evidence/tmp'); $env:TMP=$env:TEMP
$env:PYTHONPYCACHEPREFIX=(Join-Path $PWD 'evidence/cache')
$env:PYTHONPATH=(Join-Path $PWD 'tools')
& 'C:\Users\er-ka\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe' `
  -m unittest -v tools/test_package_server.py
# Exit 0, 7 tests.
```

## Exact hashes and retained fixture

All source SHA256 values are in [source evidence](<evidence/source-sha256.json>), with matching Debian readback for the three production edits and new test. Native inputs below were **observed unchanged**, not regenerated:

| Source | SHA256 |
|---|---|
| [Packager](<tools/package-server.py>) | `db6bbff068c0d6af6507c6439c7c0a2dcb7b6e5ff08696559e40838fd5e643d7` |
| [Bootstrap](<server/managed/bootstrap.sh>) | `2509ff6458de94c691e679c1a9af79e7b7f4b3d740d2e6e64dfba9ca35a7733d` |
| [Updater](<server/managed/update.py>) | `931dd576aafa9e89c36959572db207e9e5561a75e61d0d8410fd126b0c99495f` |
| [Native core](<server/managed/cascade_native.py>) | `e16b9f63262caa9bb01a7a1e7602afa2010092baaad4d33e1bf2f3690c7c52b4` |
| [Native lifecycle](<server/managed/cascade_native_lifecycle.py>) | `ab43499fb0f5e4b2ed211dbccb7bcf42d94b1646317c47bf90346939ca8ca257` |
| [Native RPC](<server/managed/cascade_native_rpc.py>) | `dd52ff878ad8f6372737aa4c55b872bc4922b8961e27d34f3cdb0909180066d7` |

[Retained fixture proof](<evidence/archive-proof.json>) records every member hash/mode and the unchanged release-manifest structure. Fixture archive SHA256: `afee0f4e3cbedb65348d81b23c51a7c77f237f29c74e05161a61f2e215b0a056`. Real native member bytes equal source bytes here (LF), mode `0600`; bootstrap/updater mirror hashes match the table. The retained fixture is on Debian under the owned scratch `fixture-proof` directory, generated by [the evidence script](<evidence/record_archive.py>). Its other inputs/binaries are synthetic; test-only hash mocking is **not** production pin bypass or release evidence.

## Deferred / not checked

- Production native binaries are absent from this fresh worktree. Real pinned production packaging, authoritative mirror/archive/metadata regeneration and version bump remain parent-reserved after all code/finalizer integration.
- No whole bootstrap was run, on a real host or otherwise. Only the exact bounded native install block was executed against temp roots.
- No real updater maintenance, service restart, native activation, VPN connection, app build/install, phone/USB/VPS operation, systemd/sysctl/network/policy mutation, push or publication was performed. Kernel/network rollback tests use fake APIs and temp files only.
- Android/Ubuntu/Windows release integration and independent native parser/status/TTL finalization remain outside this shipping patch. Apple remains deferred. Parent must integrate, regenerate with verified pinned inputs, and perform subsequent acceptance; this handoff is not a release claim.
