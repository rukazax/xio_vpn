# Server contract S1/S2 candidate — 2026-11-05 UTC

Base: `3da0535d96b3c139ddad2b80b7fc8b457f30a6a6`. Exclusive worktree/branch `agent-server-contract-fixes-20261105`. Candidate only: independent parent/reviewer acceptance is required.

## Bounded changes

- [admin.py](../../../server/managed/admin.py): shared decoded nonzero 32-byte admission for generic/static add. Incoming keys are canonicalized; all existing server/user keys (including revoked and cross-protocol history) are compared by decoded identity. Duplicate/malformed registry is rejected before effects, without rewriting, deleting or rotating existing material. Revoke uses the same registry guard before stats/persistence/removal; ordinary valid revoke and repeat remain supported. Inspect/status behavior is unchanged.
- [admin.py](../../../server/managed/admin.py): static AWG profile is fully preflighted/rendered before adding a registry record or save/apply. Uses existing dualstack native schema/identity/TTL validation, desired families, and same connector/revision resampling. All selected AWG families must be ready; DNS is restricted to those families. Ordinary native profiles retain BOTH default captures, including when only one inner family is selected. Outer endpoint IP family and host main IPv6 route do not override native intent.
- API compatibility boundary: `ipv6Only=true` under native opt-in now explicitly fails before effects, rather than permitting IPv4 DIRECT escape. With native opt-in absent, legacy default behavior is preserved; explicit legacy IPv6-only requires usable IPv6 and emits only IPv6 DNS/capture.
- [test_admin.py](../../../server/managed/test_admin.py): replace invalid placeholder server key with a synthetic valid key; static legacy tests mock observations rather than probing the host.
- [test_admin_contract.py](../../../server/managed/test_admin_contract.py): pure AST-extracted actual admin functions plus actual dualstack validators. Persistence/render/statistics and UAPI transport are mocked, not admission/profile rendering/apply. Provider evidence is fixture-only. No real keys or sensitive profiles are logged.

## Verification

The final 15 focused tests were run unchanged against both base admin and candidate. Baseline uses a separate UTF-8 export of `git show 3da0535:server/managed/admin.py` plus unchanged dualstack and final focused test file, not a reset or another worktree.

- [Baseline](before-final.txt): exit **1**, 15 methods, **35 failed subcases, zero errors**. Expected failures establish key alias/zero/server/within-request admission, existing registry ambiguity, native static DNS/readiness, IPv6-only, and profile observation ordering defects. Positive compatibility/auth tests also run.
- [Fixed focused suite](after.txt): exit **0**, **15 passed** on bundled Windows Python, `-B -m unittest discover -s server/managed -p test_admin_contract.py -v`.
- [Linux full managed suite](managed-after.txt): exit **0**, **222 tests: 221 passed, 1 skipped**, **111.240 s**; original 207 plus 15 new focused methods. Final exact source/tests verified **2026-11-05T21:10:42Z**. Executed only in `/srv/archives/agent-server-contract-fixes-20261105/src`, with TMPDIR and XDG_CACHE_HOME under the same owned scratch root. [Runner](run-managed.sh) captures the actual Python exit code. No installs/downloads or host network/service/TUN mutation.
- [SHA-256 manifest](hashes.txt) binds source/tests and retained logs. Local and transferred Linux bytes matched for all three changed source/test files (`sha256sum` vs `Get-FileHash`). Debian Python **3.13.5**. `git diff --check`: exit **0**.

Linux replay: transfer `server/managed` and `server/catalog` to the owned `src` directory, then run `sh /srv/archives/agent-server-contract-fixes-20261105/run-managed.sh`. All tests use synthetic/mock state; the suite's optional real private kernel test remains skipped without explicitly opted-in private network+mount namespaces.

## Explicit limits / not closed

Readiness is a validated **pre-effect snapshot**, not a guarantee that its TTL survives apply or profile delivery, and not a live data-plane/DNS reachability test. There is no post-effect reobservation/reprobe or new blind revoke path. Existing add/apply rollback semantics and parent-owned full owner/user durability and unknown outcomes are NOT claimed fixed.

Optional third-party CLI local output-existence prevalidation was not changed; its post-remote-add conflict behavior remains a separate follow-up. No WebUI S3, MTProto S4, native module/backend, app/UI/Dart, artifacts/mirrors/build metadata/version/publication, host networking, phone/VPS or SAC changes. This is not release acceptance.
