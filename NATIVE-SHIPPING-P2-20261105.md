# P2 rollback parent ownership — follow-up, 2026-11-05 UTC

Base: `28192d9aa6ba1b4ee80f8ae1de947bc4991fc111`, branch `agent/native-shipping-20261105`.

**Independent review correctly rejected the original shipping handoff on P2.** This bounded follow-up fixes the identified rollback ownership gap. Acceptance remains for the parent/independent reviewer; this is not a release-complete claim.

## Reproduced defect

The original updater checked a newly created auxiliary directory's inode only during empty-directory cleanup, **after** rollback had already restored/unlinked its member paths. A privileged concurrent rename followed by a foreign same-name directory or symlink replacement could therefore cause foreign files to be deleted or overwritten.

[Before evidence](<evidence/parent-ownership-before.log>): exit 1, one regression test with **four failing subcases**. The new test injects failure after STATE replacement, displaces either a newly created cascade root or preexisting catalog root, substitutes either a foreign directory or symlink containing the **same archive filename** and a foreign note, and observes restore/unlink attempts through the replacement. No real managed deployment was involved.

## Correction

Only [updater production code](<server/managed/update.py>) and [focused shipping tests](<tools/test_native_shipping.py>) changed; the other new/updated files are reports/evidence.

- Record directory `(st_dev, st_ino)` identities during destination preflight; record newly created auxiliary parents before backup.
- Inspect ancestors **root to leaf with `lstat`**. A non-directory/symlink, disappearance, unrecorded parent or changed identity refuses traversal before inspecting descendants.
- Validate **every backed-up target's parent chain before any rollback restore/unlink**, then validate each target again at its rollback operation. Deferred dualstack helper restore/unlink receives the same check; no networking behavior was otherwise changed.
- Check a new target is regular/not symlinked before rollback unlink. Preserve the owned, identity-matching, empty-directory-only cleanup; refuse a changed directory identity rather than silently treating recovery as complete.
- On mismatch, use the existing **owner-recovery / backup-retained** path. Retain parent identity evidence alongside the original hashes and backups. Do not restore or unlink through the foreign replacement, and do not rename or mutate the displaced old parent.

**Recovery boundary:** a parent mismatch means automatic rollback is unsafe. STATE/runtime files may remain at their post-failure state and services may require owner recovery; the result explicitly does **not** claim the old deployment was fully restored. Ordinary rollback still passes the unchanged normal suite. This is conservative identity checking at transaction boundaries, not a guarantee against an unrestricted privileged actor racing each filesystem syscall.

## Verification

- [After evidence](<evidence/parent-ownership-after.log>): **exit 0, 37 tests**, including all original 36 normal tests and the new four-case regression. All cases assert no foreign writes/unlinks, exact foreign bytes, unchanged displaced-parent file bytes/modes, unchanged symlink/directory replacement type, explicit owner recovery and retained hash/parent evidence.
- Complete generated installer unpack/update, native3 and auxiliary modes/bytes, STATE-last behavior, missing-native pre-maintenance refusal, layout fences, ordinary injected rollback and mocked network recovery all remain covered; no tests were weakened.
- [Current source SHA256](<evidence/source-sha256-p2.json>) matches independent Debian readback:
  - [Updater](<server/managed/update.py>): `30eb074ac1a3d03bcd81dc9216d0a1ecf70e65285ead3eeebf38d05c852fca10`.
  - [Shipping tests](<tools/test_native_shipping.py>): `57e1ee276e4b072ba9161627c94a992853f8b136d26fd90220e327dac7ad7977`.
- [Current fixture proof](<evidence/archive-proof-p2.json>) is separate from the historical original proof. It records the new updater mirror hash and full member bytes/modes. The retained test fixture is under `/srv/archives/agent-native-shipping-20261105/fixture-proof-p2`; it is explicitly **TEST-FIXTURE-NOT-A-RELEASE**, not a regenerated authoritative asset.

Exact main verification command, executed through `ssh debian17-root`:

```sh
cd /srv/archives/agent-native-shipping-20261105/src
TMPDIR=/srv/archives/agent-native-shipping-20261105/tmp \
PYTHONPYCACHEPREFIX=/srv/archives/agent-native-shipping-20261105/cache \
PYTHONPATH=tools:server/managed \
python3 -m unittest -v tools/test_native_shipping.py tools/test_package_server.py \
  server/managed/test_update.py server/managed/test_update_ipv6.py \
  server/managed/test_network_delta.py
# Exit 0, 37 tests, 118.862 seconds.
```

The isolated before command used the same environment and only `tools.test_native_shipping.NativeShippingTests.test_rollback_replaced_auxiliary_parent_preserves_foreign_and_displaced_files`, against the old updater: exit 1, four failures, 8.543 seconds. A later assertion additionally checks recovery parent evidence; all four original failure scenarios remain unchanged.

## Scope and deferred work

No native core/lifecycle/RPC, parser/status/TTL, AppCore, schema, pinned-source verification, manifest layout, authoritative assets/mirrors/bindings/source-hash metadata, versions or broad network logic changed. No bootstrap or real updater was run; all Linux commands/services/network operations in updater tests are fake. All new Debian scratch/cache/output remains under the previously authorized scratch root. No installs/downloads, activation, VPS/phone/USB operations, routes/sysctl/systemd mutations, push or publication.

Windows packaging and shell parsing were not rerun for this Python-only follow-up (their source files did not change); original results remain historical in [the original report](<NATIVE-SHIPPING-20261105.md>). Parent must obtain independent P2 acceptance and integrate/regenerate production artifacts later.
