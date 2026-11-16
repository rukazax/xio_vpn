# G5 C1a — R6 forward-fix report

**Status:** forward repair of the sealed `715d67d` findings, same passive new-file surface. Author-green only, **not acceptance**. No integration, live CA/native/ASN.1/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `715d67d351c786bae540ad9c31dd83c0ee7c9b38` (preserved) |
| Prior reports | R1–R5 preserved |
| Fix commit | `86a77c2ac853d9c25c7e203a73ad57b1c1c0f3e1` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only primitive, tests and revision reports |

## 1. Central native validation

`_validate_native_evidence` now runs before **any** ISSUE, NO_EFFECT, ADOPT/seed or repair resolution. It enforces:

- `CAEvidence` type and concrete `serial`/`crlnumber` ints (bool/float/strings rejected, non-negative/bounded).
- Empty raw index only with zero rows; non-empty raw must be the selected six-field LF-only encoding with strict UTF-8 and exact `/CN` fields, and every raw line must bind to its corresponding supplied `IndexRow` by status, expiry/revocation, serial, file token and exact CN.
- Malformed raw, same-hash opaque/malformed baselines, row-count mismatches and contradictory labels are fenced before hash equality can resolve ISSUE/NO_EFFECT.

The branch rules remain explicit: ISSUE requires exact baseline maps and no target effect; ADOPT requires the exact target-only delta and stage/seed semantics; NO_EFFECT requires exact unchanged raw/counter/manifest state and no target row/body/stage.

## 2. NO_EFFECT nonempty baseline

The prior unconditional non-empty cert/stage repair is replaced by central binder + exact-manifest comparison. NO_EFFECT now permits an exact unchanged non-target non-empty baseline (old unrelated rows/certs/stages preserved byte-for-byte), while a target row/body without its row, a target staged key, or any changed/extra manifest still repairs. The positive old-unrelated baseline and negative target-without-row are candidate-owned regressions.

## 3. Explicit proof flags

`reconcile_client_issue` no longer defaults `intent_durable` or `barrier_complete`. Both are required keyword-only booleans, and `marker_present`, `intent_durable`, `barrier_complete` are checked with `type(...) is bool`; `0/1/None/"yes"` cannot become proof. `intent_durable=False` and `barrier_complete=False` retain their fences. Constructing an intent and observing `LeaseState.FREE` is not durability proof.

## 4. Fixtures and versioned outcomes

Author positive ISSUE/NO_EFFECT fixtures were updated openly from opaque `b"index"` to the selected empty/canonical baseline; no sentinel bypass was added. The original reviewer scripts and hashes remain untouched. Original runs on R6 show their API/fixture-shape outcomes honestly:

| Original suite | R6 original outcome |
|---|---|
| Fresh R5 12 (SHA `7765bc…`) | **12/12 PASS** (already explicit flags) |
| Fresh R3 16 (SHA `2759ce…`) | **16/16 PASS** (wrapper already explicit flags) |
| Fresh R4 17 (SHA `07eb4d…`) | 17 cases, 10 errors from old opaque index fixtures rejected by central validation |
| 19-interface (SHA `d05f12…`) | 19 cases, 4 errors from old opaque fixtures/strict validation |
| Old V2 (SHA `084ead…`) | 6 fixture/API-shape errors plus the known pure-proposal oracle |

Because these originals embed the deliberately superseded opaque fixtures/default flag shape, clearly versioned mechanical copies were made preserving every assertion and only (a) supplying explicit synthetic `intent_durable=True`/`barrier_complete=True` where previously omitted, and (b) mapping strict-validation `PrimitiveError` to the existing fence expectation:

| Versioned copy | SHA-256 | Result |
|---|---|---|
| `reviewer_r4_index_adapt.py` | `bef165e099928b91c4943f55a4b9acce5870db79661b0a6ea0cb854d47b96a82` | **17/17 PASS** |
| `reviewer_new_interfaces_adapt.py` | `3ca00ccc58242c876a9bc550e6e1e78d4f871b7de6d8a20e16e92f9fb39342f5` | **19/19 PASS** |
| `reviewer_adversarial_adapt.py` | `20ecc38695d1ea4d45cd944f40ca712c14a2ce8271df6eabe93ca8446dae1c4d` | **26/27**, only the documented pure-proposal oracle |

No assertion was weakened; negative expectations remain negative, and positive fixtures are canonical. This is a transparent API-shape/versioning outcome, not an all-repair green.

## 5. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite (updated canonical fixtures + new regressions) | **49/49 PASS**, exit 0 |
| Unchanged fresh R5 12 (SHA `7765bc…`) | **12/12 PASS** |
| Unchanged fresh R3 16 (SHA `2759ce…`) | **16/16 PASS** |
| Versioned 17/19/V2 adapters | 17/17, 19/19, 26/27 known oracle |
| `python3 -B -m py_compile` | exit 0 |
| Existing-file diff | empty |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r6-author.log`, `c1a-r6-n12.log/.exit`, `c1a-r6-n16.log/.exit`, original `c1a-r6-n17.log`, `c1a-r6-n19.log`, `c1a-r6-v2.log`, and adapted `c1a-r6-n17-adapt.log`, `c1a-r6-n19-adapt.log`, `c1a-r6-v2-adapt.log`.

## 6. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `c3d6bf013aa15758532b9fa542904d706d2f06dfa16b978e7b3853200380df30` |
| `server/managed/tests/test_issuance_primitives.py` | `b559f198201b7ae57c1a7d247340118cd5deaa60d89a7bd49febd7353c2c7497` |

## 7. Limits / unproven

Fake X.509/index evidence only; no real CSR/cert parser, OpenSSL/CA, native lease/power-cut, A/D journal, D caller, capability endpoint, installer/wiring or client. POSIX-owned temp roots. `complete=false`, all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This is author-green, not independent acceptance or integration.

Final candidate: the forward child commit containing this report; fix commit `86a77c2ac853d9c25c7e203a73ad57b1c1c0f3e1`. `715d67d` and all older proof remain preserved.
