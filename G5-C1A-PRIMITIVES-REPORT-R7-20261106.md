# G5 C1a — R7 forward-fix report

**Status:** forward repair of sealed `fc038a9` findings, same passive new-file surface. Author-green only, **not acceptance**. No integration, live CA/native/ASN.1/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `fc038a927811604b5b3c88815ddf83ac132ba6d4` (preserved) |
| Prior reports | R1–R6 preserved |
| Fix commit | `9b34b3c8e013c8568e962e5cfb5e0f1e2a76cd69` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only primitive, tests and revision reports |

## 1. Exact six-field grammar

- `_bind_index_rows` splits the raw line on `\t` and requires **exactly six fields before** regex/binding. A seventh field, extra tab, missing field or unsupported shape is rejected; it cannot be swallowed into `CN`.
- CN is strict UTF-8, 1–256 bytes, non-control (no TAB/CR/LF/NUL/DEL), and must equal the supplied row CN by full equality. The subject is exactly `/CN=<cn>`; old raw prefix and valid target append controls remain.
- The extra-column negative now fails at the selected field boundary (`INDEX_ROW_CN` for the pinned extra-column case).

## 2. Target identity union

Before any ISSUE, NO_EFFECT, ADOPT/seed or absence resolution, actual certificate material in **both** namespaces is classified from trusted adapter metadata:

- target if actual certificate `CN == expected target UID`;
- target if certificate `SPKI == current CSR SPKI`;
- target/owned if staged under the requested `staged_key` (body still classified by CN/SPKI).

Consequences:

- Target-CN cert with an old/different SPKI and no row ⇒ ISSUE repairs; NO_EFFECT repairs.
- Target body under another pre-existing staged key ⇒ NO_EFFECT repairs.
- Orphan CA copy with no index/target row cannot ISSUE or clear.
- Unrelated immutable old rows/certs/stages with neither target CN nor CSR SPKI and key != `staged_key` remain allowed only when exactly preserved from pre-state; the non-empty unrelated NO_EFFECT positive remains.
- Valid canonical target ADOPT (matching stage → adopt; missing stage → seed, not complete) is unchanged. A target CN with wrong SPKI repairs.

## 3. Adapter/evidence honesty

The old author adapter’s blanket `PrimitiveError → STRICT_FENCE` remains preserved only as a limited compatibility artifact; it is **not** claimed as gate proof. Validation for R7 used the pinned b9 coherent/means:

- `reviewer_r6_fresh.py` SHA `64c921…` — **26/26 PASS**
- `reviewer_17_own_r6.py` SHA `30dc42…` — **17/17 PASS**, exact-code whitelist negatives, no blanket catch
- `reviewer_19_own_r6.py` SHA `229b98…` — **19/19 PASS**, coherent canonical rows/pre+1, no catch; positive ADOPT plus specific MANIFEST_DELTA/CRL/pre-cert-loss gates reached
- `reviewer_v2_own_r6.py` SHA `a513bd…` — **26/27**, only documented pure-proposal oracle, explicit TRUE kwargs, no catch

No blanket catch is used in the candidate. No product/default flag shim.

## 4. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite (incl. new R7 union/grammar regression) | **50/50 PASS**, exit 0 |
| Pinned b9 fresh 26 (SHA `64c921…`) | **26/26 PASS** |
| Pinned b9 own 17 (SHA `30dc42…`) | **17/17 PASS** |
| Pinned b9 own 19 (SHA `229b98…`) | **19/19 PASS** |
| Pinned b9 own V2 (SHA `a513bd…`) | **26/27**, known pure-proposal oracle |
| Unchanged 12 (SHA `7765bc…`) | **12/12 PASS** |
| Unchanged 16 (SHA `2759ce…`) | **16/16 PASS** |
| `python3 -B -m py_compile` | exit 0 |
| Existing-file diff | empty |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r7-author.log`, `c1a-r7-exits.txt`, `c1a-r7-fresh26.log`, `c1a-r7-own17.log`, `c1a-r7-own19.log`, `c1a-r7-ownv2.log`, `c1a-r7-n12.log`, `c1a-r7-n16.log`.

## 5. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `1c0ee1a6116ad291429fe5930c908d254fc3c26bca2070187d00f7c2a0e50fb3` |
| `server/managed/tests/test_issuance_primitives.py` | `7aebcf2f07bf9c88fae456c06bbc887eb91e30c7d7831f6a4214a387cc7ad1fb` |

## 6. Limits / unproven

Fake X.509/index evidence only; no real CSR/cert parser, OpenSSL/CA, native lease/power-cut, A/D journal, D caller, capability endpoint, installer/wiring or client. POSIX-owned temp roots. `complete=false`, all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This is author-green, not independent acceptance or integration.

Final candidate: the forward child commit containing this report; fix commit `9b34b3c8e013c8568e962e5cfb5e0f1e2a76cd69`. `fc038a9` and all older proof remain preserved.
