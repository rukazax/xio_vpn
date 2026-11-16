# G5 C1a — R4 forward-fix report

**Status:** forward repair of the sealed `4708c24` findings, same passive new-file surface. Author-green only, **not acceptance**. No integration, publication, production wiring, real CA/native/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `4708c24d133c38e6f57d9e3d12a891a27a0277e2` (preserved) |
| Prior reports | `...REPORT-20261106.md`, `...R2...`, `...R3...` preserved |
| Fix commit | `75ea4e282f9db661cf840198555ce4b94056a6ab` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only the authorized primitive, tests and revision reports |

## 1. Four findings

**Index/proof on ISSUE and ADOPT (R3-B1).** Branches are now explicit and non-overlapping.

- **ISSUE** is a fresh native authorization, not a delta: it requires the exact durable pre-index hash, pre serial/counter, CRL and cert/staged manifests, and no target row/body/staged effect. It does not require `old_rows + target`. Marker-absent index/serial drift therefore repairs.
- **ADOPT** requires exactly one target append: the target row must be the last parsed row and last raw index line; the raw prefix after removing that line must hash to the durable pre-index. This binds all old rows/their full raw bytes by hash without a new pre-row manifest or real parser. Old R-row DROP/REVIVE, reorder, extra row or serial jump repairs. It never returns `issue` for an already observed append.
- **NO_EFFECT** remains exact raw-index/CRL/cert/staged equality; **REPAIR** is the remaining branch.
- The raw index is bounded (≤65536 bytes, 1024-byte lines, one line per parsed row, canonical newline structure). The proof fits the existing `pre_state.indexSha256`/intent cap; no new 128-row schema and no claim that all per-field maxima fit simultaneously. No real ASN.1/OpenSSL parser is used.

**Serial/counter (R3-B2).** Native serial is canonical hexadecimal. Adoption requires `issued_row.serial == preSerial` and `current_counter == preSerial + 1`, not merely `current > issued`; issue requires `current == preSerial`. Fixtures distinguish decimal values from canonical hex spelling. No serial reservation, counter rewrite or bootstrap/revoke intent is introduced.

**Current authority (R3-B3).** `Principal` is validated as a closed shape before grant: role exactly `owner|delegate`, `revoked` exactly bool, owner UID exactly `None`, delegate UID exactly 32-hex and `record.actor` non-null/32-hex. Invalid role/UID/type returns `AUTHORITY_INVALID`; invalid current authority cannot authorize through `None == record.actor`.

**Link conflict (R3-B4).** `FileExistsError` is a known target conflict only when publication did not occur. After a successful hard-link publication, any later `FileExistsError` is `uncertain` (or `CLEANUP_RESIDUE` when owned-temp cleanup fails). The published target/competitor is never deleted.

## 2. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite (including new R4 regressions) | **48/48 PASS**, exit 0 |
| Unchanged 19-interface suite (SHA `d05f12…`) | **19/19 PASS**, exit 0 |
| Unchanged fresh R3 suite (SHA `2759ce…`) | **16/16 PASS**, exit 0 |
| Unchanged V2 (SHA `084ead…`) | **26/27**, only the documented pure-proposal oracle conflict |
| `python3 -B -m py_compile` | exit 0 |
| Existing-file diff | empty |

The old V2 `test_current_snapshot_cancel_cannot_be_lost` still expects the pure helper itself to reject a stale proposal; that is the documented oracle conflict, not a product failure. The adapted candidate-owned guarded-commit case and the unchanged fresh suite verify the actual commit rejection, no write and preserved cancel. No lineage/input mutation was reintroduced.

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r4-author.log`, `c1a-r4-exits.txt` (`PYCOMPILE=0`, `AUTHOR=0`), `c1a-r4-n16.log/.exit`, `c1a-r4-n19.log/.exit`, `c1a-r4-v2.log/.exit`.

## 3. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `8865b7d0da3ad519a016d9bc6d38b60743b889e8646d17e013f741b01d4733cb` |
| `server/managed/tests/test_issuance_primitives.py` | `441bab323e6873e06ebee0eb58b53dddaa77b7d43949a920e380ddaccac4e3f2` |

## 4. Limits / unproven

Fake X.509/index evidence only; no real CSR/certificate parsing, OpenSSL/CA, native lease, power-cut proof, A/D journal, D caller, capability endpoint, installer/wiring or client integration. POSIX-owned temp roots only. `complete=false`, all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This is author-green, not independent acceptance or integration.

Final candidate: the forward child commit containing this report; fix commit `75ea4e282f9db661cf840198555ce4b94056a6ab`. `4708c24`, `591f785`, `aaa389` and all older proof remain preserved.
