# G5 C1a — R3 forward-fix report (N1–N5)

**Status:** forward repair of the independent `591f785` HOLD, same passive new-file surface. Author-green only, **not acceptance**. No integration, publication, production wiring, real CA/native/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `591f785dcba378291c673223702f4aee0a6269cd` (preserved) |
| Prior reports | `G5-C1A-PRIMITIVES-REPORT-20261106.md`, `...-REPORT-R2-...md` preserved |
| Fix commit | `7690e456890c30f177fdf29aac061423768f514a` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only the authorized primitive, tests and revision reports |

## 1. N1–N5 closure

**N1 — current authority and guarded identity.** `advance_record` now decodes the raw store bytes itself and binds raw SHA-256, UID, expected operation ID, immutable identity and revision before proposing. It requires an injected `current_principal(uid, operation_id)` read **under the same exclusion**; the caller supplies actor identity only, while current role/revocation comes from the store. A revoked/omitted current authority denies even if a cached non-revoked principal is supplied. `now` is finite non-negative int; a record at `MAX_SAFE_INTEGER` revision cannot be advanced; the generated candidate is decoded with the module's own codec before CAS. Readback remains verification, not durability proof. The hidden mutable lineage/input mutation was removed; pure `transition` no longer mutates its input.

**N2 — terminal/state monotonicity.** `reject` requires proved no-effect unless every backend is `notStarted`; `applyUnknown`, `failed`, `staged` and `appliedVerified` all require proof. `backend_applied` is monotonic: `notStarted -> staged/appliedVerified/applyUnknown/failed`, `staged -> appliedVerified`, `applyUnknown -> appliedVerified`; downgrades/clears (`applyUnknown -> notStarted`, `appliedVerified -> notStarted`) return `BACKEND_REGRESSION`. Terminal completion still requires all five backends `appliedVerified` and no cancellation.

**N3 — intent and native deltas.** `intent_durable=False` is rejected before any branch and can never issue. `intent=None` cannot issue: with a marker or existing native state it is `INTENT_MISSING`, otherwise `INTENT_REQUIRED`; empty state is not a durable baseline proof. Adoption and no-marker branches preserve the preState CRL number and every pre-existing cert/staged manifest entry; a lost/different pre-existing body is `PRE_MANIFEST_LOSS`, not adoption/no-effect. V-only rows, next-unused serial, config witness, CA/CN/SPKI/serial/digest binding remain.

**N4 — durable I/O error ordering.** Once publication (hard link) succeeded, any OSError is `uncertain`; cleanup failure reports `CLEANUP_RESIDUE`, otherwise `IO_UNCERTAIN`. Unsupported no-clobber is `failed UNSUPPORTED_NO_CLOBBER` only when temp cleanup succeeded; an unpublished OSError with failed cleanup is `uncertain CLEANUP_RESIDUE`. Owned residue is preserved; no broad deletion.

**N5 — canonical certificate representation.** Progress certificate validation now requires exact PEM armor, 64-column non-final body lines, canonical base64 decode/reencode (pad bits and line layout), exact raw-byte digest, and a positive canonical serial. This binds the injected evidence representation without real ASN.1/X.509 parsing. IKE UTF-8 bytes/printability, pre-decode base64 length cap, lone-surrogate finite error and C0 MAX-only metadata compatibility are unchanged.

## 2. V2 oracle conflict (honest report)

The old reviewer V2 is **unchanged** (SHA-256 `084ead1451fb47667364761ca97fe2bfb30b8407bcd4cdfaa5e08238edd4be36`). On R3 it is **26/27**, with exactly one anticipated failure:

- `test_current_snapshot_cancel_cannot_be_lost` asserts that the **pure** `transition(stale_record, ...)` itself returns `None` after another writer's cancel. That was a valid pre-guarded-commit regression baseline, but is no longer the accepted boundary: a pure helper may compute a stale proposal; the actual guarded commit must reject it.
- The old V2 file and history were not edited or weakened. Instead, a clearly named candidate-owned case, `test_adapted_v2_stale_snapshot_is_rejected_by_guarded_commit`, checks the post-R2 contract: pure proposal may exist, but `advance_record` with the old raw hash under current authority returns `STALE_RECORD`, does not write, and leaves the current cancelled state intact.
- All other 26 V2 assertions pass. This one failure is recorded as an intentional oracle conflict, not a product regression.

## 3. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite | **45/45 PASS**, exit 0 |
| Unchanged new interface suite (SHA `d05f12…`) | **19/19 PASS**, exit 0 |
| Unchanged reviewer V2 (SHA `084ead…`) | 26/27, one anticipated stale-pure-proposal conflict (above) |
| `python3 -B -m py_compile` module + tests | exit 0 |
| Existing-file diff | empty |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r3-author.log`, `c1a-r3-exits.txt` (`PYCOMPILE=0`, `AUTHOR=0`), `c1a-r3-n19.log`, `c1a-r3-n19.exit`, `c1a-r3-v2.log`, `c1a-r3-v2.exit`.

## 4. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `a1b3097d76b0bb42175203f622af5907a05958c0522a5e1285dbde22fb939f6a` |
| `server/managed/tests/test_issuance_primitives.py` | `b6abf2478f9d5f12fae121951f597275502920ea720ccfff747ffce794e1c347` |

## 5. Limits / unproven

Fake X.509 evidence only; no real CSR/certificate parsing, OpenSSL/CA, native lease, power-cut proof, A/D journal, D caller, capability endpoint, installer/wiring or client integration. POSIX-owned temp roots only. `complete=false` and all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This report does not claim integration acceptance.

Final candidate: the forward child commit containing this report; fix commit `7690e456890c30f177fdf29aac061423768f514a`. `591f785`, `aaa389` and all older proof remain preserved for independent rereview.
