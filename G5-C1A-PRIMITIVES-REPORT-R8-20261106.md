# G5 C1a — R8 forward-fix report

**Status:** minimal forward repair of sealed `bcc0a47` finding, same passive new-file surface. Author-green only, **not acceptance**. No integration, live CA/native/ASN.1/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `bcc0a47caae75e023ffa5f2f047c3e0f381e21bf` (preserved) |
| Prior reports | R1–R7 preserved |
| Fix commit | `0cb3d23423de35a6dbf83d0d92d20fec4fefa3fe` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only primitive, tests and revision reports |

## 1. Staged raw-byte binding

For every `evidence.staged` body, before any use of `info.cn`, `info.spki_der` or the stage key:

```text
info = adapter.certificate_info(body)
require info.digest == SHA256(body)   # existing finite CERT_DIGEST fence
```

- A stale/inconsistent verifier result cannot make a staged body appear unrelated; it cannot authorize ISSUE, NO_EFFECT_CLEAR, `adopt` or `adopt_seed_stage`.
- Adapter exceptions continue to fence as unknown target material.
- Correct-digest foreign/unrelated staged bodies remain allowed in an exact unchanged baseline; the positive issue/no-effect/seed paths remain.
- Existing cert-body digest binding and owned-stage ADOPT digest check are unchanged. No new framework/schema/crypto/parser/cleanup/live change.

## 2. New own regression

`test_r8_staged_digest_bound_before_identity`:
- Correct-digest foreign stage at `old-stage` still permits ISSUE (marker absent) and NO_EFFECT_CLEAR (marker present).
- Same body with inconsistent `info.digest` raises the finite `CERT_DIGEST` fence instead of resolving either path.

## 3. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite | **51/51 PASS**, exit 0 |
| Pinned R7 fresh 12 (SHA `e10532…`) | **12/12 PASS** |
| Pinned R6 fresh 26 (SHA `64c921…`) | **26/26 PASS** |
| Pinned prior 12 (SHA `7765bc…`) | **12/12 PASS** |
| Pinned prior 16 (SHA `2759ce…`) | **16/16 PASS** |
| Pinned coherent own 17 (SHA `30dc42…`) | **17/17 PASS** |
| Pinned coherent own 19 (SHA `229b98…`) | **19/19 PASS** |
| Pinned explicit-proof V2 (SHA `a513bd…`) | **26/27**, only documented pure-proposal oracle |
| `python3 -B -m py_compile` | exit 0 |
| Existing-file diff | empty |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r8-author.log`, `c1a-r8-exits.txt`, `c1a-r8-fresh12.log`, `c1a-r8-fresh26.log`, `c1a-r8-n12.log`, `c1a-r8-n16.log`, `c1a-r8-own17.log`, `c1a-r8-own19.log`, `c1a-r8-ownv2.log`.

No blanket catch is used in the candidate; no negative-only green. The old author adapters remain only limited compatibility artifacts and are not cited as gate proof.

## 4. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `7f4cf87bef45d311be806c78a95637ff7840386e33ac11c569b6ba667aff5c8d` |
| `server/managed/tests/test_issuance_primitives.py` | `c8461e26bc4227658d2083517c06da10ffd93be11ddc8443e427db7b63c46a1b` |

## 5. Limits / unproven

Fake X.509/index evidence only; no real CSR/cert parser, OpenSSL/CA, native lease/power-cut, A/D journal, D caller, capability endpoint, installer/wiring or client. POSIX-owned temp roots. `complete=false`, all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This is author-green, not independent acceptance or integration.

Final candidate: the forward child commit containing this report; fix commit `0cb3d23423de35a6dbf83d0d92d20fec4fefa3fe`. `bcc0a47` and all older proof remain preserved.
