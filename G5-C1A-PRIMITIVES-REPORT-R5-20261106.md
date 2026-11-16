# G5 C1a — R5 forward-fix report

**Status:** forward repair of the sealed `04d24fa` findings, same passive new-file surface. Author-green only, **not acceptance**. No integration, live CA/native/ASN.1/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held predecessor | `04d24fa5e9336a745de26c7b47a80ba4ba396db2` (preserved) |
| Prior reports | R1–R4 reports preserved |
| Fix commit | `6c72c37d63fc36f05ea95b68efec521ba9e9d585` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Surface | no existing file modified; only primitive, tests and revision reports |

## 1. R5-B1 — strict raw new-row identity

The selected fake index row is now a strict, finite six-field encoding: `status`, `expiry`, `revoked`, `serial`, `file`, `subject`.

- Exactly six tab-separated fields; no seventh/extra column.
- Status exactly `V|R`; expiry exact `300101000000Z`; revoked empty exactly for V and `261106000000Z` exactly for R; serial canonical positive hex; file exactly `unknown`.
- Subject exactly `/CN=<row.cn>` with full equality, strict UTF-8 decode (no replacement). A raw CN equal to the UID plus suffix, multiple CN components, or invalid UTF-8 no longer matches.
- Raw must be non-empty with exactly one final LF and no CR/NUL/blank/extra line. CRLF, missing final LF and extra empty lines are rejected.
- Every line is bound to its corresponding `IndexRow` (not count-only). The complete old raw prefix hash remains preserved; target must be the exact last line.
- This is the selected bounded fake format, not a claim of universal OpenSSL interoperability.

## 2. R5-B2 — exact branch manifests

- **ISSUE** requires the exact durable baseline: raw index hash, serial/counter, CRL and cert/staged maps exactly equal to pre-state, with no target effects. Any unrelated CA-copy/cert/staged entry repairs.
- **ADOPT** permits exactly the pre-state maps plus the one target certificate (`row.serial -> target cert digest`). If the target staged body is present, it permits exactly the one owned `staged_key -> target body`; matching staged -> `adopt`. If the target staged body is absent, no staged addition is permitted and the result is `adopt_seed_stage`, explicitly not complete. Unrelated staged paths/cert additions repair rather than being silently seeded/ignored.
- Cert map remains serial-keyed; staged map remains stage-keyed. Existing multiple immutable old rows/certs remain a positive append fixture.
- No real CA parser/ASN.1/new native transaction framework.

## 3. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| Author suite | **48/48 PASS**, exit 0 |
| Unchanged fresh R4 17 (SHA `07eb4d0a…`) | **17/17 PASS**, exit 0 |
| Unchanged fresh R3 16 (SHA `2759ce…`) | **16/16 PASS**, exit 0 |
| Unchanged 19 (SHA `d05f12…`) | **19/19 PASS**, exit 0 |
| Unchanged V2 (SHA `084ead…`) | **26/27**, only the documented pure-proposal oracle |
| `python3 -B -m py_compile` | exit 0 |
| Existing-file diff | empty |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r5-author.log`, `c1a-r5-exits.txt` (`PYCOMPILE=0`, `AUTHOR=0`), `c1a-r5-n17.log/.exit`, `c1a-r5-n16.log/.exit`, `c1a-r5-n19.log/.exit`, `c1a-r5-v2.log/.exit`.

## 4. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `d23b6ab643ef7b4ef0686b02f46f9c93c1a0ad96c45913f41cf5ff1de4fe0eb9` |
| `server/managed/tests/test_issuance_primitives.py` | `c262749cdbe2ae6b0a9225a948d8f19681ca7e6e10c5250ebf715d0807cdcfec` |

## 5. Limits / unproven

Fake X.509/index evidence and fake adapters only; no real CSR/certificate parser, OpenSSL/CA, native lease, power-cut proof, A/D journal, D caller, capability endpoint, installer/wiring or client. POSIX-owned temp roots only. `complete=false`, all issuance actions false. Mesh/grant/Store/startup/updater/authority gates remain open. This is author-green, not independent acceptance or integration.

Final candidate: the forward child commit containing this report; fix commit `6c72c37d63fc36f05ea95b68efec521ba9e9d585`. `04d24fa` and all older proof remain preserved.
