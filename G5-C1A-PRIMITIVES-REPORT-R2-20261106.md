# G5 C1a — R2 forward-fix report (B1–B8)

**Status:** forward repair of the independent `aaa389` HOLD, within the authorized new-file surface. Author-green only, **not acceptance**. No integration, publication, production wiring, real CA/native/SSH/network effect, A/D or capability change.

| Fact | Value |
|---|---|
| Held candidate | `aaa389276bb3149b7cf0a770df01c5737b56fa4c` (preserved) |
| Old report/fixtures | `G5-C1A-PRIMITIVES-REPORT-20261106.md`, `6b99f26` tests preserved; this is a separate revision report |
| Fix commit | `c34e36a49132d1c2b92de3e0ae79b0c736f0ae8f` |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| Base | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` |
| Unchanged surface | no existing file modified; only `server/managed/issuance_primitives.py`, `server/managed/tests/test_issuance_primitives.py`, and this report |

## 1. B1–B8 closure

**B1 — guarded commit, no proposal-as-overwrite.** Added `RecordStore` protocol (`exclusive`, `read(uid)->raw/sha/record`, `compare_and_swap`) and `advance_record`: one exclusion encloses fresh read, raw SHA-256 + revision/identity verification, transition on the fresh record, and CAS commit. A stale retained record after a concurrent cancel fails `STALE_RECORD`. `transition` remains a pure proposal and additionally carries a lineage guard so the independent stale-snapshot regression fails. New-record no-clobber and existing-record CAS update are separate primitives.

**B2 — persistent cancel/effects fence.** `cancellation.requested` is persistent and survives `repair`; backend/complete/reject paths are blocked after cancellation. `reject` requires `no_effect_proved=True` when any backend is `applyUnknown`/`failed`. `AdmissionBook.release` defaults to denied and removes a reservation only with `terminal=True` or `no_effect_proved=True`.

**B3 — reversible codec and nested authority.** `decode_record` stores the canonical camelCase request object (`json.loads(request.canonical())`), so repeated decode/encode is byte-stable. Nested `caConfig` is validated as the closed `XIO-CA-CONFIG-WITNESS-1` shape (schema/kind/configSha/mapping/options). Record commitments must match every overlapping public-request commitment; only known server material commitments may be additional. New regressions cover second roundtrip, nested unknown key, commitment mutation.

**B4 — conservative native/CA evidence.** Row status is consulted: only `V` may adopt (`R`/unknown => repair). Adoption requires the next-unused serial to be strictly beyond the issued row's serial. A durable-intent predicate (`intent_durable`) separates the constructed intent from a proven durable one. With no marker, any target row/body/staged effect => `repair` (`LEGACY_NATIVE_EFFECT`), never a fresh issue. `no_effect_clear` now requires current `certs`/`staged` manifests to equal the preState exactly; a missing/different pre-existing body is `repair`, not absence. Index/serial/CRL and config witness are checked on the no-effect branch; cert body/digest/CN/SPKI/CA/serial are checked on adoption.

**B5 — atomic no-clobber.** Publication uses `os.link(temp,target)` (atomic `EEXIST` failure) instead of check-then-`os.replace`. A competing writer's target is never overwritten; unsupported filesystems fail closed (`UNSUPPORTED_NO_CLOBBER`); failed cleanup yields `uncertain` with `CLEANUP_RESIDUE`, not broad deletion.

**B6 — fresh-session ancestry fence.** `refence_ancestry` is unconditional for every write: it fsyncs the trusted root and every existing directory down to the target parent, with no marker/flag to skip. A new `DurableWriter` instance after a predecessor's mkdir-before-parent-fsync failure re-fences the existing ancestry; the fresh-instance regression observes the root fsync. No marker format was added.

**B7 — symlink/ownership.** `_resolve` uses `lstat` on every component including the leaf and never resolves an inside-root alias; `read_bounded` additionally uses `O_NOFOLLOW`. Failed exclusive creation does not authorize cleanup; only owned temp entries are removed; cleanup failure reports owned residue.

**B8 — codec/byte hardening.** Encoded base64 length is checked against the decoded cap before `b64decode`; IKE password uses UTF-8 byte length ≤128 and printable/LF bytes; lone surrogates raise finite `NAME_UNICODE`; progress certificates require canonical PEM armor/body and a digest matching the exact bytes, while remaining injected-evidence-only (no ASN.1).

C0 metadata behavior is unchanged: MAX-only envelope parsing compatibility is preserved; no minimum-ciphertext parity was invented. The withdrawn empty-cipher metadata expectation was not treated as a bug.

## 2. Verification

Owned Debian archive `/srv/archives/agent-c1a-primitives-20261106`, Python 3.13.5 stdlib, owned HOME/TMPDIR/XIO_C1A_TEST_ROOT; bytecode disabled.

| Check | Result |
|---|---|
| `python3 -B -m py_compile` module + tests | `PYCOMPILE=0` |
| Author suite | `AUTHOR=0`, **44 tests OK** |
| Unchanged independent V2 (`reviewer_adversarial.py`, SHA-256 `084ead1451fb47667364761ca97fe2bfb30b8407bcd4cdfaa5e08238edd4be36`) | **V2=0, 27/27 OK** |
| Diff to base for existing paths | empty; only the authorized new files |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-r2-exits.txt`, `c1a-r2-test.log`, `c1a-v2.exit`, `c1a-v2.log`; V2 runs with the exact reviewer script copied byte-identically and an owned source/test tree.

## 3. Hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `aaa55825dc40d07d8efd9de734f2f70d44d6c72c7f3b99b277d890282d71c451` |
| `server/managed/tests/test_issuance_primitives.py` | `5450afcb264260d86491fbd10af2e5c4a50c8d8de8e86b07f4b55f2b9b48da73` |

## 4. Honest limits / unproven

- Fake X.509 evidence adapter only; no real CSR/certificate parsing, OpenSSL/CA, native lease, or power-loss proof. The CA evidence remains synthetic.
- No A/D journal-v2, D caller, capability endpoint, installer/wiring, or client integration; `complete=false` and all issuance actions false.
- POSIX temp-root tests only; no real filesystem power-cut or platform-specific `os.link`/`O_NOFOLLOW` universal guarantee beyond the exercised host.
- Mesh, grant, Store, startup/updater/authority writers and whole-project gates remain open. This report does not claim integration acceptance.

Final candidate: the forward child commit containing this report; fix commit `c34e36a49132d1c2b92de3e0ae79b0c736f0ae8f`. `aaa389` and its old report remain preserved for independent rereview.
