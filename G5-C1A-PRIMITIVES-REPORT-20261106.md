# G5 C1a — passive issuance primitives: implementation report

**Status:** bounded implementation authorized by `G5-C1A-PARENT-IMPLEMENTATION-BRIEF-20261106.md`; author-green only, **not acceptance**. No production wiring, no live CA/native/SSH/network effect, no Dart/Flutter runtime used, no full capability advertised.

| Fact | Value |
|---|---|
| Base composition | `cd38fc8ab02d95bf04b3ffc33238304558a98e91` (accepted A + C0) |
| Branch/worktree | `slice-c1a-primitives-20261106` / `work/agent-c1a-primitives-20261106` |
| C0 branch | untouched (`agent/g5-c0-sealer-20261106`, `97a7df6`) |
| Implementation commit | `6b99f2612221f0522e53fb02f460a4068f5cf6ac` |
| New files only | `server/managed/issuance_primitives.py`, `server/managed/tests/test_issuance_primitives.py`, this report |

## 1. What was implemented

### Strict bounded codecs

- `strict_json` reads at most the caller cap, rejects duplicate keys at every object level (via `object_pairs_hook`), trailing/second values (Python JSON decoder EOF), floats/nonfinite constants, depth > 16 and total value nodes > 4096; all limits are checked before the corresponding parse/allocation.
- `parse_put_command` enforces the exact top-level shape, 32-hex uid/operationId, UTF-8 `displayName` (1–80 Unicode scalars, ≤320 bytes, already trimmed, no controls; no ASCII narrowing and no normalization), and an exact public request object.
- The ASCII canonical request contains `nameSha256` (exact UTF-8 display-name bytes) plus `publicKeys`, `admin`, `userLimit`, optional `adminPublicKey`, `protocols`, `commitments`; canonical bytes ≤8192. Raw display name is not in the canonical bytes.
- `protocols` is the actual C1a set `wireguard, awg, rivet-h3, rivet-s1, xray, shadowsocks, openvpn, cloak, ikev2`; mesh/unknown/duplicate are rejected before any effect; public keys are canonical base64(32) for exactly the selected `wireguard`/`awg` protocols; client material commitments are exactly the required `rivet.deviceSecret/entryToken`, `stack.xrayUuid`, `stack.shadowsocksKey` for the selected protocols.
- `canonical_material` freezes byte rules: decoded-32 SHA-256 for `rivet.deviceSecret`, `rivet.entryToken`, `stack.shadowsocksKey`; decoded-16 for `stack.cloakUid`; canonical lowercase UUID string for `stack.xrayUuid`; exact UTF-8/PEM bytes for `stack.ikePassword`, `stack.tlsCryptV2`, `stack.openvpnPrivateKey`, `csrPem`; canonical base64 spelling required; per-kind caps enforced.

### Capsule identity and C1 producer predicate

- `encode_capsule_plaintext` uses the accepted C0 context and payload shape, sorted keys, Dart-compatible JSON escaping, LF only in artifact values, and the selected C1 kinds `openvpn.client-key` (≤4096), `openvpn.tls-crypt-v2-client` (≤4096), `ikev2.password` (≤128), `cloak.uid` (≤32). Aggregate serialized plaintext ≤17934; adversarial quote/backslash escaping is tested. Certificate/CSR/RIVET/AWG/xray/SS are not capsule artifacts here.
- `CapsuleRef.from_raw` strictly parses the exact five-field C0 envelope, canonical base64, recipient 32, ciphertext ≤32816, raw ≤45056, and the compact C1 bound 24169; computes distinct `capsuleId`, `ciphertextSha256` (decoded ciphertext), and `envelopeSha256` (exact raw file bytes).
- `FirstPin.encode` (≤4096) and `ProgressReceipt.encode` (≤16384, public cert ≤8192) are fixed-field strict encoders; `capsule_fetch_response` is a separate response (≤61440, outer base64 ≤32228) carrying the exact raw envelope bytes, never reserialized. No truncation: over-budget returns a finite error.

### Durable write primitive

- `DurableWriter(root, faults)` requires an explicit existing owned root; no default/production root and no import-time I/O. Paths are relative, `..`/escape/symlink rejected; new parent directories are created 0700 one by one with a parent fsync after each new entry.
- Writes use an exclusive unique temp (`O_CREAT|O_EXCL`), complete write loop, file fsync, `os.replace`, target-directory fsync, then read-back. Fault cutpoints: `before_temp`, `after_temp_create`, `after_write`, `after_file_fsync`, `after_replace`, `after_dir_fsync`, `after_parent_create`, `after_parent_fsync`. Visible-but-not-durable is `uncertain`; read-back is verification, not a fence. Existing targets are never overwritten (`EXISTS`); capsule is written and durable before the record that references it; failed/uncertain record writes do not remove the capsule or evidence.

### Record/state predicates

- `Record` has immutable identity (uid/opId/deployment/request hash), public request + commitments, CSR PEM + `csrSha256`, SPKI hash, public CA config witness, capsule ref, phase/backends/revision/cancellation; strict encode/decode bounded at 131072. No raw private material field.
- `pin_capsule` enforces stale revision and first-pin immutability (`CONFLICT_CAPSULE`); `replay_operation` returns replay/conflict/cancelled/pending without quota admission.
- `transition` checks current authority before cached actions, stale CAS, terminal/tombstone immutability, cancel-requested blocking of completion/backends, and requires complete backend evidence + settled CA ownership for `cancelledConfirmed`. ACK is always refused (`ACK_TRUST_REQUIRED`, `deleted=False`).
- `AdmissionBook` models one shared view of registry (active slots, decoded key history including revoked, quota count) plus unresolved reservations for C1 and other-UID legacy admission; exact same-op replay is not re-admitted; no TTL/release except explicit `release`.

### CA intent, witness, fake evidence

- `XIO-CA-CONFIG-WITNESS-1`: compact ASCII canonical JSON `{schema,kind,configSha256,mapping,options}`; `configSha256` is SHA-256 of exact `ca.cnf` bytes; mapping is the closed actual seven-key resolved mapping and is required to resolve to `.../pki/certs` (`new_certs_dir`), not an invented `new_certs`; options are the closed supported map; `caConfigSha256` is SHA-256 of the encoded witness. Witness ≤32768 and mapping/options values are validated.
- `CAIntent` is bounded ≤32768, includes operation/uid/CSR hash/SPKI hash/CN/config hash/CA certificate hash and a bounded pre-state (`indexSha256`, serial/crlnumber + hashes, ≤128 cert body hashes, staged hashes).
- `CAEvidence` bounds ≤128 certificate entries, each body ≤8192, aggregate ≤1 MiB, index ≤65536, positive canonical serials; fake adapter is an injected Protocol (`csr_spki_der`, `certificate_info`) and is conspicuously test-only. No X.509/ASN.1 parsing or crypto is implemented.
- `reconcile_client_issue` is client-issue-only; other kinds (`bootstrap`, `server_certificate`, `revoke`, `gencrl`, `remove`) raise `UNSUPPORTED_CA_KIND` before any fake effect. It separately checks lease (`HELD`/`UNKNOWN` => fenced), barrier completion, CSR hash and adapter SPKI, actual `certs`/staged bodies, duplicate CN/bodies, missing body, serial/CRL/index drift, and returns `issue`, `adopt`, `adopt_seed_stage`, `no_effect_clear`, `repair`, or `fenced`. `no_effect_clear` is impossible with any actual cert/staged body, advanced serial/CRL, changed index, held/unknown lease or incomplete barrier. Adoption checks certificate CN, SPKI, issuer/CA hash, serial, body digest (and staged digest when present).

### Capability

- `internal_capability()`: `implementation="c1a"`, `complete=false`, `atomic=true`, `mesh=false`, `put/read/resume/needsMaterialReply/cancel/ackDelivery/readCapsule=false`, `requires=["A-D-journal-v2","D-caller"]`; encoded ≤4096. No production endpoint/dispatcher/import wiring exists.

## 2. Verification

Owned environment: Debian `root`, `/srv/archives/agent-c1a-primitives-20261106`, owned `HOME/TMPDIR/XIO_C1A_TEST_ROOT`, Python 3.13.5 stdlib only. No `/etc`, no shared cache, no production PKI, no subprocess/network.

| Check | Result |
|---|---|
| `python3 -m py_compile` module + test | `PYCOMPILE=0` |
| `python3 server/managed/tests/test_issuance_primitives.py` | `TEST=0`, **37 tests OK** |
| `git diff` to base for existing paths | empty (only new files) |
| Import-time I/O / subprocess / socket / HTTP | none (module imports stdlib only; roots are injected) |

Logs: `/srv/archives/agent-c1a-primitives-20261106/logs/c1a-test.log`, `logs/c1a-exits.txt` (`PYCOMPILE=0`, `TEST=0`).

Covered controls: duplicate/EOF/nonfinite/float/depth/node/raw caps; Unicode name/hash and canonical request; protocol/commitment/key scope; material vectors and noncanonical base64; selected capsule plaintext escaping/boundary; distinct capsule/ciphertext/raw digests; first pin/progress/capsule-fetch bounds; durable cutpoints, parent birth, overwrite refusal, capsule-first; replay/conflict/CAS/cancel/tombstone/authority; quota/slot/key reservations and no TTL; CA witness actual `certs` mapping, CSR/SPKI mismatch, lease/barrier fence, no-effect only with empty actual resources, adopt/seed, body missing/duplicate/unrelated, unsupported kinds; capability disabled; ACK refusal/no delete; record cap and no raw material.

## 3. Honest limits / unproven boundaries

- Fake X.509 evidence adapter only; no real CSR/certificate parsing or verification, no OpenSSL/CA/native call, no real lease, no power-cut/durability proof. `CAEvidence`/`CAConfigWitness` are synthetic.
- No production A/D journal-v2, no D caller, no capability endpoint, no client integration; `complete=false` and all issuance actions false. This slice is not usable recovery.
- No real filesystem durability claim beyond the injected POSIX temp-root tests; no fault-injection proof against a real power loss, no `/etc` or production roots.
- Mesh, grant, receipt/CA activation, installer/wiring, legacy authority writers, startup/updater/firewall/stats integration remain outside this slice; none is claimed fixed.
- No Dart/Flutter runtime was used; no C0 branch or accepted artifacts were modified.

## 4. Source hashes

| File | SHA-256 |
|---|---|
| `server/managed/issuance_primitives.py` | `d73aff286e359517aeabae3f726a50384b24363b5b0c485c2f350fdb8d373550` |
| `server/managed/tests/test_issuance_primitives.py` | `36d98f64ee89904125d53621b4410a9713015c7b40dfaf6a9e24a1ffc3bfd264` |

Final candidate: the forward child commit containing this report; implementation commit `6b99f2612221f0522e53fb02f460a4068f5cf6ac`. No publication/main promotion; independent review required before any integration.
