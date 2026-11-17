# Android native wire delta — proposed amendment to WIRE-V2 (for parent/core sync)

Status: **implementation evidence, not an edited shared contract**. This file describes exactly what the
Android native side at `e7c9e6d` validates and returns. The parent owns any amendment to WIRE-V1/V2 and the
Dart/Go sides; treat this as the delta to reconcile, not a replacement.

Base: WIRE-V1 request-method section + WIRE-V2. Where the two already agree with this table, nothing changes.

## 1. Request fields for `policyBegin` / `policyCommit` / `policyReconcile`

Exactly these keys, no more, no fewer (unknown key ⇒ `POLICY_INVALID`, missing key ⇒ `POLICY_INVALID`):

| field | type | Android rule |
|---|---|---|
| `version` | integer `1` | anything else ⇒ `POLICY_UNSUPPORTED` |
| `storeIdentity` | 64 lowercase hex | shape only; bound into the envelope |
| `controllerNonce` | 32 lowercase hex | shape only; bound into the envelope |
| `instanceNonce` | 32 lowercase hex | must equal the *current* `policyCapabilities.instanceNonce`; an earlier engine lifetime ⇒ `POLICY_STALE` |
| `transactionId` | 32 lowercase hex | never reused for different content (retired after settle) |
| `expectedGeneration` | 32 lowercase hex or `null` | exact CAS (see §3) |
| `planGeneration` | 32 lowercase hex | random per publication; not derived from the plan |
| `plan` | schema-2 plan object | strict per WIRE-V2 §1; `routing` is **required non-null** on Android |

`policyAbort` is exactly `{version:1, instanceNonce:<32hex>, transactionId:<32hex>}`: all three are required,
missing/unknown/type-invalid keys are `POLICY_INVALID`, a non-current `instanceNonce` is `POLICY_STALE`. Abort
of an unknown transaction is a no-op response (`state` reflects the journal), never an error that implies
released ownership.

## 2. Success ACK shape (all three ACK-producing methods)

```json
{"version":1,
 "instanceNonce":"<current engine nonce>",
 "controllerNonce":"<from the reservation>",
 "transactionId":"<from the reservation>",
 "planGeneration":"<from the reservation>",
 "state":"pending|ready"}
```

This is exactly the WIRE-V1 six-field ACK. `storeIdentity` is **not** repeated in the ACK (it is available in
`policyState`); `writePhase` is not returned (the Dart-side document writer owns `committed` /
`renamedNativeUnconfirmed` / `pendingUnknown` reporting; native `policyState.phase` reports
`pending` / `pendingUnknown` / `ready` / `blocked` / `absent`).

`policyBegin` ACKs `state:"pending"` only after the PENDING envelope is durably committed.
`policyCommit`/`policyReconcile` ACK `state:"ready"` only after the READY envelope is durably committed **and**
the stored document/receipt/digests/routing/priority/selection re-derivation succeeded (§4).

## 3. `expectedGeneration` and the pending-recovery cut

| current native state (same process) | `policyBegin` | `policyCommit` | `policyReconcile` |
|---|---|---|---|
| absent / blocked (`expectedGeneration` must be `null`) | allowed | n/a | allowed |
| ready with generation G (`expectedGeneration` must be `G`) | allowed | n/a | allowed |
| persisted `pending`/`pendingUnknown` after process restart (no live writer) | `POLICY_BUSY` | n/a | **allowed only with `expectedGeneration:null`** |
| same-process reservation outstanding | `POLICY_BUSY` | only the same transaction/generation/plan | `POLICY_BUSY` |
| a non-null `expectedGeneration` while native is not ready | `POLICY_STALE` | n/a | `POLICY_STALE` |

A crash after the pending ACK therefore recovers through `policyReconcile(..., expectedGeneration:null)` only;
a fresh `policyBegin` or a generation CAS cannot silently replace the unfinished publication. A failed
`commit()` in the same process keeps the reservation owned: the app may retry the **same** `policyCommit`
(idempotent content) or abort; a new transaction is `POLICY_BUSY` until the lane settles.

### Supported liveness for "pending ACK, crash before the app rename"

Because every READY now requires its durable receipt, that exact crash cut cannot be reconciled directly
(there is no receipt yet for the dead transaction). The supported, public-RPC-only sequence is:

1. `policyReconcile` for the dead publication (`expectedGeneration:null`) is **refused** with `POLICY_STALE`,
   and native must leave a **durable BLOCKED** envelope (it replaces the persisted PENDING one; the physical
   ticket is released only after that receipt is durable). `policyState.phase` becomes `blocked`.
2. `policyBegin` with a **new** `transactionId`/`planGeneration` and `expectedGeneration:null` is now allowed
   (before the blocked receipt, it is `POLICY_BUSY`).
3. The app performs its own owned publication: it writes the frozen document with the **new**
   `connectionPlanReceipt`, then calls `policyCommit` for the same transaction/generation/plan. Native
   re-derives the receipt + digests + routing + priority + selection and ACKs READY.
4. Tile/native capture then validates the pair and admits candidates.

If the BLOCKED receipt write itself fails (`commit()==false`), native stays `pendingUnknown`/owned and
`policyBegin` remains BUSY; `policyAbort(deadTransactionId)` retries the blocked reconciliation. No manual
preferences deletion and no native document write is ever required. `RecoveryLivenessTest` exercises the whole
sequence.

## 4. Commit/reconcile precondition (no "mode confirmed" ACK for mismatched state)

Before writing READY, native re-reads and compares against the proposal:

1. `connectionPlanReceipt` must exist and match `transactionId` + `planGeneration` + canonical plan, for
   **both** `policyCommit` and `policyReconcile`. An absent receipt stays blocked: an ACK without it would
   create a READY state that the boot validator rejects. Establishing a receipt is the app's owned publication
   (native pending → app writes the frozen document with a NEW receipt → reconcile validates the same
   plan/transaction/generation → ready); native never writes the document.
2. `connectionPolicy` key must exist and its `mode` must equal `plan.policy.mode`.
3. `selectedId` equals the document `selected`.
4. `site`, `siteCheckEnabled`, `protocolTimeoutSeconds`, `priorityProtocol` equal the document values.
5. Stored canonical routing (`routingGet` values) equals `plan.routing`.
6. Every `ids` profile exists with the same protocol/endpoint and eligible account, and the SHA-256 of its
   exact `ConfigVault` string equals `profiles[].configDigest`.

Any failure ⇒ `POLICY_STALE` (or `POLICY_INVALID` for a malformed/absent marker), the proposal is revoked to a
durable BLOCKED envelope, and no ACK is returned.

## 5. `policyCapabilities` / `policyState` shape

```json
{"version":1,"instanceNonce":"<32hex>","state":"ready|pending|blocked","resourceState":"clean|owned|unknown"}
```

`state:"ready"` also covers "no envelope yet" (`resourceState:"clean"`), i.e. a first publication is allowed.
`resourceState:"owned"` means a reservation/write exists; `unknown` means the persisted envelope could not be
parsed.

```json
{"version":1,"instanceNonce":"<32hex>","state":"ready|pending|blocked|absent",
 "phase":"absent|pending|pendingUnknown|ready|blocked","resourceState":"clean|owned",
 "storeIdentity":"<64hex|null>","controllerNonce":"<32hex|null>",
 "transactionId":"<32hex|null>","planGeneration":"<32hex|null>",
 "receipt":{...}|null,"pendingTransaction":"<32hex|null>","error":"<string|null>"}
```

`receipt` is non-null only when `readyForAdmission()` (confirmed durable READY, no outstanding writer). It is
the exact six-field activation attachment `{version, storeIdentity, instanceNonce, controllerNonce,
transactionId, planGeneration}` built with the current engine nonce.

## 6. Minimal JSON fixtures (copy-paste for Dart/Go tests)

Capabilities (clean, nothing published):

```json
{"version":1,"instanceNonce":"66666666666666666666666666666666","state":"ready","resourceState":"clean"}
```

Begin request:

```json
{"version":1,
 "storeIdentity":"4444444444444444444444444444444444444444444444444444444444444444",
 "controllerNonce":"55555555555555555555555555555555",
 "instanceNonce":"66666666666666666666666666666666",
 "transactionId":"11111111111111111111111111111111",
 "expectedGeneration":null,
 "planGeneration":"22222222222222222222222222222222",
 "plan":{"schema":2,
   "selectedId":"awg1",
   "ids":["awg1","xr1"],
   "profiles":[
     {"id":"awg1","protocol":"awg","endpoint":"203.0.113.9:51820",
      "configDigest":"39f8033617d67670c707dde7332ad7e616ef4902d4b7e6cf797e102af1611389"},
     {"id":"xr1","protocol":"xray","endpoint":"example.invalid:443",
      "configDigest":"c40bb489a48a897507a8a486f6403b631ed8b518d9077a7a9102058cfc2c9542"}],
   "routing":{"mode":"all","packages":[],"networks":[],"domains":[]},
   "priorityProtocol":"xray",
   "policy":{"mode":"automatic","roundMillis":30000},
   "site":"https://youtube.com","siteCheckEnabled":false,"timeoutSeconds":15,
   "roundMillis":30000,"clientOnly":false,
   "consentRevision":"2026-10-18","vpnDisclosure":"2026-10-18"}}
```

Begin ACK:

```json
{"version":1,"instanceNonce":"66666666666666666666666666666666",
 "controllerNonce":"55555555555555555555555555555555",
 "transactionId":"11111111111111111111111111111111",
 "planGeneration":"22222222222222222222222222222222","state":"pending"}
```

Commit request: the same object as begin (same four identity fields and the same `plan`), with
`expectedGeneration` unchanged. Commit ACK: same six fields with `"state":"ready"`.

Pending-recovery reconcile request after a crash: `transactionId` **new**, `planGeneration` **new**,
`expectedGeneration:null`, and the plan that the durable document now describes.

Abort request (exactly these three fields):

```json
{"version":1,"instanceNonce":"66666666666666666666666666666666",
 "transactionId":"11111111111111111111111111111111"}
```

Abort response:

```json
{"version":1,"state":"blocked","transactionId":"11111111111111111111111111111111"}
```

Error envelope (existing platform/HTTP envelope; the code carries the meaning and never implies rollback):

```json
{"code":"POLICY_STALE","message":"Policy receipt does not match the committed plan"}
{"code":"POLICY_BUSY","message":"Connection request outstanding"}
{"code":"POLICY_UNSUPPORTED","message":"The app must finish saving the connection policy first"}
{"code":"POLICY_PERSISTENCE","message":"Policy publication did not complete"}
{"code":"POLICY_INVALID","message":"plan.routing: required on Android"}
{"code":"POLICY_UNKNOWN","message":"Connection policy is not ready (pending)"}
```

Persisted envelope (native-private `xio.policy`; shown only so tests can model restarts):

```json
{"schema":1,"phase":"ready",
 "storeIdentity":"4444…","instanceNonce":"6666…","controllerNonce":"5555…",
 "transactionId":"1111…","planGeneration":"2222…","expectedGeneration":null,
 "plan":{...schema-2 plan...},"reason":null}
```

Durable document minimum that native boot/Tile validation needs (extras are ignored only if they are not
admission fields; unknown top-level keys are rejected):

```json
{"schema":2,
 "profiles":[{"id":"awg1","name":"awg1","protocol":"awg","endpoint":"203.0.113.9:51820"}],
 "users":[],
 "legalRecord":{"revision":"2026-10-18","timestamp":"2026-11-06T07:00:00.000Z",
                "textSha256":"<64hex>","language":"en"},
 "vpnDisclosure":"2026-10-18",
 "selected":"awg1",
 "priorityProtocol":"xray",
 "checkSite":"https://youtube.com","siteCheckEnabled":false,"protocolTimeoutSeconds":15,
 "splitDomains":[],
 "connectionPolicy":{"mode":"automatic","roundMillis":30000},
 "connectionPlanReceipt":{"schema":1,"transactionId":"1111…","planGeneration":"2222…","plan":{...same plan...}}}
```

`connectionPolicy` and `connectionPlanReceipt` are both **required** for a versioned READY plan; their
absence (together with no native envelope) is the only legacy-automatic shape. A versioned document with a
missing receipt is `POLICY_UNKNOWN` at boot and `POLICY_STALE` at publication.

## 7. Open points for the parent/core (not silently decided here)

1. **Resolved by parent:** abort is exactly `{version, instanceNonce, transactionId}`, all required; no
   transactionId-only form (implemented).
2. **Resolved by parent:** READY (commit and reconcile) always requires the matching durable
   `connectionPlanReceipt`; a missing receipt stays blocked and is never treated as consistent. Native never
   writes the document. The crash pair is covered by `BootTileAdmissionTest`: pending-ACK death before the app
   rename => `POLICY_STALE`/blocked; after the app's owned rename writes the new receipt => the same reconcile
   proposal validates. No recovery bypass was added.
3. **Resolved by parent:** `policyState` may expose `phase`, `error`, `pendingTransaction` as documented optional
   diagnostic fields (finite codes, no secrets); they must not appear in the ACK, and core must add them to the
   allowed response schema instead of ignoring arbitrary unknown fields (implemented: ACK is the six WIRE-V1
   fields).
