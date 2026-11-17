# Android native policy admission — worker report (in progress)

Base `c946c920f764770c62312a68d4d104c0e2dea90a`; branch `agent/policy-android-native-20261106`;
worktree `work/agent-policy-android-native-20261106`. Contract: WIRE-V1 + WIRE-V2 (schema 2), DESIGN
amendment, review conditions A–D and gates G1/G3. Android native only: no Dart, catalogue, Go/server or
provisioning changes.

## What is implemented

### One versioned native envelope (single writer)

`app/android/app/src/main/java/app/xio/xio/`:

| File | Role |
|---|---|
| `StrictJson.java` | exact-type JSON for the policy wire: no `optString/optLong/optBoolean` coercion, duplicate/unknown keys are errors, `30000.0` cannot pass as integer 30000, trailing data is an error. |
| `PolicyPlan.java` | immutable schema-2 plan: ordered `ids`, same-order `profiles[]` with `configDigest`, typed `policy`, typed `routing` (nullable only per WIRE-V2), verbatim `priorityProtocol`, C5 site/timeout/consent, `roundMillis` exactly 30000. Manual must be exactly the selection; a malformed multi-id manual plan is rejected, never truncated; protocol aliases are not accepted. |
| `PolicyEnvelope.java`, `PublicationPhase.java`, `PolicyReceipt.java` | one persisted envelope (pending / pendingUnknown / ready / blocked) with `storeIdentity`, `instanceNonce`, `controllerNonce`, `transactionId`, `planGeneration`, `expectedGeneration`, plan; six-field activation receipt including `storeIdentity`. |
| `PolicyJournal.java` | the publication lane: pending then ready ACK only after the durable boolean; `commit()==false` → `pendingUnknown`, never an ACK, never a rollback; DOWN/timeout revoke the logical owner but keep the physical ticket until a blocked receipt is durably written; exact-generation CAS; retired transactions cannot be replayed. |
| `DurableDocument.java` | strict reader of the real `filesDir/profiles.json` (schema 2): selected, profiles, users/revocation, legal record + VPN disclosure, priority, site, timeout, split domains and the committed plan receipt. |
| `DurableAdmission.java` | re-derives config digests (SHA-256 of the exact `ConfigVault` UTF-8 string), routing snapshot, `priorityProtocol`, selected identity, consent, revocation and candidate eligibility, and compares them with the plan/receipt. Any divergence is `POLICY_STALE`; malformed/unknown is `POLICY_INVALID`/`POLICY_UNKNOWN`; a missing activation receipt after versioned ownership began is `POLICY_UNSUPPORTED`. |
| `RoutingCanon.java`, `NativeProtocols.java`, `ConnectionPolicy.java`, `PolicyFailure.java` | one canonical routing snapshot (deduped, sorted, literal-only `IpRoutes`), the five exact native protocols with id-prefix consistency, the accepted 30-second budget, coded failures. |
| `LegacyPlan.java` | pre-envelope migration source: the old raw plan is admitted only as validated **legacy automatic**, and only while no envelope exists. |
| `PublicationLease.java` | extended, not reinterpreted: `idle()` still means only "no outstanding cancellation"; new policy reservation requires empty request set, no cancellation, no active publication owner, no config mutation; `begin/configMutation` reject while reserved; DOWN marks the policy ticket revoked without releasing it. |

Kotlin wiring (`main/kotlin/app/xio/xio/`):

- `PolicyBridge.kt` — SharedPreferences store for the dedicated `xio.policy` file, capabilities/state/begin/commit/reconcile/abort on the Engine worker, boot/Tile capture and per-candidate admission, DOWN settle helper.
- `MainActivity.kt` — `Engine.connect` validates the attachment and re-derives identity **before** `Mobile.stopWithTimeout` and before every native UP effect; the activity passes the captured `policyReceipt`; config save/delete and `routingSave` take a synchronous admission fence before their IO and release it in `finally`; `saveConnectionPlan` strictly validates the legacy payload and keeps a schema-2 payload only as a validated, never-read mirror; policy channel methods return coded failures.
- `VpnControlService.kt` — the Tile copies the ready envelope receipt **and** candidate list once (`PolicyBridge.capture`), then carries that captured receipt/generation through every candidate; no `optJSON*` fallback and no raw-plan read.
- `XioVpnService.kt` — restarts the controller only for a strictly parsed READY envelope or a legacy plan; pending/blocked/malformed envelopes never auto-reconnect.
- `XrayBackend.kt` — uses the admitted plan's site (no silent `https://youtube.com` default) and no longer reads the raw plan.
- `Engine.status` active-id reconciliation reads the committed/revalidatable plan ids (or the strictly validated
  legacy plan) instead of the raw plan, so the raw plan has no remaining reader except the explicit legacy
  migration path.

## Proven (offline, pure JVM)

Executed on JDK 21 with `javac`/`java`, no Android, no device, no network:

```
PolicyWireTest          PASS  schema-2 plan, WIRE-V2 golden config digests (trailing LF differs),
                              exact types/budget, ids/profiles identity, selection rules,
                              canonical sorted routing, verbatim priority, C5 site, envelope/receipt strictness
PolicyJournalTest       PASS  pending/ready ACK only after durable commit; commit()==false is
                              pendingUnknown without ACK/rollback; DOWN during an outstanding write
                              settles then blocks; failed reconciliation keeps ownership; parent
                              timeout is not pre-rename; restart ignores a failed cache; CAS/replay
PolicyAdmissionTest     PASS  known-clean boot/Tile path without Flutter; exact vault digests;
                              routing/priority/selected/settings divergence; consent/revocation;
                              malformed and mixed receipt pairs; late-automatic resurrection blocked;
                              null-routing rules; empty plan; legacy automatic migration
PolicyWiringTest        PASS  admission before stop/UP; receipt carried through every Tile candidate;
                              no raw-plan tile/xray/restart consumer; synchronous config/routing fence;
                              real PublicationLease + PolicyJournal DOWN/late-write ownership;
                              pendingUnknown; C7 FLAG_SECURE ordering preserved
ServiceDownWiringTest   PASS  unchanged pre-existing source/DOWN/admission invariants
ConnectionBudgetTest    PASS  unchanged root/sub-budget semantics
BackgroundVerificationOptionsTest PASS unchanged C5 typed consent
```

The WIRE-V2 goldens are asserted verbatim: `39f8033…` (trailing LF), `b5e42d8…` (no trailing LF),
`c40bb48…` (vless JSON), `e3b0c44…` (empty).

## Review corrections applied (parent message, 2026-11-06)

| Finding | Resolution |
|---|---|
| Android routing must be non-null for every schema-2 plan | `PolicyPlan.parse` now rejects `routing: null` (and a missing key) for automatic/all too: `POLICY_INVALID`. Legacy raw plan is a separate path and carries no routing snapshot. Negative test added. |
| Legacy must not key off "no native envelope" alone | Legacy automatic now requires **all** of: no envelope saved, no durable `connectionPolicy` key, no `connectionPlanReceipt`, automatic-only old payload. Implemented in `DurableAdmission.requireLegacyState` and in the restart predicate. Regression tests: automatic versioned/document-without-receipt/no-envelope, manual versioned/no-envelope, candidate re-check. |
| `PolicyEnvelopes.autonomous` allowed legacy with a pending/blocked envelope | Rewritten: any saved envelope => only a process-confirmed READY answer; legacy considered only when no envelope exists **and** the durable document is pre-versioned. Comment corrected: "ready" means process-confirmed durable, not "on disk". |
| Cached READY after `commit()==false` | `PolicyJournal.readyForAdmission()` / `revalidatable()` are the only readiness authorities; every reader (Tile capture, Engine admission, restart predicate) uses them. A failed commit leaves the previous READY bytes in memory but they are not revalidatable and never admitted. Tests model cached-READY/durable-PENDING, same-process and restart. |
| Commit/reconcile ACKed without re-deriving stored state | `DurableAdmission.validateProposal` re-reads document receipt, all config digests, routing, priority, selection, consent, revocation and eligibility **before** writing READY. Mismatch revokes the proposal and writes BLOCKED; no ACK. Commit requires the exact receipt; reconcile permits an absent receipt but never a disagreeing one. Tests cover changed/missing config, routing, selection, priority, generation and receipt. |
| `candidateIds` read the raw legacy mirror even with a versioned pending/blocked/malformed envelope or document, and `Engine.status` writes `activeId` from it | Display ids now go through `DurableAdmission.legacyIdsIfPristine`: the mirror is returned only with no envelope of any phase, no `connectionPolicy` marker and no receipt; otherwise `null`. `LegacyDisplayTest` covers pending/blocked/malformed + old mirror => no rewrite, and pristine legacy => ids. |
| `connectionBusy` could make an owned publication block its own commit/recovery | `connectionBusy` reports the reservation to *new* callers only; publication commit/abort paths never consult it. `PolicyWiringTest` asserts new connections are refused while the owning pending/commit/abort completes and admission opens afterwards. |

## Restart without Flutter: how durable READY becomes process-confirmed (G3)

The autonomous path never trusts a cached string and never treats `unknown` as the steady state:

1. **Fresh process.** `PolicyBridge.initialize` creates one journal and calls `load()` exactly once. Under the
   cold-process assumption (a new process/provider that has performed no writes in this process; not a claim
   about Android power-cut/fsync durability), the first `SharedPreferences.getString` reflects what was loaded
   from the file, so a strict READY envelope sets `status=READY`. A malformed file sets BLOCKED; a
   `pending`/`pendingUnknown`/`blocked` phase keeps its own status; nothing is guessed. The fake store in the
   tests models this assumption; it does not prove device-level durability.
2. **Positive re-proof without Flutter.** `PolicyBridge.capture(context)` (the Tile path) takes the journal's
   `revalidatable()` envelope and calls `DurableAdmission.validateReady`: strict schema-2 plan, document
   `connectionPolicy` + `connectionPlanReceipt`, `selected`, profiles/users/revocation, consent, routing
   (`routingGet` values), `priorityProtocol`, site/timeout and every exact `ConfigVault` digest. Success
   (`BootTileAdmissionTest`) yields the ordered candidate list and a receipt built from the **current** engine
   nonce; the envelope is adopted as process-confirmed and every candidate is re-checked before its effect.
3. **Barrier is not weakened.** `readyForAdmission()` is `status==READY && envelope.phase==READY && no active
   reservation`. After a failed `commit()`, a late/revoked write or a failed blocked reconciliation the status
   is `pendingUnknown` (or BLOCKED), so `revalidatable()` returns `null` and capture/admission/restart all
   refuse even though the previous READY bytes are still in memory. A restart that finds `pending` can only be
   repaired by an explicit `policyReconcile(expectedGeneration:null)`; `policyBegin` stays BUSY.
4. **Receipt-required recovery (liveness, not only refusal).** Both commit and reconcile require the exact
   durable receipt. For the cut "pending ACK, process death before the app rename" the supported sequence is
   `RecoveryLivenessTest`: the rejected reconcile leaves a durable BLOCKED envelope (replacing the persisted
   PENDING one; the ticket is released only after that write) => a fresh `policyBegin` with a new
   transaction/generation and `expectedGeneration:null` is allowed => the app writes its frozen document with
   the new receipt => `policyCommit` re-derives and ACKs READY => Tile/native capture admits the candidate. A
   failed blocked write keeps ownership and is retryable via `policyAbort(deadTransactionId)`. No manual
   preference deletion, no native document write. `BootTileAdmissionTest` also asserts the cut-B
   reconcile-validates case and a receipt-generation mismatch.
5. **Negative evidence in the same test:** pending restart, blocked restart, malformed envelope, READY envelope
   against a document without marker/receipt, changed digest, changed routing, and a versioned document with
   an old raw plan but no envelope (legacy refused). The positive case is asserted first, so a permanent
   block would fail the suite. Proof remains pure JVM + compiler; no device/power-cut claim.

## Independent review findings (reviewer `0cf`, after `6f0c16a`) — fixed forward

| Finding | Fix | Evidence |
|---|---|---|
| **P1 deadlock**: actual `Engine.cancelConnect(null)` holds `synchronized(publication)` through `revokePublication` → `PolicyBridge.revokeLogical` → `journal.revokeAll`, while the worker holds the journal and reaches `Engine.policyReserve` (publication) | `revokePublication` is now the activation fence only (no journal). Each DOWN caller performs `revokeLogicalPolicy()` AFTER every publication monitor is released (`cancelConnect` sets `globalDown` under the monitor and calls it after the block; both services call it immediately after the fence). The journal still takes publication inside its gate, so the only legal order is journal→publication and the reverse path is gone. | Reviewer boundary probe's hand-written graph still deadlocks by construction; the authoritative **actual-Engine probe** `engine-probe.py` reproduced (exit 1 AssertionError, bounded 12s) on the old compiled classes and is re-run unchanged after the fixed compile. |
| **3 identity variants**: `PolicyBridge.commit` compared only transaction id/generation/plan, so foreign `controllerNonce`, foreign `storeIdentity` and a mismatched `expectedGeneration` still produced a READY ACK | `PolicyJournal.requireSameProposal` compares **all** bound identities (store, controller, transaction, expectedGeneration, planGeneration, canonical plan) against the active reservation before any write; mismatch is `POLICY_STALE`, malformed hex `POLICY_INVALID`, no authority transfer. | `PolicyJournalTest` covers every field plus the exact control; reviewer `bridge-probe.py` reproduced 3 READY ACKs on the old class and is re-run (its hard-coded `PolicyBridge.class` SHA pin necessarily changes) against the fixed class. |
| **Empty/whitespace config** passed proposal, READY and candidate admission when the plan digest matched those bytes | `checkProfile`, `validateLegacy` and `validateLegacyCandidate` reject `exact.trim().isEmpty()` as `POLICY_STALE` before digest comparison. | Reviewer `IndependentBoundaryProbe.blank("")/blank(" \t\n")` now throw `PolicyFailure: Saved configuration is empty` (per-case runner over the unchanged probe); own tests cover proposal/ready/legacy. |
| **Present `connectionPlanReceipt:null`** without `connectionPolicy` admitted legacy activation and display | `DurableDocument` tracks the receipt **key** (`hasPlanReceiptKey`). Legacy/display require the key to be absent; a present-null receipt is `POLICY_INVALID` at READY/proposal and never a legacy boundary. Restart predicate uses the same flag. | Reviewer probe `nullReceipt()` now throws `PolicyFailure: Saved document already carries a plan receipt boundary`; own tests cover legacy/display/READY/proposal. |

Probe-runner note: the boundary probe hard-codes its hand-written DOWN ordering, so its `deadlock()` case keeps deadlocking after the Engine fix; the reviewer's actual-Engine probe is the authoritative before/after for that finding. The bridge probe pins the old `PolicyBridge.class` SHA, so it cannot run against a fixed class without re-pinning; the same unchanged test body is used with the new pin for the after run. `6f0c16a` evidence is preserved as the previous candidate; no history was rewritten.

## DOWN call-site audit (complete)

| Site | Activation fence (under publication) | Journal revocation (outside every publication monitor) |
|---|---|---|
| `Engine.cancelConnect(null)` | `if(roundId == null) revokePublication()` inside the monitor; `globalDown=true` | `if(globalDown) revokeLogicalPolicy()` after the monitor block, before JNI cancel |
| `VpnControlService` tile/DOWN | `Engine.revokePublication()` | `Engine.revokeLogicalPolicy()` immediately after, before the worker disconnect queue |
| `XioVpnService` DISCONNECT | `Engine.revokePublication()` | `Engine.revokeLogicalPolicy()` immediately after, before `Engine.initialize` |
| `XioVpnService.onRevoke` | `Engine.revokePublication()` | `Engine.revokeLogicalPolicy()` immediately after |

`PolicyBridge.revokeLogical` has exactly one caller (`Engine.revokeLogicalPolicy`), and every call site of that is outside
`synchronized(publication)`. All remaining publication-monitor blocks (`requireActivation`, `policyReserve/Revoke/Release`,
`admissionOpen`, config mutation, `disconnect`, `connect` begin) are flag/publication-only and never enter the journal.
Order is therefore journal→publication only.

**Freeze correction:** `57e73f8` was a forward-only fix attempt but its `commit` path referenced an undefined reservation
variable (not buildable) and did not yet satisfy report §2's "reject without revoking the owner's reservation" atomically.
It is superseded by the next commit, which binds identity and returns the matched reservation under one journal monitor
before any proposal validation/abort/write/ACK.

## AFTER candidate `fccb254` — exact compile + independent probe replay

**Product commit `fccb2544394026e04be881b14ccbad44d767c338`** (supersedes `6f0c16a`; `57e73f8` is marked **not compilable by source check** — no Gradle was ever run on it and no compile exit is claimed for it).

Compile, exact source + accepted all-ABI AAR `7e118036…`, serial Full→Client, offline, `--no-daemon --no-build-cache --max-workers=1`, clean build dir: Full `compileDebugKotlin` + `compileDebugJavaWithJavac` executed exit 0 in 2m43s (27 tasks), Client both executed exit 0 in 1m44s (6 tasks); 46 Kotlin + 92 Java classes; source archive `0c99d244…`, `tar -df` overlay identical, staged manifest unchanged before/after runs; per-mode BuildConfig captured.

Independent probes replayed on the new compiled classes (unchanged Java test bodies; driver diffs contain only owned paths and the expected class-hash re-pin):

| Probe | Before (`6f0c16a`) | After (`fccb254`) |
|---|---|---|
| Actual compiled Engine + PolicyBridge DOWN/publication lock order (`IndependentEngineLockOrderTest`, unchanged body) | exit 1, real monitor cycle | **exit 0 PASS** (`PASS actual product DOWN/publication lock order`; worker's expected `VPN cancellation incomplete` PolicyFailure, no monitor cycle) |
| Actual compiled PolicyBridge commit identity (`IndependentCommitIdentityTest`, unchanged body, driver only re-pins `PolicyBridge.class` `27e3103…` → `5d98a70e…`) | control PASS + 3 foreign READY ACKs | **control PASS + 3×`POLICY_STALE` rejection**, exit 0 |
| Owner-liveness control (new wrapper; after each foreign commit) | — | **PASS**: reservation still the same instance, not revoked, durable state still PENDING; the exact legitimate commit then returns READY |
| `IndependentBoundaryProbe` blank/whitespace/null-receipt cases (unchanged probe, per-case runner, expected rejection) | all 3 accepted | **all 3 rejected**: `Saved configuration is empty` / `Saved document already carries a plan receipt boundary` |
| Ten pure suites on the same snapshot | exit 0 | **exit 0** |

The boundary probe's composed `deadlock()` schedule still deadlocks by construction (it hard-codes the pre-fix call graph) and is not a regression of the repaired Engine; the actual-Engine probe above is the authoritative before/after for finding 1. Evidence: `evidence/after-fccb254/` (compile logs, manifests, per-mode BuildConfig, pure exits, `probes/` with driver diffs, hashes, raw probe logs and control logs).

## Residual blank-config finding (after `fccb254`) — fixed forward

Independent review confirmed that Java `String.trim()` is ASCII-only, so a saved config consisting of U+00A0,
U+2003 or U+FEFF was still admitted at proposal/READY/candidate. Fix: one shared predicate `PolicyText`
implements the parent's exact Dart 3.13.5 parity matrix (blank: U+0009–000D, U+0020, U+0085, U+00A0, U+1680,
U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF; non-blank: U+0000, U+001C–001F, U+180E, U+200B)
and is used by `checkProfile`, `validateLegacy` and `validateLegacyCandidate`. The predicate inspects the exact
saved string; the config digest is still computed over untouched bytes (no trim, no normalization).

Evidence: `UnicodeWhitespaceTest` covers the full matrix, mixed whitespace, non-blank controls, exact-byte digest
equality and rejection at proposal/READY/legacy; the reviewer's unchanged `UnicodeWhitespaceProbe` (which calls the
unchanged `IndependentBoundaryProbe.blank`) now prints `PASS U+00A0/U+2003/U+FEFF rejected POLICY_STALE`.
Previous `fccb254` findings remain closed but are not retro-accepted; this forward commit is the new candidate.

## Limits / not claimed

- No real device, JNI execution, VPN service, route, credential, phone or network action.
- Physical IO is modelled as an independent cache/durable pair with deferred completion; real
  `SharedPreferences.commit()` behaviour is used but power-loss/directory-fsync durability is not claimed.
- The journal reads SharedPreferences once per process (`load()`); after that only its own committed boolean
  and status decide readiness, so a failed commit's cached value is never re-read as authority.
- A durable DOWN after process death is still the separate guarantee DESIGN explicitly excludes; the
  implemented invariant is "no old ready plan after a newer committed ACK", enforced by document receipt
  comparison at boot.
- `storeIdentity` is validated as a 64-hex product identity and bound into the envelope; this slice does not
  re-derive the Dart store hash (Dart owns that derivation).
- The Tile reports a policy rejection as one honest generic failure (no new localized strings were added:
  all-13 catalogue work is out of this native scope); the coded reason is logged.
- Android compile proof (real Kotlin+Java) is recorded below; per-ABI packaged APK/device behaviour is still unclaimed.

## Integration composition (parent, 2026-11-06)

The parent integrated the independently accepted all-ABI AAR as commit `5a0f2b9f3c42f3ced7e496f01e3ec93ef35592f2`
on the integration branch: the only product delta from `595def6a` is the AAR payload, source unchanged. That is
the same payload this report''s compile uses (`7e118036…` / `classes.jar 8f184933…`), so the pinning is:

```
integration tree  = 595def6a + AAR 7e118036
compiled tree     = 5a472c6 (workspace source) + the same AAR 7e118036
```

The compile proof below remains pinned to `5a472c6` and was not restarted or rebased when integration advanced.
Product acceptance and Dart composition remain separate; nothing here is claimed as integrated.

## FINAL product candidate `6f0c16a8` (supersedes the `5a472c6` revision)

After the targeted review fix (pristine-gated legacy display ids + self-busy coverage) the final product SHA is
`6f0c16a8064b30973f9e2c233e746f378f4a6722`. It is compiled and tested on its exact source:

- archive `212d22355a403e982d230f29726d22cbe7560a702f1be5f07cd832ab1668a6fa`, `tar -df` overlay diff empty,
  staged manifest unchanged before/after both runs (`SOURCE-UNCHANGED-DURING-RUNS`);
- accepted all-ABI AAR `7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c`
  (`classes.jar 8f184933…`, JNI arm64-v8a / armeabi-v7a / x86_64);
- Full `:app:compileDebugKotlin` + `:app:compileDebugJavaWithJavac` executed, exit 0, 51s (27 tasks);
  Client both executed, exit 0, 37s (6 tasks); 46 Kotlin + 92 Java classes; per-mode BuildConfig captured;
- bytecode: admission (176/189/195) before `Mobile.stopWithTimeout` (226); commit `requireProposal` (119) before
  `readyJson` (125); reconcile 64 before 70; FLAG_SECURE 7 before Flutter 12;
- all pure suites on the same snapshot exit 0, including the new `LegacyDisplayTest` (pristine legacy only;
  pending/blocked/malformed versioned envelope, `connectionPolicy` marker and committed receipt all hide the raw
  mirror) and the self-busy assertions (owned publication commits/aborts while `connectionBusy` refuses new
  connections).

Evidence: `evidence/final-6f0c16a8/` (compile summary, logs, ordering, classes, AAR, per-mode BuildConfig,
`pure-explicit/`). The earlier `5a472c6` compile remains in `evidence/final-compile/` as the previous revision;
it is not acceptance for this candidate.

## Previous revision `5a472c6` (kept as prior evidence, not acceptance)

**Compiled product tree: commit `5a472c6058c4fe828dbd706f8d297c6823e3fd9c`**, staged from
`git archive` (archive SHA-256 `cd93e7d049494befebed7298a2181152bf50e189fe8158bcdc48a072e19b60e7`), overlay checked
with `tar -df` (empty diff) and the staged tree manifest unchanged before/after both runs
(`SOURCE-UNCHANGED-DURING-RUNS`). Owned root `/srv/archives/agent-policy-android-native-20261106`.

Dependency substitution (staging only, exactly the independently verified all-ABI payload):
`rivet.aar` `7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c`, `classes.jar`
`8f1849333170c09c3e874c740bfc932a89adb177f454d131cf7caa86d5741400`, JNI `arm64-v8a`, `armeabi-v7a`,
`x86_64`. Toolchain: JDK 21.0.13, Gradle 9.3.1, Flutter 3.47.7, AGP as in the tree.

Both application compile tasks were executed serially, offline, `--no-daemon --no-build-cache --max-workers=1`,
after deleting the shared build directory:

| Mode | `:app:compileDebugKotlin` | `:app:compileDebugJavaWithJavac` | exit | duration |
|---|---|---|---|---|
| Full (`app.xio.xio`, `CLIENT_ONLY=false`) | executed | executed | 0 | 1m51s (27 tasks executed) |
| Client (`app.xio.client`, `CLIENT_ONLY=true`) | executed | executed | 0 | 1m12s (6 tasks executed) |

46 Kotlin + 92 Java application class outputs. Bytecode ordering proofs (not source assertions):

- `Engine.connect`: `requirePolicyAdmissionOpen` (176), `PolicyBridge.requireAdmission` (189), re-check (195),
  then `Mobile.stopWithTimeout` (226).
- `PolicyBridge.commit`: `requireProposal` (119) before `PolicyJournal.readyJson` (125); `reconcile`:
  `requireProposal` (64) before `readyJson` (70).
- `MainActivity.onCreate`: `Window.addFlags` (7) before `FlutterActivity.onCreate` (12).

This is a compiler-only proof: no APK/AAB, packaging, signing, device, JNI runtime or VPN behaviour is claimed.
The branch head at the time of writing is `90a18dde…` (two later consumer/UI-busy changes, listed in the final
handoff); it is **not** part of this compiled tree and would need its own compile slot if accepted.

Evidence: `evidence/final-compile/COMPILE-FINAL.txt`, `full-gradle.txt`, `client-gradle.txt`, `ordering.txt`,
`classes.txt`, `source-overlay.txt`, `source-stability.txt`, `aar-after.txt`, `buildconfig/`; the full staged
manifests and bytecode dumps remain in the owned root (`evidence/compile/`).