package app.xio.xio;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Source-wiring proof for the Android native policy path, plus the real
 * PublicationLease + PolicyJournal gate behaviour. NOT a Kotlin/JNI/device test.
 */
public final class PolicyWiringTest {
    private static String read(Path dir, String name) throws Exception {
        return new String(Files.readAllBytes(dir.resolve(name)), java.nio.charset.StandardCharsets.UTF_8).replace("\r\n", "\n");
    }

    private static String journalSource(Path java) throws Exception { return read(java, "PolicyJournal.java"); }

    private static String section(String source, String start, String end) {
        int from = source.indexOf(start);
        int to = source.indexOf(end, from < 0 ? 0 : from);
        if (from < 0 || to < 0) throw new AssertionError("missing section: " + start + " .. " + end);
        return source.substring(from, to);
    }

    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }

    public static void main(String[] args) throws Exception {
        Path kotlin = Path.of(args[0]);
        Path java = Path.of(args[1]);
        String engine = read(kotlin, "MainActivity.kt");
        String controller = read(kotlin, "VpnControlService.kt");
        String service = read(kotlin, "XioVpnService.kt");
        String xray = read(kotlin, "XrayBackend.kt");
        String bridge = read(kotlin, "PolicyBridge.kt");
        String lease = read(java, "PublicationLease.java");
        String journal = read(java, "PolicyJournal.java");

        // ---- Engine.connect: admission must precede EVERY effect, including stop.
        int connectStart = engine.indexOf("fun connect(id: String");
        int stopAt = engine.indexOf("Mobile.stopWithTimeout(budget.remainingMillis())");
        int admissionCall = engine.indexOf("PolicyBridge.requireAdmission(app, policyReceipt, id)");
        check(connectStart >= 0 && stopAt > connectStart && admissionCall > connectStart && admissionCall < stopAt,
            "admission must happen BEFORE Mobile.stopWithTimeout");
        check(engine.substring(connectStart, stopAt).contains("policyReceipt: Map<String,Any?>? = null"),
            "connect carries the activation attachment");
        int firstFence = engine.indexOf("requirePolicyAdmissionOpen()", connectStart);
        int secondFence = firstFence < 0 ? -1 : engine.indexOf("requirePolicyAdmissionOpen()", firstFence + 1);
        check(firstFence > connectStart && secondFence > firstFence && secondFence < stopAt,
            "admission is fenced before and after derivation, before the effect boundary");
        check(engine.indexOf("PolicyBridge.requireAdmission(app, policyReceipt, id)") < engine.indexOf("backend.setState(tunnel, Tunnel.State.UP, effective)"),
            "admission must happen BEFORE the native UP effect");
        check(engine.contains("val frozenPolicy = admission.policyJson()") && engine.contains("RivetBackend.connect(service,id,raw,left,frozenPolicy)"),
            "the frozen policy, not the request, drives the engine");
        check(engine.contains("admittedSite = admission.site") && engine.contains("fun capturedSite():String = admittedSite ?: error(\"No admitted site policy\")"),
            "site policy comes from the admitted plan and has no default");

        // ---- Activity: the captured receipt travels with the request.
        check(engine.contains("val policyReceipt:Map<String,Any?>?=null"), "ConnectRequest stores the receipt");
        check(engine.contains("policyReceipt = call.argument<Map<String,Any?>>(\"policyReceipt\")"), "connect arguments accept policyReceipt");
        String worker = section(engine, "private fun connect(request: ConnectRequest)", "private fun preparePendingVpn");
        check(worker.contains("policyReceipt=request.policyReceipt") && worker.contains("admissionToken=request.admissionToken"), "worker passes the captured receipt");
        check(worker.contains("e is PolicyFailure)e.code"), "policy failures keep their exact code");

        // ---- Tile: capture once, carry that generation through EVERY candidate.
        String tile = section(controller, "     // Copy the committed envelope receipt", "   } catch(e:Exception)");
        check(tile.contains("val captured=PolicyBridge.capture(this@VpnControlService)"), "tile captures a validated admission");
        check(bridge.contains("private fun revalidatableEnvelope(journal: PolicyJournal): PolicyEnvelope? = journal.revalidatable()"),
            "capture/admission use the journal's revalidatable gate, never a bare envelope");
        check(bridge.contains("requireProposal(reservation)"),
            "commit/reconcile re-derive stored identity before a ready ACK");
        check(bridge.indexOf("requireProposal(reservation)") < bridge.indexOf("val bytes = journal.readyJson(reservation)"),
            "publication validation precedes the ready write");
        check(bridge.indexOf("requireProposal(reservation)") < bridge.indexOf("requireProposal(reservation)", bridge.indexOf("requireProposal(reservation)") + 1),
            "both commit and reconcile share the same receipt-required validation");
        check(bridge.contains("val allowed = setOf(\"version\", \"instanceNonce\", \"transactionId\")")
            && bridge.contains("for (key in allowed) if (!args.containsKey(key))"),
            "policyAbort has the exact three-field shape with all fields required");
        check(bridge.contains("\"instanceNonce\", \"transactionId\", \"expectedGeneration\"")
            || bridge.contains("\"controllerNonce\", \"instanceNonce\", \"transactionId\""),
            "publication requests carry the engine-lifetime nonce");
        check(bridge.contains("requireInstance(request.instanceNonce)"), "publication requests validate the engine nonce");
        check(!bridge.contains("ack.storeIdentity"), "the ACK keeps the WIRE-V1 six-field shape");
        check(journalSource(java).contains("if (!reconcile || expectedGeneration != null)")
            && journalSource(java).contains("Reconcile the pending connection policy first"),
            "a persisted pending envelope can only be replaced by explicit reconcile");
        check(bridge.contains("DurableAdmission.validateProposal(reservation.plan, reservation.transactionId, reservation.planGeneration")
            && bridge.contains("runCatching { drain(journal, journal.abort(reservation.transactionId), reservation) }"),
            "a mismatched proposal is revoked to BLOCKED, never ACKed");
        check(read(java, "DurableAdmission.java").contains("Saved document has no committed plan receipt")
            && !read(java, "DurableAdmission.java").contains("requireReceipt"),
            "every publication ACK requires the exact durable receipt (no weaker reconcile path)");
        check(read(java, "DurableAdmission.java").contains("requireLegacyState(document)"),
            "legacy admission requires a pre-versioned document");
        check(read(java, "PolicyPlan.java").contains("path + \".routing: required on Android\""),
            "Android schema-2 plans cannot carry null routing");
        check(tile.indexOf("PolicyBridge.capture") < tile.indexOf("budget.runCandidates"), "capture precedes every candidate");
        check(tile.contains("val ids=captured.candidates"), "candidate list is copied with the receipt");
        check(tile.contains("Engine.connect(id,true,attempt,captured.policyJson(),roundId,policyReceipt=captured.receipt)"),
            "every candidate carries the SAME captured receipt");
        check(tile.contains("if(captured.mode==\"selectedOnly\")1"), "manual mode keeps one candidate");
        check(tile.contains("round.cap(ConnectionPolicy.ROUND_MILLIS)"), "root budget stays the accepted 30s");
        check(!tile.contains("optJSONArray") && !tile.contains("optJSONObject") && !tile.contains("optLong") && !tile.contains("optString"),
            "tile never falls back to coercing JSON");
        check(!tile.contains("connectionPlan"), "tile never reads the raw plan");
        check(controller.indexOf("Engine.registerConnect(round)") < controller.indexOf("PolicyBridge.capture(this@VpnControlService)"),
            "the tile root request is registered before capture so a publication cannot interleave");

        // ---- Restart consumer: only a strictly parsed READY envelope or legacy plan.
        check(service.contains("PolicyEnvelopes.autonomous(this)"), "restart consumer asks the versioned envelope");
        check(!service.contains("getString(\"connectionPlan\""), "restart consumer no longer trusts the raw plan");
        check(!bridge.contains("ready(context) || legacyPlan(context)"),
            "the old plan must never bypass a present versioned envelope");
        check(bridge.contains("val versioned = context.getSharedPreferences(PolicyPrefs.FILE, Context.MODE_PRIVATE)"),
            "restart predicate checks whether versioned ownership began");
        check(bridge.contains("if (versioned) return ready(context)"), "any envelope present allows only confirmed READY");
        check(bridge.contains("private fun legacyAutonomous(context: Context): Boolean")
            && bridge.contains("!document.hasConnectionPolicy && !document.hasPlanReceiptKey"),
            "legacy restart requires a genuinely pre-versioned durable document (receipt key included)");
        check(bridge.contains("if (PolicyBridge.initialized) return PolicyBridge.confirmedReady()"),
            "restart never trusts a cached READY after this process wrote the envelope");
        check(bridge.contains("return readyJournal().readyForAdmission()"), "confirmed READY is the journal's durable answer");
        check(journalSource(java).contains("status == Status.READY && envelope != null && envelope.phase == PublicationPhase.READY"),
            "journal gates readiness on confirmed status, not cached bytes");

        // ---- Legacy plan consumer replacement.
        check(xray.contains("Engine.capturedSite()") && !xray.contains("optString(\"site\""), "xray uses the admitted site, no default");
        check(!xray.contains("connectionPlan"), "xray no longer reads the raw plan");
        // DOWN journal revocation happens only after the publication monitor is released.
        String fence = section(engine, "fun revokePublication(", "fun revokeLogicalPolicy");
        check(!fence.contains("PolicyBridge.revokeLogical"), "activation fence never enters the journal");
        String cancel = section(engine, "fun cancelConnect(", "fun retireRound(");
        check(cancel.contains("if(globalDown) revokeLogicalPolicy()"), "cancelConnect revokes the journal after the block");
        check(cancel.indexOf("if(globalDown) revokeLogicalPolicy()") > cancel.indexOf("publication.token()"),
            "journal revocation follows the publication-monitor section");
        check(controller.contains("Engine.revokeLogicalPolicy()") && service.contains("Engine.revokeLogicalPolicy()"),
            "every service DOWN path performs the journal revocation outside the monitor");
        check(engine.contains("PolicyBridge.candidateIds()") && !engine.contains("getString(\"connectionPlan\""),
            "the status/active-id path consults the committed plan, not the raw plan");
        check(bridge.contains("DurableAdmission.legacyIdsIfPristine(journal.versionedOwnership(), raw, documentText)"),
            "display ids use the same pristine no-envelope/no-marker gate as capture/boot");

        // ---- Config/routing writes fence READY admission synchronously.
        check(engine.contains("val fence = if (call.method in setOf(\"saveConfig\",\"deleteConfig\",\"routingSave\"))"),
            "config save/delete and routingSave fence admission");
        check(engine.indexOf("val fence = if (call.method in setOf") < engine.indexOf("Engine.worker.execute {\n                    try {"),
            "the fence is taken synchronously before the IO is queued");
        check(engine.contains("if (fence != 0L) Engine.endConfigMutation(fence)"), "the fence is released only when the write settles");
        check(engine.contains("LegacyPlan.parseExactStored(raw)"), "the legacy plan is strictly validated");
        check(engine.contains("PolicyPlan.parse(parsed, \"connectionPlanMirror\")"), "a schema-2 mirror is validated, not trusted");

        // ---- Gate semantics that make the above true.
        check(lease.contains("if (policy != null) throw new IllegalStateException(\"Connection policy publication in progress\")")
            && lease.contains("if (!requests.isEmpty()) throw new IllegalStateException(\"Connection request outstanding\")"),
            "policy reservation requires a genuinely idle gate");
        check(lease.contains("if (policy != null) policy.revoked = true; // Logical only: physical writer stays owned."),
            "DOWN revokes the logical policy owner only");
        check(lease.contains("if (mutations != 0) throw new IllegalStateException(\"Connection settings are being saved\")"),
            "config mutations fence admission");
        check(journal.contains("PENDING_UNKNOWN(\"pendingUnknown\")") || read(java, "PublicationPhase.java").contains("PENDING_UNKNOWN(\"pendingUnknown\")"),
            "pendingUnknown is a normative phase");
        check(journal.contains("status = Status.PENDING_UNKNOWN;"), "failed writes become pendingUnknown in memory");
        check(journal.contains("gate.releasePolicy") && journal.contains("while (retired.size() > 16)"),
            "ownership is released on settle and transactions are retired");

        // ---- Real gate + journal: registration blocks a publication; DOWN revokes
        //      the logical owner but never the physical ticket.
        PublicationLease gate = new PublicationLease();
        ConnectionBudget root = new ConnectionBudget(30000, () -> 1000L);
        gate.register(root);
        PolicyJournal.Store store = new PolicyJournal.Store() {
            String cache;
            public String cached() { return cache; }
            public boolean commit(String value) { cache = value; return true; }
        };
        PolicyJournal liveJournal = new PolicyJournal(store, new PolicyJournal.Gate() {
            public void reservePolicy(String transactionId) {
                try { gate.reservePolicy(transactionId); }
                catch (IllegalStateException busy) { throw PolicyFailure.busy(busy.getMessage()); }
            }
            public void revokePolicy(String transactionId) { gate.revokePolicy(transactionId); }
            public void releasePolicy(String transactionId) { gate.releasePolicy(transactionId); }
        });
        liveJournal.load();
        try {
            liveJournal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN,
                PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1"), false)));
            throw new AssertionError("publication admitted while a connect request was registered");
        } catch (PolicyFailure busy) {
            check(PolicyFailure.BUSY.equals(busy.code), "registered request must yield POLICY_BUSY");
        }
        gate.release(root);
        PolicyJournal.Reservation reservation = liveJournal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, null, PolicyFixtures.GEN, PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1"), false)));
        check(gate.policyReserved(), "gate owns the reservation");
        ConnectionBudget intruder = new ConnectionBudget(30000, () -> 1000L);
        try { gate.begin(gate.admissionToken(), intruder, "intruder"); throw new AssertionError("connect admitted during a policy reservation"); }
        catch (IllegalStateException expected) { }
        try { gate.register(intruder); throw new AssertionError("request registered during a policy reservation"); }
        catch (IllegalStateException expected) { }
        long mutation = gate.beginConfigMutation();
        check(!gate.admissionOpen(), "config mutation closes admission");
        gate.endConfigMutation(mutation);
        check(gate.configMutations() == 0, "config mutation released");
        liveJournal.pendingJson(reservation);
        check(store.commit("pending"), "pending durable");
        liveJournal.settlePending(reservation, true);
        liveJournal.readyJson(reservation);
        gate.revoke(); // External DOWN: lease fence AND logical journal revocation, as Engine.revokePublication does.
        liveJournal.revokeAll();
        check(gate.policyRevoked(PolicyFixtures.TX), "DOWN marks the policy ticket revoked");
        check(liveJournal.active() != null, "DOWN did not release the physical writer");
        PolicyJournal.Settle late = liveJournal.settleReady(reservation, true);
        check(!late.acked() && late.blockedWriteRequired, "late write after DOWN is never an ACK");
        liveJournal.settleBlocked(reservation, true);
        check(!gate.policyReserved() && liveJournal.status() == PolicyJournal.Status.BLOCKED, "blocked receipt releases ownership");
        PolicyJournal.Reservation successor = liveJournal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("xr1"), true)));
        check(gate.policyReserved() && successor.planGeneration.equals(PolicyFixtures.GEN2), "successor reservation after settlement");

        // ---- C7 ordering and C5 typed consent must survive this change.
        String onCreate = section(engine, "override fun onCreate(savedInstanceState", "private data class ConnectRequest");
        check(onCreate.indexOf("window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)") < onCreate.indexOf("super.onCreate(savedInstanceState)"),
            "FLAG_SECURE still precedes Flutter");
        check(tile.contains("BackgroundVerificationOptions.fromPlanValue(captured.siteCheckEnabled)"),
            "C5 website consent stays typed");

        // Self-busy: the policy lane reports "busy" to new connections, but its own
        // commit and abort must not be blocked by that flag (no deadlock).
        PublicationLease selfGate = new PublicationLease();
        PolicyJournal.Store selfStore = new PolicyJournal.Store() {
            String cache;
            public String cached() { return cache; }
            public boolean commit(String value) { cache = value; return true; }
        };
        PolicyJournal selfJournal = new PolicyJournal(selfStore, new PolicyJournal.Gate() {
            public void reservePolicy(String transactionId) {
                try { selfGate.reservePolicy(transactionId); }
                catch (IllegalStateException busy) { throw PolicyFailure.busy(busy.getMessage()); }
            }
            public void revokePolicy(String transactionId) { selfGate.revokePolicy(transactionId); }
            public void releasePolicy(String transactionId) { selfGate.releasePolicy(transactionId); }
        });
        selfJournal.load();
        PolicyPlan selfPlan = PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1"), true));
        PolicyJournal.Reservation owned = selfJournal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, null, PolicyFixtures.GEN, selfPlan);
        check(!selfGate.admissionOpen(), "external readers see the publication as busy");
        try { selfGate.register(new ConnectionBudget(30000, () -> 1000L)); throw new AssertionError("new connection admitted during an owned publication"); }
        catch (IllegalStateException expected) { }
        String selfPending = selfJournal.pendingJson(owned);
        check(selfStore.commit(selfPending) && selfJournal.settlePending(owned, true).acked(),
            "the owning pending ACK is not self-blocked");
        String selfReady = selfJournal.readyJson(owned);
        check(selfStore.commit(selfReady) && selfJournal.settleReady(owned, true).acked(),
            "the owning commit is not self-blocked");
        check(selfGate.admissionOpen(), "admission opens after the owned publication settles");
        PolicyJournal.Reservation aborted = selfJournal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.GEN2, PolicyFixtures.GEN, PolicyFixtures.GEN2, selfPlan);
        check(!selfGate.admissionOpen(), "owned reservation is visible as busy");
        selfJournal.abort(PolicyFixtures.GEN2); // nothing written yet: releases cleanly
        check(selfGate.admissionOpen(), "the owning abort is not self-blocked");

        // Automatic failover: the candidate that finally connects IS the round's
        // publication owner. Until its activation settles the lane is closed; once
        // it settles, the accepted selection must be publishable while the tunnel
        // stays UP. Refusing that made failover stop with POLICY_BUSY right after
        // the winning candidate connected.
        PublicationLease failover = new PublicationLease();
        ConnectionBudget round = new ConnectionBudget(30000, () -> 1000L);
        failover.register(round);
        long token = failover.begin(failover.admissionToken(), round, "round-1");
        try {
            failover.reservePolicy("tx-activation");
            throw new AssertionError("publication admitted while the connect request was outstanding");
        } catch (IllegalStateException busy) {
            check(busy.getMessage().contains("request"), "an outstanding request fences the lane: " + busy.getMessage());
        }
        failover.release(round); // the connect request was delivered, the activation is still settling
        try {
            failover.reservePolicy("tx-activation");
            throw new AssertionError("publication admitted while the activation was still being established");
        } catch (IllegalStateException busy) {
            check(busy.getMessage().contains("activation"), "activation must own the lane until it settles: " + busy.getMessage());
        }
        failover.settleActivation("round-1");
        failover.reservePolicy("tx-accepted");
        check(failover.policyReserved(), "the accepted candidate can publish its selection");
        check(failover.accepts(token), "settling the activation must not revoke the live tunnel");
        failover.releasePolicy("tx-accepted");
        check(!failover.policyReserved(), "publication released");
        // A later round starts a NEW activation and closes the lane again.
        failover.register(round);
        failover.begin(failover.admissionToken(), round, "round-2");
        failover.release(round);
        try {
            failover.reservePolicy("tx-next");
            throw new AssertionError("publication admitted during the next activation");
        } catch (IllegalStateException expected) { }
        failover.retire("round-2", null); // candidate failure: lane reopens for recovery
        failover.reservePolicy("tx-recovery");
        check(failover.policyReserved(), "a retired activation releases the lane for recovery");
        failover.releasePolicy("tx-recovery");

        System.out.println("PASS native policy wiring: admission before stop/UP, receipt carried through every tile candidate, "
            + "no raw-plan tile/xray/restart consumer, synchronous config/routing fence, real gate+journal DOWN/late-write "
            + "ownership, pendingUnknown, failover publication after a settled activation, C7 FLAG_SECURE ordering");
    }

    private PolicyWiringTest() { }
}



