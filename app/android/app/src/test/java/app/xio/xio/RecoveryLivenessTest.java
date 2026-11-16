package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * End-to-end liveness for the crash cut "pending ACK, process death before the
 * app rename": the only supported path is public-RPC-only, with no manual
 * preferences deletion and no native document writing.
 *
 * <pre>
 * persisted pending
 *   -> policyReconcile(plan/tx/gen of the dead publication, expectedGeneration=null)
 *      rejected (the durable receipt for it does not exist) and leaves durable BLOCKED
 *   -> policyBegin(new tx/gen, expectedGeneration=null)   [allowed only after BLOCKED]
 *   -> app writes its frozen document with the NEW receipt
 *   -> policyCommit validates the same receipt -> READY
 *   -> Tile/native capture validates the pair and admits the selected candidate
 * </pre>
 */
public final class RecoveryLivenessTest {
    static final class Store implements PolicyJournal.Store {
        String disk;
        boolean durable = true;
        Store(String disk) { this.disk = disk; }
        public String cached() { return disk; }
        public boolean commit(String value) { disk = value; return durable; }
    }

    static final class Gate implements PolicyJournal.Gate {
        int reserved, released, revoked;
        public void reservePolicy(String transactionId) { reserved++; }
        public void revokePolicy(String transactionId) { revoked++; }
        public void releasePolicy(String transactionId) { released++; }
    }

    public static void main(String[] args) {
        Map<String, Object> plan1 = PolicyFixtures.plan(List.of("awg1", "xr1"), false);
        PolicyPlan first = PolicyFixtures.parsePlan(plan1);
        PolicyEnvelope pending = new PolicyEnvelope(PublicationPhase.PENDING, PolicyFixtures.STORE,
            PolicyFixtures.INSTANCE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, first, null);

        // Crash state: the durable envelope is PENDING; the app has not renamed yet.
        Store store = new Store(pending.canonicalJson());
        Gate gate = new Gate();
        PolicyJournal journal = new PolicyJournal(store, gate);
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.PENDING, "crash state is pending");
        PolicyFixtures.check(!journal.readyForAdmission(), "pending is not admissible");
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            null, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", first));

        // 1. Explicit reconcile of the dead publication: the durable receipt for it
        //    is missing, so the proposal is refused (POLICY_STALE) and recovery
        //    must leave a durable BLOCKED receipt instead of the old PENDING one.
        PolicyJournal.Reservation recovery = journal.reserveReconcile(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, first);
        PolicyFixtures.check(recovery.supersedesPersistedState(), "reconcile knows it replaces persisted pending");
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(
            first, PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(),
            false, PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(plan1))));
        PolicyJournal.Settle refused = journal.abort(PolicyFixtures.TX);   // what requireProposal does
        PolicyFixtures.check(refused.blockedWriteRequired && journal.active() != null,
            "rejected recovery must write a blocked receipt, not silently release");
        String blockedBytes = journal.blockedJson(recovery, "Recovery receipt missing");
        PolicyFixtures.check(store.commit(blockedBytes), "blocked receipt durable");
        journal.settleBlocked(recovery, true);
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.BLOCKED && !journal.hasActiveReservation(),
            "durable BLOCKED after rejected recovery");
        PolicyFixtures.check(PolicyEnvelope.parse(StrictJson.parse(store.disk), "durable").phase == PublicationPhase.BLOCKED,
            "disk really holds BLOCKED");
        PolicyFixtures.check(journal.revalidatable() == null, "blocked state has no reusable READY envelope");
        PolicyFixtures.check(gate.released == 1, "the physical ticket was released only after the blocked receipt");

        // 2. Fresh owned publication after the explicit recovery.
        String tx2 = "cccccccccccccccccccccccccccccccc", gen2 = "dddddddddddddddddddddddddddddddd";
        Map<String, Object> plan2Map = PolicyFixtures.plan(List.of("awg1"), true);
        PolicyPlan plan2 = PolicyFixtures.parsePlan(plan2Map);
        PolicyJournal.Reservation publication = journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, tx2, null, gen2, plan2);
        String pendingBytes = journal.pendingJson(publication);
        PolicyFixtures.check(store.commit(pendingBytes) && journal.settlePending(publication, true).acked(),
            "fresh pending ACK after recovery");

        // 3. The app writes its frozen document with the NEW receipt (owned by the app).
        String document = PolicyFixtures.documentText(PolicyFixtures.documentWithReceipt(plan2Map, tx2, gen2));
        DurableAdmission.validateProposal(plan2, tx2, gen2, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(),
            false, document);

        // 4. Commit -> READY for exactly that receipt.
        String readyBytes = journal.readyJson(publication);
        PolicyFixtures.check(store.commit(readyBytes), "ready durable");
        PolicyJournal.Settle ready = journal.settleReady(publication, true);
        PolicyFixtures.check(ready.acked() && ready.ack.planGeneration.equals(gen2), "commit ACK after recovery");
        PolicyFixtures.check(journal.readyForAdmission(), "recovered publication is process-confirmed");
        PolicyFixtures.check(journal.readyReceipt(PolicyFixtures.INSTANCE).transactionId.equals(tx2),
            "receipt identity is the fresh publication");

        // 5. Tile/native capture succeeds on the recovered pair.
        PolicyEnvelope captured = journal.revalidatable();
        PolicyFixtures.check(captured != null, "capture finds the recovered envelope");
        DurableAdmission.Admission admission = DurableAdmission.validateReady(captured,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        admission.requireActivatable();
        PolicyFixtures.check(admission.candidates.equals(List.of("awg1")), "recovered manual candidate");
        DurableAdmission.validateCandidate(admission, "awg1", PolicyFixtures.allRoutingSource(),
            PolicyFixtures.vault(), false, document);

        // Variant: a failed blocked receipt keeps ownership and stays retryable via
        // policyAbort, never by deleting preferences.
        PolicyJournal.Reservation stuck = journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            gen2, "ffffffffffffffffffffffffffffffff", plan2);
        journal.pendingJson(stuck);
        PolicyFixtures.check(store.commit(journal.pendingJson(stuck)), "second pending durable");
        journal.settlePending(stuck, true);
        store.durable = false;
        journal.settleReady(stuck, false);
        PolicyFixtures.check(!journal.readyForAdmission(), "failed commit is not admissible");
        store.durable = true;
        PolicyFixtures.check(store.commit(journal.blockedJson(stuck, "Commit failed")), "blocked retry durable");
        journal.settleBlocked(stuck, true);
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.BLOCKED, "failed commit ends blocked, no ACK");

        System.out.println("PASS recovery liveness: persisted pending refuses begin, rejected reconcile writes durable "
            + "BLOCKED, a fresh owned publication with a new receipt commits READY, and Tile/native capture admits it; "
            + "no manual preference deletion and no native document write");
    }

    private RecoveryLivenessTest() { }
}
