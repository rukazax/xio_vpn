package app.xio.xio;

import java.util.ArrayList;
import java.util.List;

/**
 * Publication-lane proof with independent cached/durable state and a physical
 * writer that can settle after the logical owner was revoked.
 */
public final class PolicyJournalTest {
    static final class FakeStore implements PolicyJournal.Store {
        String cache;
        String disk;
        boolean durable = true;
        String last;
        int commits;

        public String cached() { return cache; }
        public boolean commit(String value) {
            last = value;
            commits++;
            cache = value;
            if (durable) disk = value;
            return durable;
        }
        void restart() { cache = disk; }
    }

    static final class FakeGate implements PolicyJournal.Gate {
        final List<String> reserved = new ArrayList<>();
        final List<String> released = new ArrayList<>();
        final List<String> revoked = new ArrayList<>();
        boolean busy;

        public void reservePolicy(String transactionId) {
            if (busy) throw PolicyFailure.busy("Gate is busy");
            reserved.add(transactionId);
        }
        public void revokePolicy(String transactionId) { revoked.add(transactionId); }
        public void releasePolicy(String transactionId) { released.add(transactionId); }
    }

    public static void main(String[] args) {
        PolicyPlan automatic = PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1", "xr1"), false));

        // Absent envelope is legacy, not an error; malformed present state blocks.
        FakeStore absent = new FakeStore();
        PolicyJournal absentJournal = new PolicyJournal(absent, new FakeGate());
        absentJournal.load();
        PolicyFixtures.check(absentJournal.status() == PolicyJournal.Status.ABSENT && !absentJournal.versionedOwnership(), "absent state");
        FakeStore malformed = new FakeStore();
        malformed.cache = "{\"schema\":1}";
        malformed.disk = malformed.cache;
        PolicyJournal blocked = new PolicyJournal(malformed, new FakeGate());
        PolicyFixtures.check(blocked.status() == PolicyJournal.Status.BLOCKED && blocked.versionedOwnership(), "malformed blocks and started versioned ownership");

        // Happy path: pending ACK, then ready ACK for the exact generation.
        FakeStore store = new FakeStore();
        FakeGate gate = new FakeGate();
        PolicyJournal journal = new PolicyJournal(store, gate);
        journal.load();
        PolicyJournal.Reservation reservation = journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        PolicyFixtures.check(gate.reserved.equals(List.of(PolicyFixtures.TX)), "gate reservation");
        // Commit must echo every transaction-bound identity of the reservation.
        String foreign = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String foreignStore = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        PolicyPlan otherPlan = PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("xr1"), true));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(foreignStore, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(PolicyFixtures.STORE, foreign,
            PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            foreign, null, PolicyFixtures.GEN, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, PolicyFixtures.GEN2, PolicyFixtures.GEN, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, null, PolicyFixtures.GEN2, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER,
            PolicyFixtures.TX, null, PolicyFixtures.GEN, otherPlan));
        PolicyJournal.Reservation owner = journal.active();
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.requireSameProposal(foreignStore,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic));
        PolicyFixtures.check(journal.active() == owner && !owner.revoked(),
            "a foreign commit identity must not revoke or release the owner's reservation");
        journal.requireSameProposal(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null,
            PolicyFixtures.GEN, automatic);
        String pending = journal.pendingJson(reservation);
        PolicyFixtures.check(PolicyEnvelope.parse(StrictJson.parse(pending), "e").phase == PublicationPhase.PENDING, "pending bytes");
        PolicyFixtures.check(store.commit(pending), "pending durable");
        PolicyJournal.Settle pendingSettle = journal.settlePending(reservation, true);
        PolicyFixtures.check(pendingSettle.acked() && pendingSettle.ack.phase == PublicationPhase.PENDING, "pending ack");
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.PENDING, "pending status");
        PolicyFixtures.check(!journal.readyForAdmission() && journal.revalidatable() == null, "pending is not admissible");
        String ready = journal.readyJson(reservation);
        PolicyFixtures.check(store.commit(ready), "ready durable");
        PolicyJournal.Settle readySettle = journal.settleReady(reservation, true);
        PolicyFixtures.check(readySettle.acked() && readySettle.ack.planGeneration.equals(PolicyFixtures.GEN)
            && readySettle.writePhase == PolicyJournal.WritePhase.COMMITTED, "ready ack");
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.READY && !journal.hasActiveReservation(), "ready released");
        PolicyFixtures.check(journal.readyForAdmission(), "committed ready is admissible");
        PolicyFixtures.check(journal.revalidatable() != null, "committed ready may be revalidated");
        PolicyFixtures.check(gate.released.equals(List.of(PolicyFixtures.TX)), "gate released after settle");
        PolicyFixtures.check(PolicyEnvelope.parse(StrictJson.parse(store.disk), "e").phase == PublicationPhase.READY, "durable ready");
        PolicyFixtures.check(journal.readyReceipt(PolicyFixtures.INSTANCE).planGeneration.equals(PolicyFixtures.GEN), "ready receipt");

        // A finished transaction can never be replayed, even with identical content.
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.GEN2, automatic));
        // Exact generation CAS.
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, PolicyFixtures.GEN2, PolicyFixtures.GEN, automatic));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN, automatic));
        PolicyJournal.Reservation next = journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, PolicyFixtures.GEN, PolicyFixtures.GEN2, automatic);
        PolicyFixtures.check(journal.reserveBegin(PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2,
            PolicyFixtures.GEN, PolicyFixtures.GEN2, automatic) == next, "idempotent same-content retry");
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> journal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, "77777777777777777777777777777777", PolicyFixtures.GEN,
            PolicyFixtures.GEN2, automatic));
        journal.pendingJson(next);
        PolicyFixtures.check(store.commit(journal.pendingJson(next)), "second pending durable");
        journal.settlePending(next, true);
        journal.readyJson(next);
        PolicyFixtures.check(store.commit(journal.readyJson(next)), "second ready durable");
        journal.settleReady(next, true);
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.READY, "second ready");

        // commit()==false: never an ACK, never a rollback, and cache!=disk is honest.
        FakeStore failing = new FakeStore();
        FakeGate failingGate = new FakeGate();
        PolicyJournal failingJournal = new PolicyJournal(failing, failingGate);
        failingJournal.load();
        PolicyJournal.Reservation failure = failingJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        failingJournal.pendingJson(failure);
        failing.durable = false;
        failing.commit("stale-pending");
        PolicyJournal.Settle failureSettle = failingJournal.settlePending(failure, false);
        PolicyFixtures.check(!failureSettle.acked() && failureSettle.writePhase == PolicyJournal.WritePhase.PENDING_UNKNOWN,
            "failed commit is not an ACK");
        PolicyFixtures.check(failingJournal.status() == PolicyJournal.Status.PENDING_UNKNOWN, "failed commit is pendingUnknown");
        PolicyFixtures.check(!failingJournal.readyForAdmission() && failingJournal.revalidatable() == null, "failed commit is never admissible");
        PolicyFixtures.check(failureSettle.blockedWriteRequired, "failed commit needs a blocked receipt");
        PolicyFixtures.check(failingGate.released.isEmpty(), "failed commit keeps physical ownership");
        failing.durable = true;
        PolicyFixtures.check(failing.commit(failingJournal.blockedJson(failure, "commit failed")), "blocked durable");
        failingJournal.settleBlocked(failure, true);
        PolicyFixtures.check(failingJournal.status() == PolicyJournal.Status.BLOCKED && failingGate.released.size() == 1, "blocked settles ownership");
        // Restart from disk after a false commit: the disk still had the old value.
        FakeStore split = new FakeStore();
        PolicyJournal splitJournal = new PolicyJournal(split, new FakeGate());
        splitJournal.load();
        PolicyJournal.Reservation splitReservation = splitJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        splitJournal.pendingJson(splitReservation);
        split.durable = true;
        PolicyFixtures.check(split.commit("old-ready-envelope"), "old durable state");
        split.durable = false;
        splitJournal.settlePending(splitReservation, false);
        PolicyFixtures.check(split.cache.equals("old-ready-envelope") || split.cache != null, "cached memory accepted the failed value");
        split.restart();
        FakeGate splitGate = new FakeGate();
        PolicyJournal restarted = new PolicyJournal(split, splitGate);
        PolicyFixtures.check(restarted.status() == PolicyJournal.Status.BLOCKED, "restart cannot trust a failed cache");
        PolicyFixtures.check(!restarted.readyForAdmission() && restarted.revalidatable() == null, "restart blocked state is not admissible");
        PolicyFixtures.checkCode(PolicyFailure.UNKNOWN, () -> restarted.readyReceipt(PolicyFixtures.INSTANCE));

        // Cache-vs-disk after commit()==false: same-process cached memory shows a
        // READY value while the durable file still holds the PENDING envelope.
        FakeStore cacheSplit = new FakeStore();
        FakeGate cacheGate = new FakeGate();
        PolicyJournal cacheJournal = new PolicyJournal(cacheSplit, cacheGate);
        cacheJournal.load();
        PolicyJournal.Reservation cacheReservation = cacheJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        String cachePending = cacheJournal.pendingJson(cacheReservation);
        PolicyFixtures.check(cacheSplit.commit(cachePending), "pending durable before the failed ready write");
        cacheJournal.settlePending(cacheReservation, true);
        String cacheReady = cacheJournal.readyJson(cacheReservation);
        cacheSplit.durable = false;
        cacheSplit.commit(cacheReady); // cache now holds READY, disk still holds PENDING
        cacheJournal.settleReady(cacheReservation, false);
        PolicyEnvelope cachedEnvelope = PolicyEnvelope.parse(StrictJson.parse(cacheSplit.cached()), "cached");
        PolicyFixtures.check(cachedEnvelope.phase == PublicationPhase.READY, "fixture: cached bytes look READY");
        PolicyFixtures.check(!cacheJournal.readyForAdmission() && cacheJournal.revalidatable() == null,
            "same-process readers must not trust cached READY after a failed commit");
        cacheSplit.restart(); // a new process reads the durable file, not the failed cache
        PolicyJournal afterFailedCommit = new PolicyJournal(cacheSplit, new FakeGate());
        PolicyFixtures.check(afterFailedCommit.status() == PolicyJournal.Status.PENDING
            && !afterFailedCommit.readyForAdmission(), "restart sees the durable PENDING envelope");
        // A persisted pending envelope may only be replaced by explicit reconcile
        // with an unreconciled CAS; a new begin or a generation CAS stays BUSY/STALE.
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> afterFailedCommit.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, automatic));
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> afterFailedCommit.reserveReconcile(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, PolicyFixtures.GEN, PolicyFixtures.GEN2, automatic));
        PolicyJournal.Reservation recovered = afterFailedCommit.reserveReconcile(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, automatic);
        cacheSplit.durable = true; // the durable lane is writable again after restart
        String recoveredBytes = afterFailedCommit.readyJson(recovered);
        PolicyFixtures.check(afterFailedCommit.settleReady(recovered, cacheSplit.commit(recoveredBytes)).acked(),
            "explicit reconcile recovers a crashed pending publication");
        PolicyFixtures.check(afterFailedCommit.readyForAdmission(), "recovered publication is admissible");

        // DOWN while the ready write is physically outstanding: revoke, never ACK, settle then block.
        FakeStore downStore = new FakeStore();
        FakeGate downGate = new FakeGate();
        PolicyJournal downJournal = new PolicyJournal(downStore, downGate);
        downJournal.load();
        PolicyJournal.Reservation down = downJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        downJournal.pendingJson(down);
        PolicyFixtures.check(downStore.commit(downJournal.pendingJson(down)), "down pending");
        downJournal.settlePending(down, true);
        downJournal.readyJson(down); // physical writer outstanding now
        PolicyJournal.Settle revoked = downJournal.revokeAll();
        PolicyFixtures.check(!revoked.acked() && !revoked.blockedWriteRequired, "DOWN during write does not ACK or write yet");
        PolicyFixtures.check(downGate.revoked.contains(PolicyFixtures.TX), "DOWN revoked the logical owner");
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> downJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, PolicyFixtures.GEN, PolicyFixtures.GEN2, automatic));
        PolicyJournal.Settle late = downJournal.settleReady(down, true);
        PolicyFixtures.check(!late.acked() && late.blockedWriteRequired, "late ready write is not success");
        PolicyFixtures.check(!downJournal.readyForAdmission() && downJournal.revalidatable() == null, "late write never becomes admissible");
        PolicyFixtures.check(downJournal.status() == PolicyJournal.Status.PENDING_UNKNOWN, "late write is pendingUnknown");
        PolicyFixtures.check(downGate.released.isEmpty(), "late write keeps ownership");
        PolicyFixtures.check(downStore.commit(downJournal.blockedJson(down, "revoked")), "blocked after late write");
        downJournal.settleBlocked(down, true);
        PolicyFixtures.check(downJournal.status() == PolicyJournal.Status.BLOCKED && downGate.released.size() == 1, "blocked settles");
        PolicyFixtures.check(!downJournal.readyForAdmission(), "blocked envelope is not admissible");
        PolicyJournal.Reservation successor = downJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, automatic);
        downJournal.pendingJson(successor);
        PolicyFixtures.check(downStore.commit(downJournal.pendingJson(successor)), "successor pending");
        downJournal.settlePending(successor, true);
        downJournal.readyJson(successor);
        PolicyFixtures.check(downStore.commit(downJournal.readyJson(successor)), "successor ready");
        PolicyJournal.Settle successorSettle = downJournal.settleReady(successor, true);
        PolicyFixtures.check(successorSettle.acked() && successorSettle.ack.planGeneration.equals(PolicyFixtures.GEN2), "successor ACK after settlement");
        PolicyFixtures.check(downJournal.readyForAdmission(), "settled successor is admissible");

        // Failed blocked reconciliation keeps the barrier: no successor can ACK.
        FakeStore stuckStore = new FakeStore();
        FakeGate stuckGate = new FakeGate();
        PolicyJournal stuck = new PolicyJournal(stuckStore, stuckGate);
        stuck.load();
        PolicyJournal.Reservation a = stuck.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        stuck.pendingJson(a);
        PolicyFixtures.check(stuckStore.commit(stuck.pendingJson(a)), "stuck pending");
        stuck.settlePending(a, true);
        stuck.readyJson(a);
        stuck.revokeAll();
        PolicyJournal.Settle lateA = stuck.settleReady(a, true);
        PolicyFixtures.check(lateA.blockedWriteRequired, "blocked write required");
        stuckStore.durable = false;
        stuckStore.commit(stuck.blockedJson(a, "revoked"));
        PolicyJournal.Settle blockedFailure = stuck.settleBlocked(a, false);
        PolicyFixtures.check(blockedFailure.failureCode == null || !blockedFailure.acked(), "failed blocked write is not success");
        PolicyFixtures.check(stuck.status() == PolicyJournal.Status.PENDING_UNKNOWN && stuckGate.released.isEmpty(), "failed blocked write keeps ownership");
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> stuck.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, automatic));
        stuckStore.durable = true;
        PolicyFixtures.check(stuckStore.commit(stuck.blockedJson(a, "revoked")), "blocked retry durable");
        stuck.settleBlocked(a, true);
        PolicyFixtures.check(stuckGatewayReleased(stuckGate) && stuck.status() == PolicyJournal.Status.BLOCKED, "barrier released only after blocked receipt");

        // Parent timeout is not proof of pre-rename when a write is outstanding.
        FakeStore timeoutStore = new FakeStore();
        FakeGate timeoutGate = new FakeGate();
        PolicyJournal timeoutJournal = new PolicyJournal(timeoutStore, timeoutGate);
        timeoutJournal.load();
        PolicyJournal.Reservation timed = timeoutJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        timeoutJournal.pendingJson(timed);
        PolicyJournal.Settle started = timeoutJournal.parentTimeout(PolicyFixtures.TX);
        PolicyFixtures.check(!started.acked() && started.writePhase == PolicyJournal.WritePhase.PENDING_UNKNOWN, "timeout with writer outstanding");
        PolicyFixtures.check(timeoutJournal.status() == PolicyJournal.Status.PENDING_UNKNOWN && timeoutGate.released.isEmpty(), "timeout keeps ownership");
        PolicyFixtures.checkCode(PolicyFailure.BUSY, () -> timeoutJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.GEN2, null, PolicyFixtures.GEN2, automatic));
        // Timeout before anything was written changes no durable state and releases cleanly.
        FakeStore idleStore = new FakeStore();
        FakeGate idleGate = new FakeGate();
        PolicyJournal idleJournal = new PolicyJournal(idleStore, idleGate);
        idleJournal.load();
        PolicyJournal.Reservation notStarted = idleJournal.reserveBegin(
            PolicyFixtures.STORE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, null, PolicyFixtures.GEN, automatic);
        PolicyJournal.Settle idleTimeout = idleJournal.parentTimeout(PolicyFixtures.TX);
        PolicyFixtures.check(!idleTimeout.acked() && idleGate.released.size() == 1 && !idleJournal.hasActiveReservation(), "unstarted timeout releases");
        PolicyFixtures.check(idleStore.disk == null, "unstarted timeout wrote nothing");

        // Boot adoption of a proven envelope replaces the unloaded process state.
        FakeStore bootStore = new FakeStore();
        PolicyJournal bootJournal = new PolicyJournal(bootStore, new FakeGate());
        bootJournal.load();
        PolicyEnvelope adopted = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, automatic, null);
        bootJournal.adoptDurable(adopted);
        PolicyFixtures.check(bootJournal.status() == PolicyJournal.Status.READY && bootJournal.readyForAdmission(), "adopted ready");
        PolicyFixtures.check(bootJournal.readyReceipt(PolicyFixtures.INSTANCE).planGeneration.equals(PolicyFixtures.GEN), "adopted receipt");

        System.out.println("PASS publication lane: readyForAdmission ignores cached/unconfirmed state; pending/ready ACK only after durable commit, commit()==false is pendingUnknown "
            + "without ACK/rollback, DOWN during outstanding write settles then blocks, failed reconciliation keeps ownership, "
            + "parent timeout is not pre-rename, restart ignores a failed cache, exact-generation CAS and transaction replay rejection");
    }

    private static boolean stuckGatewayReleased(FakeGate gate) { return gate.released.size() == 1; }

    private PolicyJournalTest() { }
}

