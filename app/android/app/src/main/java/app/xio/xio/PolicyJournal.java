package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The single serialized native policy persistence authority.
 *
 * <p>Logical transaction validity and physical writer ownership are deliberately
 * different lifetimes. {@link #abort} revokes UI/activation permission
 * immediately, but the reservation keeps owning the physical lane until its IO
 * settles and a BLOCKED envelope is durably written. A successor can never be
 * acknowledged while any predecessor write might still land: a late automatic
 * write can therefore never resurrect an older ready plan after a newer manual
 * ACK, and a {@code commit()==false} never produces a false ACK or a rollback
 * claim.</p>
 *
 * <p>The class performs no IO itself: the lane (Engine.worker on Android) writes
 * exactly the bytes this class returns and reports the durable boolean back.
 * That keeps every check here free of fsync/JNI and lets a pure test replace the
 * store with independent cached/durable state and deferred completion.</p>
 */
public final class PolicyJournal {
    /** Independent cached memory and durable storage; {@code commit} may fail. */
    public interface Store {
        /** Process-visible value: SharedPreferences' cached string. */
        String cached();
        /** Durable write; {@code false} means the cache and disk may disagree. */
        boolean commit(String value);
    }

    /** The existing PublicationLease policy reservation/ticket, kept short-held. */
    public interface Gate {
        void reservePolicy(String transactionId);
        void revokePolicy(String transactionId);
        void releasePolicy(String transactionId);
    }

    public enum Status { ABSENT, PENDING, PENDING_UNKNOWN, READY, BLOCKED }

    /** WIRE-V2 publication outcomes. Only {@code committed} is an ACK. */
    public enum WritePhase {
        BEFORE_RENAME("beforeRename"),
        PENDING_UNKNOWN("pendingUnknown"),
        RENAMED_NATIVE_UNCONFIRMED("renamedNativeUnconfirmed"),
        COMMITTED("committed");

        public final String wire;

        WritePhase(String wire) { this.wire = wire; }
    }

    public static final class Ack {
        public final String transactionId;
        public final String planGeneration;
        public final PublicationPhase phase;
        public final String storeIdentity;
        public final String controllerNonce;

        Ack(Reservation reservation, PublicationPhase phase) {
            this.transactionId = reservation.transactionId;
            this.planGeneration = reservation.planGeneration;
            this.phase = phase;
            this.storeIdentity = reservation.storeIdentity;
            this.controllerNonce = reservation.controllerNonce;
        }
    }

    public static final class Settle {
        public final Ack ack;
        public final boolean blockedWriteRequired;
        public final String failureCode;
        public final WritePhase writePhase;

        Settle(Ack ack, boolean blockedWriteRequired, String failureCode, WritePhase writePhase) {
            this.ack = ack;
            this.blockedWriteRequired = blockedWriteRequired;
            this.failureCode = failureCode;
            this.writePhase = writePhase;
        }

        public boolean acked() { return ack != null; }
    }

    /** One publication reservation; the physical ticket lives until blocked reconciliation. */
    public static final class Reservation {
        public final String storeIdentity;
        public final String controllerNonce;
        public final String transactionId;
        public final String expectedGeneration;
        public final String planGeneration;
        public final PolicyPlan plan;
        final boolean reconcile;

        boolean writeStarted;
        boolean writeOutstanding;
        boolean revoked;
        boolean pendingAcked;
        boolean readyAcked;
        /** This reconcile reservation replaces a persisted pending state, so a
         *  rejected proposal must leave a durable BLOCKED receipt, not the old
         *  pending envelope. */
        boolean supersedesPersistedState;

        Reservation(String storeIdentity, String controllerNonce, String transactionId, String expectedGeneration,
                    String planGeneration, PolicyPlan plan, boolean reconcile) {
            this.storeIdentity = storeIdentity;
            this.controllerNonce = controllerNonce;
            this.transactionId = transactionId;
            this.expectedGeneration = expectedGeneration;
            this.planGeneration = planGeneration;
            this.plan = plan;
            this.reconcile = reconcile;
        }

        public String fingerprint() { return plan.sha256() + "/" + planGeneration; }

        public boolean writeStarted() { return writeStarted; }
        public boolean writeOutstanding() { return writeOutstanding; }
        public boolean revoked() { return revoked; }
        public boolean pendingAcked() { return pendingAcked; }
        public boolean readyAcked() { return readyAcked; }
        public boolean isReconcile() { return reconcile; }
        public boolean supersedesPersistedState() { return supersedesPersistedState; }
    }

    private final Store store;
    private final Gate gate;
    private final Map<String, String> retired = new LinkedHashMap<>();

    private boolean loaded;
    private boolean versionedOwnership;
    private Status status = Status.ABSENT;
    private PolicyEnvelope envelope;
    private String error;
    private Reservation active;

    public PolicyJournal(Store store, Gate gate) {
        this.store = Objects.requireNonNull(store, "store");
        this.gate = Objects.requireNonNull(gate, "gate");
    }

    // ------------------------------------------------------------------ load

    /** Reads the persisted envelope once per process; never trusts an absent legacy default. */
    public synchronized void load() {
        if (loaded) return;
        loaded = true;
        String raw = store.cached();
        versionedOwnership = raw != null;
        if (raw == null) {
            status = Status.ABSENT;
            envelope = null;
            return;
        }
        try {
            envelope = PolicyEnvelope.parse(StrictJson.parse(raw), "envelope");
            status = statusOf(envelope.phase);
        } catch (RuntimeException failure) {
            envelope = null;
            status = Status.BLOCKED;
            error = "Unreadable saved policy envelope";
        }
    }

    private static Status statusOf(PublicationPhase phase) {
        switch (phase) {
            case PENDING: return Status.PENDING;
            case PENDING_UNKNOWN: return Status.PENDING_UNKNOWN;
            case READY: return Status.READY;
            default: return Status.BLOCKED;
        }
    }

    // ----------------------------------------------------------------- state

    public synchronized Status status() { load(); return status; }

    public synchronized boolean versionedOwnership() { load(); return versionedOwnership; }

    public synchronized String error() { load(); return error; }

    public synchronized PolicyEnvelope envelope() { load(); return envelope; }

    /**
     * The only safe answer to "may a reader trust this as a committed plan?".
     * Cached/READY-looking content is not enough: an outstanding or unconfirmed
     * write, a revoked publication or a blocked reconciliation all answer false.
     */
    public synchronized boolean readyForAdmission() {
        load();
        return status == Status.READY && envelope != null && envelope.phase == PublicationPhase.READY
            && active == null;
    }

    /** A READY envelope that may be (re)validated: never while a write is unconfirmed. */
    public synchronized PolicyEnvelope revalidatable() {
        load();
        if (active != null || envelope == null || envelope.phase != PublicationPhase.READY) return null;
        return status == Status.READY || status == Status.BLOCKED ? envelope : null;
    }

    public synchronized boolean hasActiveReservation() { return active != null; }

    public synchronized void invalidateInMemory(String reason) {
        if (status == Status.READY) {
            status = Status.BLOCKED;
            error = reason;
        }
    }

    /**
     * Adopts a READY envelope that boot/Tile reconciliation proved against the
     * durable document. Process restart changes the instance nonce, so a fresh
     * process must re-prove the document pair before autonomous admission.
     */
    public synchronized void adoptDurable(PolicyEnvelope ready) {
        load();
        if (ready == null || ready.phase != PublicationPhase.READY) throw PolicyFailure.invalid("Not a ready envelope");
        if (active != null) throw PolicyFailure.busy("A policy publication is outstanding");
        envelope = ready;
        versionedOwnership = true;
        status = Status.READY;
        error = null;
    }

    public synchronized PolicyReceipt readyReceipt(String instanceNonce) {
        load();
        if (status != Status.READY || envelope == null || envelope.phase != PublicationPhase.READY)
            throw PolicyFailure.unknown("No committed connection policy");
        return new PolicyReceipt(envelope.storeIdentity, instanceNonce, envelope.controllerNonce,
            envelope.transactionId, envelope.planGeneration);
    }

    // ----------------------------------------------------------------- begin

    public synchronized Reservation reserveBegin(String storeIdentity, String controllerNonce, String transactionId,
                                                 String expectedGeneration, String planGeneration, PolicyPlan plan) {
        return reserve(storeIdentity, controllerNonce, transactionId, expectedGeneration, planGeneration, plan, false);
    }

    public synchronized Reservation reserveReconcile(String storeIdentity, String controllerNonce, String transactionId,
                                                      String expectedGeneration, String planGeneration, PolicyPlan plan) {
        return reserve(storeIdentity, controllerNonce, transactionId, expectedGeneration, planGeneration, plan, true);
    }

    private Reservation reserve(String storeIdentity, String controllerNonce, String transactionId,
                                String expectedGeneration, String planGeneration, PolicyPlan plan, boolean reconcile) {
        load();
        PolicyReceipt.requireHex(storeIdentity, 64, "storeIdentity");
        PolicyReceipt.requireHex(controllerNonce, 32, "controllerNonce");
        PolicyReceipt.requireHex(transactionId, 32, "transactionId");
        PolicyReceipt.requireHex(planGeneration, 32, "planGeneration");
        if (expectedGeneration != null) PolicyReceipt.requireHex(expectedGeneration, 32, "expectedGeneration");
        if (plan == null) throw PolicyFailure.invalid("Plan is required");
        if (active != null) {
            // Exact idempotent retry of the same proposal returns the same reservation.
            if (active.transactionId.equals(transactionId) && active.fingerprint().equals(plan.sha256() + "/" + planGeneration)
                && !active.revoked)
                return active;
            throw PolicyFailure.busy("Another policy publication is outstanding");
        }
        if (status == Status.PENDING || status == Status.PENDING_UNKNOWN) {
            // A persisted pending/en-route envelope has no live writer after a
            // restart, so only an explicit reconciliation may replace it, and only
            // against an unreconciled CAS (expectedGeneration == null).
            if (!reconcile || expectedGeneration != null)
                throw PolicyFailure.busy("Reconcile the pending connection policy first");
        }
        if (status == Status.READY) {
            if (envelope == null || !envelope.planGeneration.equals(expectedGeneration))
                throw PolicyFailure.stale("Expected generation does not match the committed policy");
        } else if (expectedGeneration != null) {
            throw PolicyFailure.stale("No committed generation to compare");
        }
        String previous = retired.get(transactionId);
        if (previous != null && !previous.equals(plan.sha256() + "/" + planGeneration))
            throw PolicyFailure.stale("Transaction was already used for different content");
        gate.reservePolicy(transactionId);
        active = new Reservation(storeIdentity, controllerNonce, transactionId, expectedGeneration, planGeneration, plan, reconcile);
        active.supersedesPersistedState = reconcile && (status == Status.PENDING || status == Status.PENDING_UNKNOWN);
        return active;
    }

    // ----------------------------------------------------------------- write

    /** PENDING envelope bytes; the lane commits exactly this value. */
    public synchronized String pendingJson(Reservation reservation) {
        requireActive(reservation);
        if (reservation.reconcile) throw PolicyFailure.invalid("A reconcile writes ready directly");
        reservation.writeStarted = true;
        reservation.writeOutstanding = true;
        return buildEnvelope(reservation, PublicationPhase.PENDING, null).canonicalJson();
    }

    /** READY envelope bytes for commit or reconcile. */
    public synchronized String readyJson(Reservation reservation) {
        requireActive(reservation);
        if (!reservation.writeStarted && !reservation.reconcile)
            throw PolicyFailure.invalid("A pending envelope must be acknowledged first");
        reservation.writeStarted = true;
        reservation.writeOutstanding = true;
        return buildEnvelope(reservation, PublicationPhase.READY, null).canonicalJson();
    }

    /** BLOCKED envelope bytes used after revocation, timeout, or a failed commit. */
    public synchronized String blockedJson(Reservation reservation, String reason) {
        requireActive(reservation);
        reservation.writeOutstanding = true;
        return buildEnvelope(reservation, PublicationPhase.BLOCKED, reason).canonicalJson();
    }

    private PolicyEnvelope buildEnvelope(Reservation reservation, PublicationPhase phase, String reason) {
        PolicyPlan plan = phase == PublicationPhase.BLOCKED ? null : reservation.plan;
        return new PolicyEnvelope(phase, reservation.storeIdentity, instanceNonce(), reservation.controllerNonce,
            reservation.transactionId, reservation.planGeneration, reservation.expectedGeneration, plan, reason);
    }

    /** The writing instance nonce; Android replaces this with the Engine nonce. */
    private String instanceNonce = "00000000000000000000000000000000";

    public synchronized void instanceNonce(String nonce) {
        PolicyReceipt.requireHex(nonce, 32, "instanceNonce");
        this.instanceNonce = nonce;
    }

    private synchronized String instanceNonce() { return instanceNonce; }

    // ---------------------------------------------------------------- settle

    public synchronized Settle settlePending(Reservation reservation, boolean durable) {
        requireActive(reservation);
        reservation.writeOutstanding = false;
        if (!durable) {
            status = Status.PENDING_UNKNOWN;
            error = "Pending policy write is unconfirmed";
            return new Settle(null, true, PolicyFailure.PERSISTENCE, WritePhase.PENDING_UNKNOWN);
        }
        if (reservation.revoked) {
            status = Status.PENDING_UNKNOWN;
            error = "Policy write settled after revocation";
            return new Settle(null, true, PolicyFailure.STALE, WritePhase.PENDING_UNKNOWN);
        }
        PolicyEnvelope pending = buildEnvelope(reservation, PublicationPhase.PENDING, null);
        envelope = pending;
        status = Status.PENDING;
        reservation.pendingAcked = true;
        return new Settle(new Ack(reservation, PublicationPhase.PENDING), false, null, WritePhase.COMMITTED);
    }

    public synchronized Settle settleReady(Reservation reservation, boolean durable) {
        requireActive(reservation);
        reservation.writeOutstanding = false;
        if (!durable) {
            status = Status.PENDING_UNKNOWN;
            error = "Ready policy write is unconfirmed";
            return new Settle(null, true, PolicyFailure.PERSISTENCE, WritePhase.PENDING_UNKNOWN);
        }
        if (reservation.revoked) {
            // The write landed but the owner was revoked: never publish success.
            status = Status.PENDING_UNKNOWN;
            error = "Ready policy write settled after revocation";
            return new Settle(null, true, PolicyFailure.STALE, WritePhase.PENDING_UNKNOWN);
        }
        PolicyEnvelope ready = buildEnvelope(reservation, PublicationPhase.READY, null);
        envelope = ready;
        status = Status.READY;
        reservation.readyAcked = true;
        finished(reservation);
        return new Settle(new Ack(reservation, PublicationPhase.READY), false, null, WritePhase.COMMITTED);
    }

    public synchronized Settle settleBlocked(Reservation reservation, boolean durable) {
        if (reservation == null || reservation != active) {
            // A superseded settlement can never publish or release anything.
            return new Settle(null, false, PolicyFailure.STALE, WritePhase.PENDING_UNKNOWN);
        }
        reservation.writeOutstanding = false;
        if (!durable) {
            status = Status.PENDING_UNKNOWN;
            error = "Blocked reconciliation is unconfirmed";
            return new Settle(null, false, PolicyFailure.PERSISTENCE, WritePhase.PENDING_UNKNOWN);
        }
        PolicyEnvelope blocked = buildEnvelope(reservation, PublicationPhase.BLOCKED, "Publication revoked or failed");
        envelope = blocked;
        status = Status.BLOCKED;
        finished(reservation);
        return new Settle(null, false, null, WritePhase.COMMITTED);
    }

    /** Revokes the logical owner immediately; the physical ticket stays owned. */
    public synchronized Settle abort(String transactionId) {
        if (active == null || !active.transactionId.equals(transactionId))
            return new Settle(null, false, null, WritePhase.PENDING_UNKNOWN);
        active.revoked = true;
        gate.revokePolicy(transactionId);
        if (active.writeOutstanding) {
            // The settle that follows this write reports the blocked write itself.
            return new Settle(null, false, null, WritePhase.PENDING_UNKNOWN);
        }
        if (!active.writeStarted && !active.pendingAcked) {
            // Nothing new reached the lane. A persisted pending envelope still has
            // to be replaced by a durable BLOCKED receipt; otherwise a successor
            // could never be admitted without deleting preferences by hand.
            if (active.supersedesPersistedState) {
                status = Status.PENDING_UNKNOWN;
                return new Settle(null, true, null, WritePhase.PENDING_UNKNOWN);
            }
            finished(active);
            return new Settle(null, false, null, WritePhase.BEFORE_RENAME);
        }
        return new Settle(null, true, null, WritePhase.PENDING_UNKNOWN);
    }

    /** Bounded caller wait expired while the physical write may still be outstanding. */
    public synchronized Settle parentTimeout(String transactionId) {
        if (active == null || !active.transactionId.equals(transactionId))
            return new Settle(null, false, null, WritePhase.PENDING_UNKNOWN);
        if (!active.writeStarted && !active.pendingAcked) {
            active.revoked = true;
            if (active.supersedesPersistedState) {
                status = Status.PENDING_UNKNOWN;
                gate.revokePolicy(transactionId);
                return new Settle(null, true, PolicyFailure.PERSISTENCE, WritePhase.PENDING_UNKNOWN);
            }
            finished(active);
            return new Settle(null, false, null, WritePhase.PENDING_UNKNOWN);
        }
        status = Status.PENDING_UNKNOWN;
        active.revoked = true;
        gate.revokePolicy(transactionId);
        return new Settle(null, !active.writeOutstanding, PolicyFailure.PERSISTENCE, WritePhase.PENDING_UNKNOWN);
    }

    /** DOWN/dispose: revoke every logical policy owner without touching physical IO. */
    public synchronized Settle revokeAll() {
        if (active == null) return new Settle(null, false, null, WritePhase.COMMITTED);
        active.revoked = true;
        gate.revokePolicy(active.transactionId);
        if (active.writeOutstanding) return new Settle(null, false, null, WritePhase.PENDING_UNKNOWN);
        if (!active.writeStarted && !active.pendingAcked) {
            if (active.supersedesPersistedState) {
                status = Status.PENDING_UNKNOWN;
                return new Settle(null, true, PolicyFailure.STALE, WritePhase.PENDING_UNKNOWN);
            }
            finished(active);
            return new Settle(null, false, null, WritePhase.BEFORE_RENAME);
        }
        return new Settle(null, true, null, WritePhase.PENDING_UNKNOWN);
    }

    public synchronized Reservation active() { return active; }

    /**
     * Commit must echo EVERY transaction-bound identity of the active reservation.
     * Comparing only transaction id, generation and plan bytes would let a foreign
     * controller/store or a different CAS transfer publication authority.
     */
    public synchronized Reservation requireSameProposal(String storeIdentity, String controllerNonce, String transactionId,
                                                       String expectedGeneration, String planGeneration, PolicyPlan plan) {
        if (active == null) throw PolicyFailure.stale("No publication reservation is current");
        if (plan == null) throw PolicyFailure.invalid("Plan is required");
        if (!active.storeIdentity.equals(storeIdentity)
            || !active.controllerNonce.equals(controllerNonce)
            || !active.transactionId.equals(transactionId)
            || !Objects.equals(active.expectedGeneration, expectedGeneration)
            || !active.planGeneration.equals(planGeneration)
            || !active.plan.sha256().equals(plan.sha256()))
            throw PolicyFailure.stale("Commit does not match the reserved proposal");
        return active;
    }

    // -------------------------------------------------------------- internal

    private void requireActive(Reservation reservation) {
        if (reservation == null || reservation != active)
            throw PolicyFailure.stale("Publication reservation is not current");
    }

    private void finished(Reservation reservation) {
        retire(reservation.transactionId, reservation.fingerprint());
        if (active == reservation) active = null;
        gate.releasePolicy(reservation.transactionId);
    }

    private void retire(String transactionId, String fingerprint) {
        retired.put(transactionId, fingerprint);
        while (retired.size() > 16) {
            java.util.Iterator<String> keys = retired.keySet().iterator();
            keys.next();
            keys.remove();
        }
    }

    /** Clears the in-memory reservation after an external settle; test/lane helper. */
    public synchronized void forget() { active = null; }
}
