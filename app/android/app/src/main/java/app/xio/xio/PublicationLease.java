package app.xio.xio;

import java.util.HashSet;
import java.util.Set;

/** Pure, short-held admission gate. Never performs JNI, storage or teardown. */
public final class PublicationLease {
    private long admissionEpoch;
    private long epoch;
    private boolean revoked;
    private String owner;
    private ConnectionBudget current;
    private int cancellations;
    private final Set<ConnectionBudget> requests = new HashSet<>();

    /** Policy publication reservation: a distinct identity from every epoch here. */
    private PolicyTicket policy;
    /** Counted, non-exclusive config/routing mutation intents that fence READY admission. */
    private int mutations;
    private long policyEpoch;

    public static final class PolicyTicket {
        public final String transactionId;
        boolean revoked;
        PolicyTicket(String transactionId) { this.transactionId = transactionId; }
        public boolean revoked() { return revoked; }
    }

    public synchronized long register(ConnectionBudget budget) {
        if (policy != null) throw new IllegalStateException("Connection policy publication in progress");
        if (mutations != 0) throw new IllegalStateException("Connection settings are being saved");
        requests.add(budget);
        return admissionEpoch;
    }
    public synchronized long admissionToken() { return admissionEpoch; }
    public synchronized long token() { return epoch; }
    public synchronized long begin(long admission, ConnectionBudget budget) { return begin(admission, budget, null); }
    public synchronized long begin(long admission, ConnectionBudget budget, String roundId) {
        if (admission != admissionEpoch) throw new ConnectionBudget.Expired();
        if (cancellations != 0) throw new IllegalStateException("VPN cancellation incomplete");
        if (policy != null) throw new IllegalStateException("Connection policy publication in progress");
        if (mutations != 0) throw new IllegalStateException("Connection settings are being saved");
        budget.remainingMillis();
        owner = roundId;
        current = budget;
        revoked = false;
        return ++epoch;
    }
    public synchronized boolean owns(String roundId, ConnectionBudget budget) {
        return java.util.Objects.equals(owner, roundId) && current == budget;
    }
    /** Failed child retirement is not external DOWN: never cancel its parent. */
    public synchronized boolean retire(String roundId, ConnectionBudget expected) {
        if (!java.util.Objects.equals(owner, roundId) || (expected != null && current != expected)) return false;
        invalidate();
        if (current != null) current.cancel();
        return true;
    }
    /** Reserves the existing native cancel owner without holding this monitor in JNI. */
    public synchronized void reserveCancellation() { ++cancellations; }
    public synchronized void finishCancellation() {
        if (cancellations <= 0) throw new IllegalStateException("Cancellation owner");
        --cancellations;
    }
    public synchronized boolean idle() { return cancellations == 0; }
    public synchronized void invalidate() { ++epoch; revoked = true; }
    public synchronized void revoke() {
        ++admissionEpoch;
        invalidate();
        if (policy != null) policy.revoked = true; // Logical only: physical writer stays owned.
        for (ConnectionBudget budget : requests) budget.cancel();
        requests.clear();
    }
    public synchronized void release(ConnectionBudget budget) { requests.remove(budget); }
    public synchronized boolean accepts(long token) { return token == epoch && !revoked; }

    // ------------------------------------------------------- policy lifecycle

    /**
     * Reserves the one policy publication lane. Quiescence is checked from the
     * gate's own registrations, NOT from {@link #idle()} (which only tracks
     * cancellations): no request, no outstanding cancellation, no active
     * publication owner, no config mutation, no previous reservation.
     */
    public synchronized PolicyTicket reservePolicy(String transactionId) {
        if (policy != null) throw new IllegalStateException("Connection policy publication in progress");
        if (cancellations != 0) throw new IllegalStateException("VPN cancellation incomplete");
        if (!requests.isEmpty()) throw new IllegalStateException("Connection request outstanding");
        if (current != null && !revoked) throw new IllegalStateException("VPN publication is active");
        if (mutations != 0) throw new IllegalStateException("Connection settings are being saved");
        policy = new PolicyTicket(transactionId);
        ++policyEpoch;
        return policy;
    }
    public synchronized void revokePolicy(String transactionId) {
        if (policy != null && policy.transactionId.equals(transactionId)) policy.revoked = true;
    }
    public synchronized void releasePolicy(String transactionId) {
        if (policy != null && policy.transactionId.equals(transactionId)) policy = null;
    }
    public synchronized boolean policyReserved() { return policy != null; }
    public synchronized boolean policyRevoked(String transactionId) {
        return policy != null && policy.transactionId.equals(transactionId) && policy.revoked;
    }
    public synchronized long policyEpoch() { return policyEpoch; }

    /** Synchronous fence: READY admission is refused until the exact token settles. */
    public synchronized long beginConfigMutation() {
        ++mutations;
        ++policyEpoch;
        return policyEpoch;
    }
    public synchronized void endConfigMutation(long token) {
        if (mutations > 0) --mutations;
    }
    public synchronized int configMutations() { return mutations; }
    public synchronized boolean admissionOpen() { return policy == null && mutations == 0; }
}
