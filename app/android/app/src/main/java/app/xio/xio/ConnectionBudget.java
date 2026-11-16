package app.xio.xio;

import java.util.concurrent.atomic.AtomicBoolean;

/** Relative durations cross the bridge; only this clock creates native deadlines. */
public final class ConnectionBudget {
    public static final long MAX_MILLIS = 30000;
    public interface Clock { long now(); }
    public interface Attempts {
        void connect(int index, ConnectionBudget attempt) throws Exception;
        void cleanup(ConnectionBudget round) throws Exception;
    }
    public static final class Expired extends RuntimeException {
        public Expired() { super("Connection round deadline"); }
    }
    public static final class CleanupIncomplete extends RuntimeException {
        public CleanupIncomplete(Throwable cause) { super("VPN cleanup incomplete", cause); }
    }

    private final Clock clock;
    private final long deadline;
    private final AtomicBoolean cancelled;
    private final ConnectionBudget parent;
    private final long cleanupReserve;

    public ConnectionBudget(long durationMillis, Clock clock) {
        if (durationMillis < 1 || durationMillis > MAX_MILLIS) throw new IllegalArgumentException("Round budget");
        this.clock = clock;
        this.deadline = clock.now() + durationMillis;
        this.cancelled = new AtomicBoolean();
        this.parent = null;
        this.cleanupReserve = Math.min(5000, durationMillis / 5);
    }
    private ConnectionBudget(Clock clock, long deadline, ConnectionBudget parent) {
        this.clock = clock; this.deadline = deadline; this.parent = parent;
        this.cancelled = new AtomicBoolean();
        this.cleanupReserve = Math.min(5000, Math.max(0, deadline - clock.now()) / 5);
    }
    public long availableMillis() {
        return cancelled.get() || (parent != null && parent.availableMillis() == 0)
                ? 0 : Math.max(0, deadline - clock.now());
    }
    /** Cancellation revokes work, not the original cleanup deadline. */
    public long cleanupMillis() { return Math.max(0, deadline - clock.now()); }
    public long remainingMillis() {
        long left = availableMillis();
        if (left == 0) throw new Expired();
        return left;
    }
    public ConnectionBudget cap(long ceilingMillis) {
        if (ceilingMillis < 1) throw new Expired();
        remainingMillis();
        return new ConnectionBudget(clock, Math.min(deadline, clock.now() + ceilingMillis), this);
    }
    public void cancel() { cancelled.set(true); }
    public static boolean canPublishUp(boolean cleanupIncomplete, boolean revoked, ConnectionBudget operation) {
        return !cleanupIncomplete && !revoked && (operation == null || operation.availableMillis() > 0);
    }
    public static boolean canPublishUp(boolean cleanupIncomplete, boolean revoked, ConnectionBudget operation,
                                       long observedEpoch, long currentEpoch) {
        return observedEpoch == currentEpoch && canPublishUp(cleanupIncomplete, revoked, operation);
    }
    public static String mode(String value) {
        if (!"automatic".equals(value) && !"selectedOnly".equals(value)) throw new IllegalArgumentException("Connection policy");
        return value;
    }

    /** This exact loop is used by the Android tile; no fresh root per candidate. */
    public int runCandidates(int count, long perAttemptMillis, Attempts work) throws Exception {
        if (count < 1 || count > 16) throw new IllegalArgumentException("Candidates");
        Exception last = null;
        for (int index = 0; index < count; index++) {
            ConnectionBudget attempt = cap(Math.min(perAttemptMillis, remainingMillis() - cleanupReserve));
            try {
                work.connect(index, attempt);
                attempt.remainingMillis(); // Late success is failure, never active acceptance.
                return index;
            } catch (Exception failure) {
                last = failure;
                try { work.cleanup(this); }
                catch (Exception cleanup) { throw new CleanupIncomplete(cleanup); }
                remainingMillis();
            }
        }
        throw last == null ? new Expired() : last;
    }
}
