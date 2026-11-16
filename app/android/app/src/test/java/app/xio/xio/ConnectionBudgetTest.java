package app.xio.xio;

/** Standalone deterministic JVM test; no Android, Gradle, socket or real wait. */
public final class ConnectionBudgetTest {
    static final class Clock implements ConnectionBudget.Clock {
        long time;
        public long now() { return time; }
    }
    static void check(boolean value) { if (!value) throw new AssertionError(); }
    public static void main(String[] args) throws Exception {
        Clock clock = new Clock();
        ConnectionBudget round = new ConnectionBudget(30000, clock);
        ConnectionBudget first = round.cap(15000);
        clock.time = 10000;
        check(first.remainingMillis() == 5000 && round.remainingMillis() == 20000);
        ConnectionBudget second = round.cap(60000);
        clock.time = 29999;
        check(second.remainingMillis() == 1);
        clock.time = 30000;
        try { second.remainingMillis(); throw new AssertionError(); } catch (ConnectionBudget.Expired expected) {}
        check(round.availableMillis() == 0);

        clock.time = 0;
        final ConnectionBudget cumulative = new ConnectionBudget(30000, clock);
        final int[] counts = {0,0};
        try {
            cumulative.runCandidates(16,15000,new ConnectionBudget.Attempts() {
                public void connect(int index,ConnectionBudget attempt) {
                    counts[0]++; clock.time += attempt.remainingMillis();
                    throw new IllegalStateException("fake dial failed");
                }
                public void cleanup(ConnectionBudget owner) { counts[1]++; }
            });
            throw new AssertionError();
        } catch (ConnectionBudget.Expired expected) {}
        check(clock.time == 25000 && counts[0] == 2 && counts[1] == 2);
        check(cumulative.cleanupMillis() == 5000); // Reserved INSIDE, not after the round.
        boolean queuedUp = true;
        clock.time = 0;
        ConnectionBudget queued = new ConnectionBudget(30000,clock);
        clock.time = 30000;
        check(!(queuedUp && ConnectionBudget.canPublishUp(false,false,queued)));
        check(!(queuedUp && ConnectionBudget.canPublishUp(false,true,null)));
        check(!(queuedUp && ConnectionBudget.canPublishUp(true,false,null)));
        check(!ConnectionBudget.canPublishUp(false,false,null,1,2));
        check(ConnectionBudget.canPublishUp(false,false,null,2,2));

        clock.time = 0;
        ConnectionBudget cancelled = new ConnectionBudget(30000,clock);
        ConnectionBudget child = cancelled.cap(10000);
        cancelled.cancel();
        check(cancelled.availableMillis() == 0 && child.availableMillis() == 0);
        try { child.remainingMillis(); throw new AssertionError(); } catch (ConnectionBudget.Expired expected) {}

        clock.time = 0;
        final int[] fallback = {0};
        int accepted = new ConnectionBudget(30000,clock).runCandidates(2,15000,new ConnectionBudget.Attempts() {
            public void connect(int index,ConnectionBudget attempt) {
                fallback[0]++;
                if (index == 0) { attempt.cancel(); throw new IllegalStateException("failed attempt revoked"); }
            }
            public void cleanup(ConnectionBudget owner) { check(owner.remainingMillis() == 30000); }
        });
        check(accepted == 1 && fallback[0] == 2); // Child revocation must not cancel automatic fallback.

        clock.time = 0;
        final int[] late = {0};
        try {
            new ConnectionBudget(30000,clock).runCandidates(2,30000,new ConnectionBudget.Attempts() {
                public void connect(int index,ConnectionBudget attempt) { late[0]++; clock.time=30001; }
                public void cleanup(ConnectionBudget owner) { throw new IllegalStateException("unjoined cleanup"); }
            });
            throw new AssertionError();
        } catch (ConnectionBudget.CleanupIncomplete expected) {}
        check(late[0] == 1); // A competing activation must not follow cleanup failure.
        check(ConnectionBudget.mode("selectedOnly").equals("selectedOnly"));
        check(ConnectionBudget.mode("automatic").equals("automatic"));
        try { ConnectionBudget.mode("manual"); throw new AssertionError(); } catch (IllegalArgumentException expected) {}
        System.out.println("ConnectionBudget: cumulative deadline, child cancellation/fallback, publication epochs, late success and cleanup reservation PASS");
    }
}
