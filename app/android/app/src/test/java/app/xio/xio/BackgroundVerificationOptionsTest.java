package app.xio.xio;

/** Offline, deterministic fake clock/handshake/website; no Android or sockets. */
public final class BackgroundVerificationOptionsTest {
    private static final class Clock implements ConnectionBudget.Clock {
        long now;
        public long now() { return now; }
    }
    private static int assertions;
    private static void check(boolean condition) {
        assertions++;
        if (!condition) throw new AssertionError();
    }
    public static void main(String[] args) throws Exception {
        Object[] disabled = {null, Boolean.FALSE, "true", "false", 1, 0, new Object()};
        for (Object raw : disabled) {
            BackgroundVerificationOptions options = BackgroundVerificationOptions.fromPlanValue(raw);
            check(!options.siteCheckEnabled);
            Clock clock = new Clock();
            final int[] calls = {0, 0};
            options.verify(10000, new ConnectionBudget(1000, clock),
                    remaining -> { calls[0]++; throw new AssertionError("Opt-out HTTP"); },
                    () -> { calls[1]++; return 10000; }, millis -> { throw new AssertionError("Fresh handshake waited"); });
            check(calls[0] == 0 && calls[1] == 1);
        }
        BackgroundVerificationOptions off = BackgroundVerificationOptions.fromPlanValue(false);
        BackgroundVerificationOptions on = BackgroundVerificationOptions.fromPlanValue(true);
        check(on.siteCheckEnabled);

        // Zero/error sentinels are never readiness, even near the Unix epoch.
        for (long started : new long[]{0, 1000, 2000}) {
            for (long missing : new long[]{0, -1, -2, -3}) {
                Clock boundary = new Clock();
                try {
                    off.verify(started, new ConnectionBudget(1000, boundary),
                            left -> { throw new AssertionError("Opt-out HTTP"); },
                            () -> missing, millis -> boundary.now += millis);
                    throw new AssertionError("Missing handshake accepted: started=" + started + " observed=" + missing);
                } catch (ConnectionBudget.Expired expected) { check(boundary.now == 1000); }
            }
            Clock positive = new Clock();
            off.verify(started, new ConnectionBudget(1000, positive),
                    left -> { throw new AssertionError("Opt-out HTTP"); },
                    () -> 1, millis -> { throw new AssertionError("Positive fresh handshake rejected"); });
            check(positive.now == 0);
        }

        Clock never = new Clock();
        final int[] website = {0};
        try {
            off.verify(10000, new ConnectionBudget(1000, never),
                    left -> { website[0]++; throw new AssertionError("Opt-out HTTP"); },
                    () -> 0, millis -> never.now += millis);
            throw new AssertionError("Unready native tunnel accepted");
        } catch (ConnectionBudget.Expired expected) { check(never.now == 1000 && website[0] == 0); }

        Clock delayed = new Clock();
        final int[] polls = {0};
        off.verify(10000, new ConnectionBudget(1000, delayed),
                left -> { throw new AssertionError("Opt-out HTTP"); },
                () -> ++polls[0] == 1 ? 7999 : 8000,
                millis -> { check(millis == 250); delayed.now += millis; });
        check(polls[0] == 2 && delayed.now == 250); // Same epoch freshness tolerance as ConnectionProbe.

        Clock cancelledClock = new Clock();
        ConnectionBudget cancelled = new ConnectionBudget(1000, cancelledClock);
        cancelled.cancel();
        for (BackgroundVerificationOptions options : new BackgroundVerificationOptions[]{off, on}) {
            try {
                options.verify(10000, cancelled, left -> { throw new AssertionError("Cancelled HTTP"); },
                        () -> { throw new AssertionError("Cancelled handshake"); }, millis -> {});
                throw new AssertionError("Cancelled round accepted");
            } catch (ConnectionBudget.Expired expected) { check(true); }
        }

        ConnectionBudget duringWait = new ConnectionBudget(1000, new Clock());
        final int[] waitPolls = {0};
        try {
            off.verify(10000, duringWait, left -> { throw new AssertionError("Opt-out HTTP"); },
                    () -> { waitPolls[0]++; return 0; }, millis -> duringWait.cancel());
            throw new AssertionError("Cancellation during poll wait ignored");
        } catch (ConnectionBudget.Expired expected) { check(waitPolls[0] == 1); }

        ConnectionBudget duringRead = new ConnectionBudget(1000, new Clock());
        try {
            off.verify(10000, duringRead, left -> { throw new AssertionError("Opt-out HTTP"); },
                    () -> { duringRead.cancel(); return 10000; }, millis -> {});
            throw new AssertionError("Late handshake accepted after cancellation");
        } catch (ConnectionBudget.Expired expected) { check(true); }

        Clock trueClock = new Clock();
        ConnectionBudget trueBudget = new ConnectionBudget(1000, trueClock);
        trueClock.now = 400;
        final int[] trueCalls = {0};
        on.verify(10000, trueBudget, remaining -> { check(remaining == 600); trueCalls[0]++; },
                () -> { throw new AssertionError("Existing combined probe owns true readiness"); }, millis -> {});
        check(trueCalls[0] == 1);
        Exception probeError = new Exception("fixture website failure");
        try {
            on.verify(10000, trueBudget, left -> { throw probeError; }, () -> 10000, millis -> {});
            throw new AssertionError("Opt-in website failure swallowed");
        } catch (Exception expected) { check(expected == probeError); }
        try {
            on.verify(10000, trueBudget, left -> trueClock.now = 1001, () -> 10000, millis -> {});
            throw new AssertionError("Late website success renewed budget");
        } catch (ConnectionBudget.Expired expected) { check(true); }

        ConnectionBudget duringWebsite = new ConnectionBudget(1000, new Clock());
        try {
            on.verify(10000, duringWebsite, left -> duringWebsite.cancel(), () -> 10000, millis -> {});
            throw new AssertionError("Website success accepted after cancellation");
        } catch (ConnectionBudget.Expired expected) { check(true); }
        ConnectionBudget root = new ConnectionBudget(1000, new Clock());
        ConnectionBudget child = root.cap(500);
        root.cancel();
        try {
            on.verify(10000, child, left -> { throw new AssertionError("Parent-cancelled HTTP"); },
                    () -> 10000, millis -> {});
            throw new AssertionError("Parent cancellation ignored");
        } catch (ConnectionBudget.Expired expected) { check(true); }

        Clock fallbackClock = new Clock();
        final int[] fallback = {0, 0};
        int accepted = new ConnectionBudget(30000, fallbackClock).runCandidates(2, 15000,
                new ConnectionBudget.Attempts() {
                    public void connect(int index, ConnectionBudget attempt) throws Exception {
                        on.verify(10000, attempt, left -> {
                            fallback[0]++;
                            if (index == 0) throw new Exception("first website failed");
                        }, () -> 10000, millis -> {});
                    }
                    public void cleanup(ConnectionBudget round) { fallback[1]++; }
                });
        check(accepted == 1 && fallback[0] == 2 && fallback[1] == 1);
        System.out.println("BackgroundVerificationOptions: " + assertions + " checks PASS (offline; zero real HTTP/DNS/wait)");
    }
}
