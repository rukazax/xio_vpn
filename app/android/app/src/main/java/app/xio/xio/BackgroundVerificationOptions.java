package app.xio.xio;

/** Saved background website consent. Unknown/legacy values never opt in to HTTP. */
public final class BackgroundVerificationOptions {
    /** Existing combined HTTPS + native-readiness verifier, opt-in path only. */
    public interface WebsiteProbe { void verify(long remainingMillis) throws Exception; }
    public interface Handshake { long observedAt() throws Exception; }
    public interface Wait { void pause(long millis) throws Exception; }

    public final boolean siteCheckEnabled;

    private BackgroundVerificationOptions(boolean enabled) {
        siteCheckEnabled = enabled;
    }

    public static BackgroundVerificationOptions fromPlanValue(Object value) {
        // JSONObject.optBoolean coerces strings; a string is not website consent.
        return new BackgroundVerificationOptions(Boolean.TRUE.equals(value));
    }

    public void verify(long started, ConnectionBudget attempt, WebsiteProbe website,
                       Handshake handshake, Wait wait) throws Exception {
        attempt.remainingMillis();
        if (siteCheckEnabled) {
            // The existing combined probe owns HTTPS and fresh-handshake checks.
            // Pass only the SAME attempt's remainder; never renew its deadline.
            website.verify(attempt.remainingMillis());
        } else {
            // Preserve the combined probe's local native-handshake readiness,
            // without opening the user's website or making an auxiliary DNS query.
            while (true) {
                attempt.remainingMillis();
                long observed = handshake.observedAt();
                long left = attempt.remainingMillis(); // Reject cancellation/late success.
                if (observed > 0 && observed >= started - 2000) break;
                wait.pause(Math.min(250, left));
            }
        }
        attempt.remainingMillis();
    }
}
