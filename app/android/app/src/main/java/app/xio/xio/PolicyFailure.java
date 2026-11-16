package app.xio.xio;

/**
 * Coded admission/publication failure. The code is the wire error code; the
 * message stays human-readable and never implies that a physical writer was
 * released or that anything was rolled back.
 */
public final class PolicyFailure extends RuntimeException {
    public static final String BUSY = "POLICY_BUSY";
    public static final String UNSUPPORTED = "POLICY_UNSUPPORTED";
    public static final String STALE = "POLICY_STALE";
    public static final String UNKNOWN = "POLICY_UNKNOWN";
    public static final String PERSISTENCE = "POLICY_PERSISTENCE";
    public static final String INVALID = "POLICY_INVALID";

    public final String code;

    public PolicyFailure(String code, String message) { super(message); this.code = code; }

    public PolicyFailure(String code, String message, Throwable cause) { super(message, cause); this.code = code; }

    static PolicyFailure busy(String message) { return new PolicyFailure(BUSY, message); }
    static PolicyFailure stale(String message) { return new PolicyFailure(STALE, message); }
    static PolicyFailure unknown(String message) { return new PolicyFailure(UNKNOWN, message); }
    static PolicyFailure persistence(String message) { return new PolicyFailure(PERSISTENCE, message); }
    static PolicyFailure invalid(String message) { return new PolicyFailure(INVALID, message); }
}
