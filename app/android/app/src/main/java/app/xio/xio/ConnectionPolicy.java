package app.xio.xio;

import java.util.List;

/**
 * The saved user intent: {@code automatic} may try other profiles/protocols,
 * {@code selectedOnly} may only ever try the selected profile. The root
 * connection budget is exactly the accepted 30 seconds and is not a knob.
 */
public final class ConnectionPolicy {
    public static final long ROUND_MILLIS = ConnectionBudget.MAX_MILLIS;

    public final String mode;
    public final long roundMillis;

    private ConnectionPolicy(String mode, long roundMillis) {
        this.mode = mode;
        this.roundMillis = roundMillis;
    }

    public static ConnectionPolicy of(String mode) { return parse(mode, ROUND_MILLIS); }

    public static ConnectionPolicy automatic() { return new ConnectionPolicy("automatic", ROUND_MILLIS); }

    public static ConnectionPolicy parse(String mode, long roundMillis) {
        try { ConnectionBudget.mode(mode); }
        catch (IllegalArgumentException failure) { throw new StrictJson.Invalid("policy.mode: unsupported"); }
        if (roundMillis != ROUND_MILLIS) throw new StrictJson.Invalid("policy.roundMillis: must be " + ROUND_MILLIS);
        return new ConnectionPolicy(mode, roundMillis);
    }

    public static ConnectionPolicy parseJson(Object value, String path) {
        java.util.Map<String, Object> json = StrictJson.asObject(value, path);
        StrictJson.exactKeys(json, path, "mode", "roundMillis");
        return parse(StrictJson.string(json.get("mode"), path + ".mode"),
            StrictJson.integer(json.get("roundMillis"), path + ".roundMillis"));
    }

    public boolean selectedOnly() { return "selectedOnly".equals(mode); }

    public java.util.Map<String, Object> toJson() {
        java.util.Map<String, Object> json = new java.util.LinkedHashMap<>();
        json.put("mode", mode);
        json.put("roundMillis", roundMillis);
        return json;
    }

    @Override public boolean equals(Object other) {
        return other instanceof ConnectionPolicy policy && mode.equals(policy.mode) && roundMillis == policy.roundMillis;
    }

    @Override public int hashCode() { return java.util.Objects.hash(mode, roundMillis); }

    static final List<String> MODES = List.of("automatic", "selectedOnly");
}
