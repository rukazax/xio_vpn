package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The exact protocol vocabulary native admission accepts.
 *
 * <p>These five strings are the ones the engine can actually start and the ones
 * the app's candidate list uses. Aliases ("wireguard", "wg", "h3", "s1",
 * "openvpn") are not accepted anywhere: loosening an alias here would let a
 * saved plan name a protocol the engine never starts, and the plan would then be
 * admitted against a different real capability.
 */
public final class NativeProtocols {
    public static final String AWG = "awg";
    public static final String RIVET_H3 = "rivet-h3";
    public static final String RIVET_S1 = "rivet-s1";
    public static final String XRAY = "xray";
    public static final String CLOAK = "cloak";

    public static final List<String> CANONICAL = List.of(AWG, RIVET_H3, RIVET_S1, XRAY, CLOAK);

    private static final Map<String, String> PREFIXES = new LinkedHashMap<>();

    static {
        PREFIXES.put(AWG, "awg");
        PREFIXES.put(RIVET_H3, "rvh");
        PREFIXES.put(RIVET_S1, "rvs");
        PREFIXES.put(XRAY, "xr");
        PREFIXES.put(CLOAK, "ck");
    }

    private static final String VAULT_ID = "((wg|awg|rvh|rvs|xr|ss|ov|ik|ck|ts)[0-9]{1,24})";

    public static boolean known(String protocol) { return protocol != null && PREFIXES.containsKey(protocol); }

    /** The id prefix {@code Engine.connect} dispatches on, for one canonical protocol. */
    public static String idPrefix(String protocol) {
        String prefix = PREFIXES.get(protocol);
        if (prefix == null) throw new StrictJson.Invalid("protocol: unsupported " + protocol);
        return prefix;
    }

    /** Vault/config identifier syntax shared with ConfigVault. */
    public static boolean vaultId(String id) { return id != null && id.matches(VAULT_ID); }

    /** A plan may only name profiles the engine can start for that protocol. */
    public static boolean idMatches(String protocol, String id) {
        return known(protocol) && vaultId(id) && id.startsWith(idPrefix(protocol));
    }

    private NativeProtocols() { }
}
