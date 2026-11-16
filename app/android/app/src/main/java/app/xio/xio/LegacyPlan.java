package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Pre-envelope migration source: the old raw {@code connectionPlan} payload.
 *
 * <p>Before the versioned envelope existed the app saved an untyped candidate
 * list plus {@code policy}/{@code site} fields. That document may only ever be
 * admitted as <b>legacy automatic</b> and only while it validates exactly and no
 * policy envelope exists at all. A present envelope, a present malformed policy
 * or a {@code selectedOnly} payload is never downgraded to this path: the old raw
 * plan must not become an independent authority again.
 */
public final class LegacyPlan {
    public final List<String> ids;
    public final String site;
    public final boolean siteCheckEnabled;
    public final int timeoutSeconds;
    /** Deterministic content generation of the exact stored bytes (never a fresh default). */
    public final String generation;

    private LegacyPlan(List<String> ids, String site, boolean siteCheckEnabled, int timeoutSeconds, String generation) {
        this.ids = List.copyOf(ids);
        this.site = site;
        this.siteCheckEnabled = siteCheckEnabled;
        this.timeoutSeconds = timeoutSeconds;
        this.generation = generation;
    }

    public static LegacyPlan parseExactStored(String exactStoredBytes) {
        if (exactStoredBytes == null) throw PolicyFailure.unknown("No saved connection plan");
        Object parsed = StrictJson.parse(exactStoredBytes);
        Map<String, Object> json = StrictJson.asObject(parsed, "legacyPlan");
        StrictJson.exactKeys(json, "legacyPlan", "ids", "site", "siteCheckEnabled", "timeoutSeconds", "policy", "roundMillis");
        List<Object> rawIds = StrictJson.array(json.get("ids"), "legacyPlan.ids");
        if (rawIds.isEmpty() || rawIds.size() > 16) throw new StrictJson.Invalid("legacyPlan.ids: 1..16 required");
        List<String> ids = new ArrayList<>();
        for (Object raw : rawIds) {
            String id = StrictJson.string(raw, "legacyPlan.ids");
            if (!NativeProtocols.vaultId(id)) throw new StrictJson.Invalid("legacyPlan.ids: invalid id " + id);
            if (ids.contains(id)) throw new StrictJson.Invalid("legacyPlan.ids: duplicate id " + id);
            ids.add(id);
        }
        Map<String, Object> policy = StrictJson.asObject(json.get("policy"), "legacyPlan.policy");
        StrictJson.exactKeys(policy, "legacyPlan.policy", "mode", "roundMillis");
        String mode = StrictJson.string(policy.get("mode"), "legacyPlan.policy.mode");
        if (!"automatic".equals(mode))
            throw PolicyFailure.stale("A saved manual policy needs the versioned envelope");
        ConnectionPolicy.parse(mode, StrictJson.integer(policy.get("roundMillis"), "legacyPlan.policy.roundMillis"));
        long roundMillis = StrictJson.integer(json.get("roundMillis"), "legacyPlan.roundMillis");
        if (roundMillis != ConnectionPolicy.ROUND_MILLIS)
            throw new StrictJson.Invalid("legacyPlan.roundMillis: must be " + ConnectionPolicy.ROUND_MILLIS);
        String site = StrictJson.string(json.get("site"), "legacyPlan.site");
        if (!PolicyPlan.validSite(site)) throw new StrictJson.Invalid("legacyPlan.site: expected HTTPS URL");
        boolean siteCheckEnabled = StrictJson.bool(json.get("siteCheckEnabled"), "legacyPlan.siteCheckEnabled");
        int timeoutSeconds = StrictJson.integerInt(json.get("timeoutSeconds"), "legacyPlan.timeoutSeconds");
        if (timeoutSeconds < 5 || timeoutSeconds > 60) throw new StrictJson.Invalid("legacyPlan.timeoutSeconds: 5..60");
        return new LegacyPlan(ids, site, siteCheckEnabled, timeoutSeconds, PolicyPlan.digest(exactStoredBytes));
    }

    public Map<String, Object> provenance() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("legacy", true);
        json.put("generation", generation);
        json.put("ids", ids);
        return json;
    }
}
