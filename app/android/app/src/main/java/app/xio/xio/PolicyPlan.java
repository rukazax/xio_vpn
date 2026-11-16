package app.xio.xio;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The immutable, self-describing native connection plan.
 *
 * <p>A plan is the whole admission snapshot for one saved policy generation: the
 * ordered eligible profiles, each profile's exact saved-config digest, the typed
 * routing snapshot, the protocol priority, the C5 website-consent fields and the
 * root budget. Native never repairs it. A manual plan that names a missing,
 * deleted, unsupported or revoked selection is rejected, not silently rewritten
 * to another profile; a protocol alias is not accepted; a plan whose
 * {@code ids}/{@code profiles}/{@code selectedId} disagree is rejected instead of
 * being truncated.
 */
public final class PolicyPlan {
    public static final int SCHEMA = 2;

    /** One eligible profile with the SHA-256 of its exact saved config bytes. */
    public static final class Profile {
        public final String id;
        public final String protocol;
        public final String endpoint;
        public final String configDigest;

        public Profile(String id, String protocol, String endpoint, String configDigest) {
            this.id = id;
            this.protocol = protocol;
            this.endpoint = endpoint;
            this.configDigest = configDigest;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> json = new LinkedHashMap<>();
            json.put("id", id);
            json.put("protocol", protocol);
            json.put("endpoint", endpoint);
            json.put("configDigest", configDigest);
            return json;
        }

        @Override public boolean equals(Object other) {
            return other instanceof Profile profile && id.equals(profile.id) && protocol.equals(profile.protocol)
                && endpoint.equals(profile.endpoint) && configDigest.equals(profile.configDigest);
        }

        @Override public int hashCode() { return Objects.hash(id, protocol, endpoint, configDigest); }
    }

    public final int schema = SCHEMA;
    public final String selectedId;
    public final List<String> ids;
    public final List<Profile> profiles;
    public final ConnectionPolicy policy;
    public final RoutingCanon.Snapshot routing;
    public final String priorityProtocol;
    public final String site;
    public final boolean siteCheckEnabled;
    public final int timeoutSeconds;
    public final boolean clientOnly;
    public final String consentRevision;
    public final String vpnDisclosure;

    private PolicyPlan(String selectedId, List<String> ids, List<Profile> profiles, ConnectionPolicy policy,
                       RoutingCanon.Snapshot routing, String priorityProtocol, String site, boolean siteCheckEnabled,
                       int timeoutSeconds, boolean clientOnly, String consentRevision, String vpnDisclosure) {
        this.selectedId = selectedId;
        this.ids = List.copyOf(ids);
        this.profiles = List.copyOf(profiles);
        this.policy = policy;
        this.routing = routing;
        this.priorityProtocol = priorityProtocol;
        this.site = site;
        this.siteCheckEnabled = siteCheckEnabled;
        this.timeoutSeconds = timeoutSeconds;
        this.clientOnly = clientOnly;
        this.consentRevision = consentRevision;
        this.vpnDisclosure = vpnDisclosure;
    }

    public static PolicyPlan parse(Object value, String path) {
        Map<String, Object> json = StrictJson.asObject(value, path);
        StrictJson.exactKeys(json, path, "schema", "selectedId", "ids", "profiles", "policy", "routing",
            "priorityProtocol", "site", "siteCheckEnabled", "timeoutSeconds", "roundMillis", "clientOnly",
            "consentRevision", "vpnDisclosure");
        long schema = StrictJson.integer(json.get("schema"), path + ".schema");
        if (schema != SCHEMA) throw new StrictJson.Invalid(path + ".schema: unsupported");

        String selectedId = StrictJson.stringOrNull(json.get("selectedId"), path + ".selectedId");
        if (selectedId != null && selectedId.isEmpty()) throw new StrictJson.Invalid(path + ".selectedId: empty");

        List<Object> rawIds = StrictJson.array(json.get("ids"), path + ".ids");
        if (rawIds.size() > 16) throw new StrictJson.Invalid(path + ".ids: too many");
        List<String> ids = new ArrayList<>();
        for (Object raw : rawIds) {
            String id = StrictJson.string(raw, path + ".ids");
            if (!NativeProtocols.vaultId(id)) throw new StrictJson.Invalid(path + ".ids: invalid id " + id);
            if (ids.contains(id)) throw new StrictJson.Invalid(path + ".ids: duplicate id " + id);
            ids.add(id);
        }

        List<Object> rawProfiles = StrictJson.array(json.get("profiles"), path + ".profiles");
        List<Profile> profiles = new ArrayList<>();
        for (Object raw : rawProfiles) {
            Map<String, Object> object = StrictJson.asObject(raw, path + ".profiles[]");
            StrictJson.exactKeys(object, path + ".profiles[]", "id", "protocol", "endpoint", "configDigest");
            String id = StrictJson.string(object.get("id"), path + ".profiles[].id");
            String protocol = StrictJson.string(object.get("protocol"), path + ".profiles[].protocol");
            String endpoint = StrictJson.string(object.get("endpoint"), path + ".profiles[].endpoint");
            String digest = StrictJson.string(object.get("configDigest"), path + ".profiles[].configDigest");
            if (!NativeProtocols.known(protocol))
                throw new StrictJson.Invalid(path + ".profiles[].protocol: unsupported " + protocol);
            if (!NativeProtocols.idMatches(protocol, id))
                throw new StrictJson.Invalid(path + ".profiles[].id: does not match protocol " + id);
            if (!validEndpoint(endpoint)) throw new StrictJson.Invalid(path + ".profiles[].endpoint: invalid");
            if (!lowerHex(digest, 64)) throw new StrictJson.Invalid(path + ".profiles[].configDigest: invalid");
            profiles.add(new Profile(id, protocol, endpoint, digest));
        }

        // profiles is the ordered same-ID metadata for ids: no truncation, no repair.
        if (profiles.size() != ids.size()) throw new StrictJson.Invalid(path + ": profiles/ids count mismatch");
        for (int index = 0; index < ids.size(); index++) {
            if (!ids.get(index).equals(profiles.get(index).id))
                throw new StrictJson.Invalid(path + ": profiles are not in ids order");
        }

        ConnectionPolicy policy = ConnectionPolicy.parseJson(json.get("policy"), path + ".policy");
        long roundMillis = StrictJson.integer(json.get("roundMillis"), path + ".roundMillis");
        if (roundMillis != ConnectionPolicy.ROUND_MILLIS) throw new StrictJson.Invalid(path + ".roundMillis: must be " + ConnectionPolicy.ROUND_MILLIS);

        // WIRE-V2: every Android schema-2 plan carries a non-null routing snapshot;
        // only the desktop helper may be offered null, and it rejects it. There is
        // no "null means default all" relaxation on Android.
        Object rawRouting = json.get("routing");
        if (rawRouting == null) throw new StrictJson.Invalid(path + ".routing: required on Android");
        Map<String, Object> routingJson = StrictJson.asObject(rawRouting, path + ".routing");
        StrictJson.exactKeys(routingJson, path + ".routing", "mode", "packages", "networks", "domains");
        List<String> packages = strings(routingJson.get("packages"), path + ".routing.packages");
        List<String> networks = strings(routingJson.get("networks"), path + ".routing.networks");
        List<String> domains = strings(routingJson.get("domains"), path + ".routing.domains");
        RoutingCanon.Snapshot routing = RoutingCanon.canonical(
            StrictJson.string(routingJson.get("mode"), path + ".routing.mode"), packages, networks, domains);
        // The plan must already be canonical: deduped and sorted, no silent repair.
        if (!routing.packages.equals(packages) || !routing.networks.equals(networks)
            || !routing.domains.equals(domains))
            throw new StrictJson.Invalid(path + ".routing: not canonical");

        // Verbatim copy of the durable document value: never recomputed, never
        // validated against the protocol list here (admission compares it).
        String priority = StrictJson.stringOrNull(json.get("priorityProtocol"), path + ".priorityProtocol");
        if (priority != null) {
            if (priority.isEmpty() || priority.length() > 64)
                throw new StrictJson.Invalid(path + ".priorityProtocol: invalid length");
            for (int index = 0; index < priority.length(); index++) {
                char c = priority.charAt(index);
                if (c < 0x20 || c == 0x7f) throw new StrictJson.Invalid(path + ".priorityProtocol: control character");
            }
        }

        String site = StrictJson.string(json.get("site"), path + ".site");
        if (!validSite(site)) throw new StrictJson.Invalid(path + ".site: expected HTTPS URL");
        boolean siteCheckEnabled = StrictJson.bool(json.get("siteCheckEnabled"), path + ".siteCheckEnabled");
        int timeoutSeconds = StrictJson.integerInt(json.get("timeoutSeconds"), path + ".timeoutSeconds");
        if (timeoutSeconds < 5 || timeoutSeconds > 60) throw new StrictJson.Invalid(path + ".timeoutSeconds: 5..60");
        boolean clientOnly = StrictJson.bool(json.get("clientOnly"), path + ".clientOnly");
        String consentRevision = StrictJson.string(json.get("consentRevision"), path + ".consentRevision");
        if (!consentRevision.isEmpty() && !consentRevision.equals("2026-10-18"))
            throw new StrictJson.Invalid(path + ".consentRevision: unsupported");
        String vpnDisclosure = StrictJson.stringOrNull(json.get("vpnDisclosure"), path + ".vpnDisclosure");
        if (vpnDisclosure != null && vpnDisclosure.isEmpty())
            throw new StrictJson.Invalid(path + ".vpnDisclosure: empty");

        validateSelection(selectedId, ids, policy, path);
        return new PolicyPlan(selectedId, ids, profiles, policy, routing, priority, site, siteCheckEnabled,
            timeoutSeconds, clientOnly, consentRevision, vpnDisclosure);
    }

    private static void validateSelection(String selectedId, List<String> ids, ConnectionPolicy policy, String path) {
        if (selectedId == null) {
            if (!ids.isEmpty()) throw new StrictJson.Invalid(path + ".ids: candidates without a selection");
            return;
        }
        if (ids.isEmpty()) return; // A saved no-admissible-selection plan is valid but cannot activate.
        if (policy.selectedOnly()) {
            if (ids.size() != 1 || !ids.get(0).equals(selectedId))
                throw new StrictJson.Invalid(path + ".ids: selectedOnly must name exactly the selected profile");
        } else if (!ids.get(0).equals(selectedId)) {
            throw new StrictJson.Invalid(path + ".ids: automatic candidates must start with the selection");
        }
    }

    private static List<String> strings(Object value, String path) {
        List<Object> raw = StrictJson.array(value, path);
        List<String> result = new ArrayList<>();
        for (Object item : raw) result.add(StrictJson.string(item, path));
        return result;
    }

    private static boolean lowerHex(String value, int length) {
        if (value == null || value.length() != length) return false;
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    private static boolean validEndpoint(String endpoint) {
        if (endpoint.isEmpty() || endpoint.length() > 512) return false;
        for (int index = 0; index < endpoint.length(); index++) {
            char c = endpoint.charAt(index);
            if (c < 0x20 || c == 0x7f) return false;
        }
        return !endpoint.trim().isEmpty();
    }

    /** Literal HTTPS check: no DNS, no login, no fragment, bounded length. */
    public static boolean validSite(String site) {
        if (site == null || site.length() > 2048 || !site.startsWith("https://")) return false;
        String rest = site.substring("https://".length());
        if (rest.isEmpty() || rest.indexOf('#') >= 0) return false;
        int end = rest.length();
        int slash = rest.indexOf('/');
        int query = rest.indexOf('?');
        if (slash >= 0) end = Math.min(end, slash);
        if (query >= 0) end = Math.min(end, query);
        String authority = rest.substring(0, end);
        if (authority.isEmpty() || authority.indexOf('@') >= 0 || authority.indexOf('\\') >= 0) return false;
        String host = authority;
        int colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            if (authority.indexOf(']') < colon) host = authority.substring(0, colon);
        }
        if (host.isEmpty() || host.startsWith(":") || host.contains(" ")) return false;
        for (int index = 0; index < site.length(); index++) {
            char c = site.charAt(index);
            if (c < 0x20 || c == 0x7f) return false;
        }
        return true;
    }

    public Profile profile(String id) {
        for (Profile profile : profiles) if (profile.id.equals(id)) return profile;
        return null;
    }

    public boolean manual() { return policy.selectedOnly(); }

    public Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("schema", SCHEMA);
        json.put("selectedId", selectedId);
        json.put("ids", ids);
        List<Object> profileValues = new ArrayList<>();
        for (Profile profile : profiles) profileValues.add(profile.toJson());
        json.put("profiles", profileValues);
        json.put("policy", policy.toJson());
        Map<String, Object> routingJson = new LinkedHashMap<>();
        routingJson.put("mode", routing.mode);
        routingJson.put("packages", routing.packages);
        routingJson.put("networks", routing.networks);
        routingJson.put("domains", routing.domains);
        json.put("routing", routingJson);
        json.put("priorityProtocol", priorityProtocol);
        json.put("site", site);
        json.put("siteCheckEnabled", siteCheckEnabled);
        json.put("timeoutSeconds", timeoutSeconds);
        json.put("roundMillis", ConnectionPolicy.ROUND_MILLIS);
        json.put("clientOnly", clientOnly);
        json.put("consentRevision", consentRevision);
        json.put("vpnDisclosure", vpnDisclosure);
        return json;
    }

    /** Canonical bytes: equal plans have equal digests regardless of key order. */
    public String canonicalJson() { return StrictJson.canonical(toJson()); }

    public String sha256() { return digest(canonicalJson()); }

    public static String digest(String text) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] hashed = sha.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder(64);
            for (byte value : hashed) out.append(String.format(java.util.Locale.ROOT, "%02x", value));
            return out.toString();
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 unavailable", failure);
        }
    }

    /** Digest of the exact saved config bytes; never of a trimmed or re-serialized form. */
    public static String configDigest(String exactConfigUtf8) {
        if (exactConfigUtf8 == null) throw new StrictJson.Invalid("config: missing");
        return digest(exactConfigUtf8);
    }

    @Override public boolean equals(Object other) { return other instanceof PolicyPlan plan && canonicalJson().equals(plan.canonicalJson()); }

    @Override public int hashCode() { return canonicalJson().hashCode(); }
}
