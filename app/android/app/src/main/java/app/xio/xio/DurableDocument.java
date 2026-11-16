package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Strict reader for the app's durable {@code filesDir/profiles.json}.
 *
 * <p>Android boot and the Quick Settings tile run with no Flutter isolate, so the
 * autonomous path has to validate the real saved document itself instead of a
 * stale in-memory enum. This reader mirrors the fields the accepted app document
 * actually carries (schema 2) and refuses a partial, unknown-schema or wrongly
 * typed document. It never writes the document.
 */
public final class DurableDocument {
    public static final int SCHEMA = 2;

    public static final class Profile {
        public final String id;
        public final String protocol;
        public final String endpoint;

        Profile(String id, String protocol, String endpoint) {
            this.id = id;
            this.protocol = protocol;
            this.endpoint = endpoint;
        }
    }

    public static final class User {
        public final String id;
        public final Map<String, String> profileIds;
        public final boolean revoked;

        User(String id, Map<String, String> profileIds, boolean revoked) {
            this.id = id;
            this.profileIds = Map.copyOf(profileIds);
            this.revoked = revoked;
        }
    }

    /** The committed plan receipt written by the app in the same atomic rename. */
    public static final class Receipt {
        public final String transactionId;
        public final String planGeneration;
        public final PolicyPlan plan;

        Receipt(String transactionId, String planGeneration, PolicyPlan plan) {
            this.transactionId = transactionId;
            this.planGeneration = planGeneration;
            this.plan = plan;
        }
    }

    public final String selectedId;
    public final Map<String, Profile> profiles;
    public final List<String> profileOrder;
    public final List<User> users;
    public final boolean legalCurrent;
    public final String vpnDisclosure;
    public final String priorityProtocol;
    public final String checkSite;
    public final boolean siteCheckEnabled;
    public final int timeoutSeconds;
    public final List<String> splitDomains;
    /** WIRE-V2 versioned marker: the durable connectionPolicy key is present. */
    public final boolean hasConnectionPolicy;
    public final String connectionPolicyMode;
    /** The receipt key itself is the versioned boundary, even when its value is null. */
    public final boolean hasPlanReceiptKey;
    public final Receipt receipt;

    private DurableDocument(String selectedId, Map<String, Profile> profiles, List<String> profileOrder, List<User> users,
                            boolean legalCurrent, String vpnDisclosure, String priorityProtocol, String checkSite,
                            boolean siteCheckEnabled, int timeoutSeconds, List<String> splitDomains,
                            boolean hasConnectionPolicy, String connectionPolicyMode, boolean hasPlanReceiptKey, Receipt receipt) {
        this.selectedId = selectedId;
        this.profiles = Map.copyOf(profiles);
        this.profileOrder = List.copyOf(profileOrder);
        this.users = List.copyOf(users);
        this.legalCurrent = legalCurrent;
        this.vpnDisclosure = vpnDisclosure;
        this.priorityProtocol = priorityProtocol;
        this.checkSite = checkSite;
        this.siteCheckEnabled = siteCheckEnabled;
        this.timeoutSeconds = timeoutSeconds;
        this.splitDomains = List.copyOf(splitDomains);
        this.hasConnectionPolicy = hasConnectionPolicy;
        this.connectionPolicyMode = connectionPolicyMode;
        this.hasPlanReceiptKey = hasPlanReceiptKey;
        this.receipt = receipt;
    }

    public static DurableDocument parse(String text) {
        Object parsed = StrictJson.parse(text);
        Map<String, Object> json = StrictJson.asObject(parsed, "document");
        StrictJson.keys(json, "document",
            List.of("schema", "profiles", "users", "legalRecord", "vpnDisclosure", "selected"),
            List.of("language", "endpointCountries", "servers", "cascadeBridge", "cascadeUnlocked", "cascadeExit",
                "cascadeHealthOk", "cascadeHealthPingMs", "cascadeExitIpv6", "cascadeExitIp", "cascadeCheckedAt",
                "cascadeBridgeCountry", "cascadeExitCountry",
                "mtprotoLink", "splitDomains", "checkSite", "siteCheckEnabled", "dnsServers", "autostart",
                "autoConnectOnStart", "allowScreenshots", "autoReconnect", "priorityProtocol",
                "protocolTimeoutSeconds", "connectionPolicy", "connectionPlanReceipt"));
        if (StrictJson.integer(json.get("schema"), "document.schema") != SCHEMA)
            throw new StrictJson.Invalid("document.schema: unsupported");

        String selectedId = StrictJson.stringOrNull(json.get("selected"), "document.selected");
        if (selectedId != null && selectedId.isEmpty()) throw new StrictJson.Invalid("document.selected: empty");

        List<Object> rawProfiles = StrictJson.array(json.get("profiles"), "document.profiles");
        Map<String, Profile> profiles = new LinkedHashMap<>();
        List<String> order = new ArrayList<>();
        for (Object raw : rawProfiles) {
            Map<String, Object> object = StrictJson.asObject(raw, "document.profiles[]");
            StrictJson.exactKeys(object, "document.profiles[]", "id", "name", "protocol", "endpoint");
            String id = StrictJson.string(object.get("id"), "document.profiles[].id");
            StrictJson.string(object.get("name"), "document.profiles[].name");
            String protocol = StrictJson.string(object.get("protocol"), "document.profiles[].protocol");
            String endpoint = StrictJson.string(object.get("endpoint"), "document.profiles[].endpoint");
            if (profiles.containsKey(id)) throw new StrictJson.Invalid("document.profiles: duplicate id " + id);
            profiles.put(id, new Profile(id, protocol, endpoint));
            order.add(id);
        }

        List<Object> rawUsers = StrictJson.array(json.get("users"), "document.users");
        List<User> users = new ArrayList<>();
        for (Object raw : rawUsers) {
            Map<String, Object> object = StrictJson.asObject(raw, "document.users[]");
            StrictJson.keys(object, "document.users[]",
                List.of("id", "name", "serverId", "profileIds", "revoked"),
                List.of("admin", "userLimit", "statistics"));
            String id = StrictJson.string(object.get("id"), "document.users[].id");
            StrictJson.string(object.get("name"), "document.users[].name");
            StrictJson.string(object.get("serverId"), "document.users[].serverId");
            Map<String, Object> rawIds = StrictJson.asObject(object.get("profileIds"), "document.users[].profileIds");
            Map<String, String> profileIds = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : rawIds.entrySet())
                profileIds.put(entry.getKey(), StrictJson.string(entry.getValue(), "document.users[].profileIds"));
            boolean revoked = StrictJson.bool(object.get("revoked"), "document.users[].revoked");
            if (object.containsKey("admin")) StrictJson.bool(object.get("admin"), "document.users[].admin");
            if (object.containsKey("userLimit")) StrictJson.integer(object.get("userLimit"), "document.users[].userLimit");
            if (object.containsKey("statistics")) StrictJson.asObject(object.get("statistics"), "document.users[].statistics");
            users.add(new User(id, profileIds, revoked));
        }

        Object rawLegal = json.get("legalRecord");
        boolean legalCurrent = false;
        if (rawLegal != null) {
            Map<String, Object> legal = StrictJson.asObject(rawLegal, "document.legalRecord");
            StrictJson.exactKeys(legal, "document.legalRecord", "revision", "timestamp", "textSha256", "language");
            String revision = StrictJson.string(legal.get("revision"), "document.legalRecord.revision");
            String timestamp = StrictJson.string(legal.get("timestamp"), "document.legalRecord.timestamp");
            String sha = StrictJson.string(legal.get("textSha256"), "document.legalRecord.textSha256");
            StrictJson.string(legal.get("language"), "document.legalRecord.language");
            legalCurrent = "2026-10-18".equals(revision) && isUtcIso(timestamp) && sha.matches("[a-f0-9]{64}");
        }
        String vpnDisclosure = StrictJson.stringOrNull(json.get("vpnDisclosure"), "document.vpnDisclosure");

        // WIRE-V2 versioned marker. A present but malformed policy is an error;
        // absence is the legacy shape and is only ever admitted as legacy automatic.
        boolean hasConnectionPolicy = json.containsKey("connectionPolicy");
        String connectionPolicyMode = null;
        if (hasConnectionPolicy) {
            Map<String, Object> connectionPolicy = StrictJson.asObject(json.get("connectionPolicy"), "document.connectionPolicy");
            StrictJson.exactKeys(connectionPolicy, "document.connectionPolicy", "mode", "roundMillis");
            connectionPolicyMode = StrictJson.string(connectionPolicy.get("mode"), "document.connectionPolicy.mode");
            if (!"automatic".equals(connectionPolicyMode) && !"selectedOnly".equals(connectionPolicyMode))
                throw new StrictJson.Invalid("document.connectionPolicy.mode: unsupported");
            if (StrictJson.integer(connectionPolicy.get("roundMillis"), "document.connectionPolicy.roundMillis")
                != ConnectionPolicy.ROUND_MILLIS)
                throw new StrictJson.Invalid("document.connectionPolicy.roundMillis: must be " + ConnectionPolicy.ROUND_MILLIS);
        }

        String priority = StrictJson.stringOrNull(json.get("priorityProtocol"), "document.priorityProtocol");
        String checkSite = json.containsKey("checkSite")
            ? StrictJson.string(json.get("checkSite"), "document.checkSite") : "https://youtube.com";
        boolean siteCheckEnabled = json.containsKey("siteCheckEnabled")
            && StrictJson.bool(json.get("siteCheckEnabled"), "document.siteCheckEnabled");
        int timeoutSeconds = json.containsKey("protocolTimeoutSeconds")
            ? StrictJson.integerInt(json.get("protocolTimeoutSeconds"), "document.protocolTimeoutSeconds") : 15;
        if (timeoutSeconds < 5 || timeoutSeconds > 60)
            throw new StrictJson.Invalid("document.protocolTimeoutSeconds: 5..60");

        List<String> splitDomains = new ArrayList<>();
        if (json.containsKey("splitDomains")) {
            for (Object raw : StrictJson.array(json.get("splitDomains"), "document.splitDomains")) {
                String domain = StrictJson.string(raw, "document.splitDomains");
                String normalized = RoutingCanon.normalizeDomain(domain);
                if (normalized == null) throw new StrictJson.Invalid("document.splitDomains: invalid domain");
                if (!splitDomains.contains(normalized)) splitDomains.add(normalized);
            }
        }

        boolean hasPlanReceiptKey = json.containsKey("connectionPlanReceipt");
        Receipt receipt = null;
        Object rawReceipt = json.get("connectionPlanReceipt");
        if (rawReceipt != null) {
            Map<String, Object> object = StrictJson.asObject(rawReceipt, "document.connectionPlanReceipt");
            StrictJson.exactKeys(object, "document.connectionPlanReceipt", "schema", "transactionId", "planGeneration", "plan");
            if (StrictJson.integer(object.get("schema"), "document.connectionPlanReceipt.schema") != 1)
                throw new StrictJson.Invalid("document.connectionPlanReceipt.schema: unsupported");
            receipt = new Receipt(
                PolicyReceipt.requireHex(StrictJson.string(object.get("transactionId"), "receipt.transactionId"), 32, "receipt.transactionId"),
                PolicyReceipt.requireHex(StrictJson.string(object.get("planGeneration"), "receipt.planGeneration"), 32, "receipt.planGeneration"),
                PolicyPlan.parse(object.get("plan"), "document.connectionPlanReceipt.plan"));
        }

        return new DurableDocument(selectedId, profiles, order, users, legalCurrent, vpnDisclosure, priority,
            checkSite, siteCheckEnabled, timeoutSeconds, splitDomains, hasConnectionPolicy, connectionPolicyMode,
            hasPlanReceiptKey, receipt);
    }

    private static boolean isUtcIso(String timestamp) {
        if (timestamp.length() < 20 || timestamp.length() > 40) return false;
        if (!timestamp.endsWith("Z")) return false;
        try { return java.time.Instant.parse(timestamp) != null; }
        catch (RuntimeException failure) { return false; }
    }

    public boolean consentReady() { return legalCurrent && "2026-10-18".equals(vpnDisclosure); }

    /** The account that owns this profile, or {@code null} when no user owns it. */
    public User userFor(String profileId) {
        for (User user : users) if (user.profileIds.containsValue(profileId)) return user;
        return null;
    }

    /**
     * The app's own eligibility rule for one candidate: a known native protocol,
     * and, unless this is a client-only build, the owning account must still be
     * present and not revoked. Absence of an owner is not a revocation.
     */
    public boolean eligible(String profileId, boolean clientOnly) {
        Profile profile = profiles.get(profileId);
        if (profile == null || !NativeProtocols.known(profile.protocol)) return false;
        if (clientOnly) return true;
        User user = userFor(profileId);
        return user == null || !user.revoked;
    }

    /** The candidate list this document admits, in plan order, without repairing. */
    public List<String> admissible(List<String> planIds, boolean clientOnly) {
        List<String> result = new ArrayList<>();
        for (String id : planIds) if (eligible(id, clientOnly)) result.add(id);
        return result;
    }
}
