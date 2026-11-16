package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shared deterministic fixtures for the pure policy tests. No Android, no IO. */
final class PolicyFixtures {
    // WIRE-V2 golden config bytes.
    static final String AWG_TRAILING =
        "[Interface]\nAddress = 10.7.0.2/32\nDNS = 9.9.9.9\nPrivateKey = priv\n[Peer]\n"
            + "PublicKey = pub\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n";
    static final String AWG_NO_TRAILING = AWG_TRAILING.substring(0, AWG_TRAILING.length() - 1);
    static final String VLESS = "{\"protocol\":\"vless\",\"serverName\":\"example.invalid\",\"port\":443}";

    static final String AWG_TRAILING_DIGEST = "39f8033617d67670c707dde7332ad7e616ef4902d4b7e6cf797e102af1611389";
    static final String AWG_NO_TRAILING_DIGEST = "b5e42d837f2cb7c753fe7434430003707486498d92ab39e51af562696182b34d";
    static final String VLESS_DIGEST = "c40bb489a48a897507a8a486f6403b631ed8b518d9077a7a9102058cfc2c9542";
    static final String EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    static final String TX = "11111111111111111111111111111111";
    static final String GEN = "22222222222222222222222222222222";
    static final String GEN2 = "33333333333333333333333333333333";
    static final String STORE = "4444444444444444444444444444444444444444444444444444444444444444";
    static final String CONTROLLER = "55555555555555555555555555555555";
    static final String INSTANCE = "66666666666666666666666666666666";

    static final Map<String, String> VAULT = new LinkedHashMap<>();

    static {
        VAULT.put("awg1", AWG_TRAILING);
        VAULT.put("awg2", AWG_NO_TRAILING);
        VAULT.put("xr1", VLESS);
    }

    static String digestOf(String id) { return PolicyPlan.configDigest(VAULT.get(id)); }

    static Map<String, Object> policy(String mode) {
        Map<String, Object> policy = new LinkedHashMap<>();
        policy.put("mode", mode);
        policy.put("roundMillis", 30000);
        return policy;
    }

    static Map<String, Object> routing(String mode, List<String> packages, List<String> networks, List<String> domains) {
        Map<String, Object> routing = new LinkedHashMap<>();
        routing.put("mode", mode);
        routing.put("packages", packages);
        routing.put("networks", networks);
        routing.put("domains", domains);
        return routing;
    }

    static Map<String, Object> allRouting() { return routing("all", List.of(), List.of(), List.of()); }

    static String protocolOf(String id) {
        if (id.startsWith("awg")) return "awg";
        if (id.startsWith("xr")) return "xray";
        if (id.startsWith("rvh")) return "rivet-h3";
        if (id.startsWith("rvs")) return "rivet-s1";
        if (id.startsWith("ck")) return "cloak";
        throw new IllegalArgumentException(id);
    }

    static String endpointOf(String id) {
        if (id.startsWith("awg")) return "203.0.113.9:51820";
        if (id.startsWith("xr")) return "example.invalid:443";
        return "example.invalid:8443";
    }

    static List<Object> profiles(List<String> ids) {
        List<Object> profiles = new ArrayList<>();
        for (String id : ids) {
            Map<String, Object> profile = new LinkedHashMap<>();
            profile.put("id", id);
            profile.put("protocol", protocolOf(id));
            profile.put("endpoint", endpointOf(id));
            profile.put("configDigest", digestOf(id));
            profiles.add(profile);
        }
        return profiles;
    }

    static Map<String, Object> plan(List<String> ids, boolean manual) {
        Map<String, Object> plan = new LinkedHashMap<>();
        plan.put("schema", 2);
        plan.put("selectedId", ids.isEmpty() ? null : ids.get(0));
        plan.put("ids", ids);
        plan.put("profiles", profiles(ids));
        plan.put("routing", allRouting());
        plan.put("priorityProtocol", "xray");
        plan.put("policy", policy(manual ? "selectedOnly" : "automatic"));
        plan.put("site", "https://youtube.com");
        plan.put("siteCheckEnabled", false);
        plan.put("timeoutSeconds", 15);
        plan.put("roundMillis", 30000);
        plan.put("clientOnly", false);
        plan.put("consentRevision", "2026-10-18");
        plan.put("vpnDisclosure", "2026-10-18");
        return plan;
    }

    static Map<String, Object> document(Map<String, Object> receiptPlan) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("schema", 2);
        doc.put("legalRecord", legalRecord());
        doc.put("vpnDisclosure", "2026-10-18");
        doc.put("language", "en");
        doc.put("servers", List.of());
        doc.put("users", List.of());
        doc.put("cascadeBridge", "");
        doc.put("cascadeUnlocked", false);
        doc.put("cascadeExit", "");
        doc.put("cascadeHealthOk", false);
        doc.put("cascadeHealthPingMs", null);
        doc.put("cascadeExitIpv6", "");
        doc.put("cascadeCheckedAt", "");
        doc.put("mtprotoLink", "");
        doc.put("splitDomains", List.of());
        doc.put("checkSite", "https://youtube.com");
        doc.put("siteCheckEnabled", false);
        doc.put("dnsServers", List.of());
        doc.put("autostart", false);
        doc.put("autoConnectOnStart", false);
        doc.put("allowScreenshots", false);
        doc.put("autoReconnect", true);
        doc.put("priorityProtocol", "xray");
        doc.put("protocolTimeoutSeconds", 15);
        doc.put("selected", "awg1");
        doc.put("endpointCountries", new LinkedHashMap<String, Object>());
        List<Object> profiles = new ArrayList<>();
        for (Map.Entry<String, String> entry : VAULT.entrySet()) {
            Map<String, Object> profile = new LinkedHashMap<>();
            profile.put("id", entry.getKey());
            profile.put("name", entry.getKey());
            profile.put("protocol", protocolOf(entry.getKey()));
            profile.put("endpoint", endpointOf(entry.getKey()));
            profiles.add(profile);
        }
        doc.put("profiles", profiles);
        if (receiptPlan != null) {
            Map<String, Object> connectionPolicy = new LinkedHashMap<>();
            Object mode = ((Map<?, ?>) receiptPlan.get("policy")).get("mode");
            connectionPolicy.put("mode", mode);
            connectionPolicy.put("roundMillis", 30000);
            doc.put("connectionPolicy", connectionPolicy);
            Map<String, Object> receipt = new LinkedHashMap<>();
            receipt.put("schema", 1);
            receipt.put("transactionId", TX);
            receipt.put("planGeneration", GEN);
            receipt.put("plan", receiptPlan);
            doc.put("connectionPlanReceipt", receipt);
        }
        return doc;
    }

    /** Versioned document whose committed receipt has an explicit transaction/generation. */
    static Map<String, Object> documentWithReceipt(Map<String, Object> plan, String transactionId, String planGeneration) {
        Map<String, Object> document = document(plan);
        @SuppressWarnings("unchecked")
        Map<String, Object> receipt = new LinkedHashMap<>((Map<String, Object>) document.get("connectionPlanReceipt"));
        receipt.put("transactionId", transactionId);
        receipt.put("planGeneration", planGeneration);
        document.put("connectionPlanReceipt", receipt);
        return document;
    }

    /** Receipt key present with a null value: the boundary exists, so no legacy path. */
    static Map<String, Object> documentNullReceipt(boolean withMarker, Map<String, Object> plan) {
        Map<String, Object> document = withMarker ? document(plan) : document(null);
        document.put("connectionPlanReceipt", null);
        return document;
    }

    /** Versioned marker present, receipt not yet renamed (crash-cut fixture). */
    static Map<String, Object> documentNoReceipt(Map<String, Object> plan) {
        Map<String, Object> document = document(plan);
        document.remove("connectionPlanReceipt");
        return document;
    }

    static Map<String, Object> legalRecord() {
        Map<String, Object> legal = new LinkedHashMap<>();
        legal.put("revision", "2026-10-18");
        legal.put("timestamp", "2026-11-06T07:00:00.000Z");
        legal.put("textSha256", "a".repeat(64));
        legal.put("language", "en");
        return legal;
    }

    static PolicyPlan parsePlan(Map<String, Object> plan) {
        return PolicyPlan.parse(StrictJson.parse(StrictJson.write(plan)), "plan");
    }

    static String documentText(Map<String, Object> document) { return StrictJson.write(document); }

    static PolicyEnvelope envelope(Map<String, Object> plan, PublicationPhase phase, String transactionId,
                                   String generation) {
        PolicyPlan parsed = parsePlan(plan);
        return new PolicyEnvelope(phase, STORE, INSTANCE, CONTROLLER, transactionId, generation, null,
            phase == PublicationPhase.BLOCKED ? null : parsed, null);
    }

    static DurableAdmission.RoutingSource allRoutingSource() { return RoutingCanon::absent; }

    static DurableAdmission.ConfigSource vault() { return VAULT::get; }

    static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }

    static void checkCode(String code, Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected " + code);
        } catch (PolicyFailure failure) {
            if (!code.equals(failure.code)) throw new AssertionError("expected " + code + " got " + failure.code + ": " + failure.getMessage());
        }
    }

    static void checkInvalid(Runnable action) {
        try {
            action.run();
            throw new AssertionError("expected invalid input");
        } catch (StrictJson.Invalid | PolicyFailure expected) { }
    }

    private PolicyFixtures() { }
}
