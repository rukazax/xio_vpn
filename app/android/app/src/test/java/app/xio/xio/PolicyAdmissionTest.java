package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Native document + digest + routing re-derivation before any effect. */
public final class PolicyAdmissionTest {
    private static Map<String, Object> plan() { return PolicyFixtures.plan(List.of("awg1", "xr1"), false); }

    private static Map<String, Object> document(Map<String, Object> plan) { return PolicyFixtures.document(plan); }

    private static Map<String, Object> withUser(Map<String, Object> document, boolean revoked) {
        Map<String, Object> copy = new LinkedHashMap<>(document);
        Map<String, Object> user = new LinkedHashMap<>();
        user.put("id", "u1");
        user.put("name", "owner");
        user.put("serverId", "s1");
        Map<String, Object> ids = new LinkedHashMap<>();
        ids.put("awg1", "awg1");
        user.put("profileIds", ids);
        user.put("revoked", revoked);
        user.put("admin", false);
        user.put("userLimit", 0);
        user.put("statistics", new LinkedHashMap<String, Object>());
        copy.put("users", List.of(user));
        return copy;
    }

    private static Map<String, String> vaultWith(String id, String raw) {
        Map<String, String> vault = new LinkedHashMap<>(PolicyFixtures.VAULT);
        vault.put(id, raw);
        return vault;
    }

    public static void main(String[] args) {
        Map<String, Object> planMap = plan();
        PolicyPlan plan = PolicyFixtures.parsePlan(planMap);
        PolicyEnvelope ready = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, plan, null);
        String document = PolicyFixtures.documentText(document(planMap));

        // Known-clean happy path: no Flutter, no UI, no network - just durable state.
        DurableAdmission.Admission admission = DurableAdmission.validateReady(
            ready, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        admission.requireActivatable();
        PolicyFixtures.check(admission.candidates.equals(List.of("awg1", "xr1")), "boot candidates");
        PolicyFixtures.check(admission.generation.equals(PolicyFixtures.GEN) && admission.receipt.planGeneration.equals(PolicyFixtures.GEN), "boot generation");
        PolicyFixtures.check(admission.receipt.instanceNonce.equals(PolicyFixtures.INSTANCE), "receipt instance");
        PolicyFixtures.check(!admission.legacy && admission.policy.mode.equals("automatic"), "boot automatic");
        DurableAdmission.validateCandidate(admission, "awg1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        DurableAdmission.validateCandidate(admission, "xr1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        PolicyFixtures.checkCode(PolicyFailure.STALE, () ->
            DurableAdmission.validateCandidate(admission, "awg2", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document));

        // Digest divergence in the actual vault is stale, not a re-hash of the plan.
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), vaultWith("awg1", PolicyFixtures.AWG_NO_TRAILING)::get, false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateCandidate(admission, "awg1",
            PolicyFixtures.allRoutingSource(), vaultWith("awg1", PolicyFixtures.AWG_NO_TRAILING)::get, false, document));

        // Routing/priority/selection/settings divergence.
        DurableAdmission.RoutingSource include = () -> RoutingCanon.canonical("include", List.of("a.app"), List.of(), List.of());
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready, include, PolicyFixtures.vault(), false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "priorityProtocol", "awg"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "selected", "awg2"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "checkSite", "https://example.com"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "protocolTimeoutSeconds", 20))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "siteCheckEnabled", true))));

        // Consent and revocation are re-derived from the real document.
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "vpnDisclosure", null))));
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(
                set(document(planMap), "legalRecord", null))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(withUser(document(planMap), true))));
        DurableAdmission.validateReady(ready, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(withUser(document(planMap), false)));

        // Malformed / unproven document pairs stay blocked.
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, "{}"));
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, "{not json"));
        PolicyFixtures.checkCode(PolicyFailure.UNKNOWN, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.document(null))));
        Map<String, Object> olderReceipt = new LinkedHashMap<>(document(planMap));
        @SuppressWarnings("unchecked")
        Map<String, Object> receipt = new LinkedHashMap<>((Map<String, Object>) olderReceipt.get("connectionPlanReceipt"));
        receipt.put("planGeneration", PolicyFixtures.GEN2);
        olderReceipt.put("connectionPlanReceipt", receipt);
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(olderReceipt)));

        // A late automatic READY write after a newer manual ACK must not resurrect.
        Map<String, Object> manualMap = PolicyFixtures.plan(List.of("awg1"), true);
        PolicyPlan manualPlan = PolicyFixtures.parsePlan(manualMap);
        Map<String, Object> manualDocument = PolicyFixtures.document(manualMap);
        @SuppressWarnings("unchecked")
        Map<String, Object> manualReceipt = new LinkedHashMap<>((Map<String, Object>) manualDocument.get("connectionPlanReceipt"));
        manualReceipt.put("planGeneration", PolicyFixtures.GEN2);
        manualReceipt.put("transactionId", PolicyFixtures.TX);
        manualDocument.put("connectionPlanReceipt", manualReceipt);
        // The old automatic envelope (GEN) cannot be blessed against the manual receipt (GEN2).
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(manualDocument)));
        PolicyEnvelope manualReady = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE,
            PolicyFixtures.INSTANCE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN2, null, manualPlan, null);
        DurableAdmission.Admission manualAdmission = DurableAdmission.validateReady(manualReady,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(manualDocument));
        PolicyFixtures.check(manualAdmission.candidates.equals(List.of("awg1")) && manualAdmission.policy.selectedOnly(), "manual admission");
        PolicyFixtures.checkCode(PolicyFailure.STALE, () ->
            DurableAdmission.validateCandidate(manualAdmission, "xr1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
                PolicyFixtures.documentText(manualDocument)));

        // WIRE-V2: null routing is rejected on Android even for automatic/all.
        Map<String, Object> nullRoutingPlan = new LinkedHashMap<>(planMap);
        nullRoutingPlan.put("routing", null);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(nullRoutingPlan));
        Map<String, Object> nullRoutingManual = new LinkedHashMap<>(PolicyFixtures.plan(List.of("awg1"), true));
        nullRoutingManual.put("routing", null);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(nullRoutingManual));

        // Publication ACK may only follow a matching durable document/config/routing.
        DurableAdmission.validateProposal(plan, PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(),
            PolicyFixtures.vault(), false, document);
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN2, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), vaultWith("awg1", PolicyFixtures.AWG_NO_TRAILING)::get,
            false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, include, PolicyFixtures.vault(), false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(set(document(planMap), "selected", "awg2"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(set(document(planMap), "priorityProtocol", "awg"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(planMap))));
        // A reconcile ACK requires the exact durable receipt, like a commit: an
        // absent receipt stays blocked instead of creating a boot-inconsistent READY.
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(planMap))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN2, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan, PolicyFixtures.TX,
            PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.document(null))));
        // Empty or whitespace-only saved configuration is never admissible, even when
        // the plan's own digest matches those bytes.
        for (String blank : new String[]{"", " \t\n"}) {
            Map<String, Object> blankMap = PolicyFixtures.plan(List.of("awg1"), true);
            @SuppressWarnings("unchecked")
            Map<String, Object> blankProfile = new LinkedHashMap<>((Map<String, Object>) ((List<?>) blankMap.get("profiles")).get(0));
            blankProfile.put("configDigest", PolicyPlan.configDigest(blank));
            blankMap.put("profiles", List.of(blankProfile));
            PolicyPlan blankPlan = PolicyFixtures.parsePlan(blankMap);
            PolicyEnvelope blankReady = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE,
                PolicyFixtures.INSTANCE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, blankPlan, null);
            String blankDocument = PolicyFixtures.documentText(document(blankMap));
            DurableAdmission.ConfigSource blankVault = id -> blank;
            PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(blankPlan,
                PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), blankVault, false, blankDocument));
            PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(blankReady,
                PolicyFixtures.allRoutingSource(), blankVault, false, blankDocument));
        }
        String blankLegacy = "{\"ids\":[\"awg1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
            + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}";
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(
            LegacyPlan.parseExactStored(blankLegacy), PolicyFixtures.allRoutingSource(), id -> "", false,
            PolicyFixtures.documentText(PolicyFixtures.document(null))));

        // A present receipt key with a null value is still the versioned boundary.
        String nullReceiptNoMarker = PolicyFixtures.documentText(
            PolicyFixtures.documentNullReceipt(false, planMap));
        String nullReceiptMarker = PolicyFixtures.documentText(
            PolicyFixtures.documentNullReceipt(true, planMap));
        String legacyRaw = "{\"ids\":[\"awg1\",\"xr1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
            + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}";
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(
            LegacyPlan.parseExactStored(legacyRaw), PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            nullReceiptNoMarker));
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, legacyRaw, nullReceiptNoMarker) == null,
            "present null receipt hides the legacy display mirror");
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, nullReceiptMarker));
        PolicyFixtures.checkCode(PolicyFailure.INVALID, () -> DurableAdmission.validateProposal(plan,
            PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            nullReceiptMarker));

        // Empty plan is stored but cannot activate (selected profile has no admissible candidate).
        Map<String, Object> emptyMap = PolicyFixtures.plan(List.of(), false);
        emptyMap.put("selectedId", "awg1");
        PolicyEnvelope emptyReady = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, PolicyFixtures.parsePlan(emptyMap), null);
        String emptyDocument = PolicyFixtures.documentText(document(emptyMap));
        DurableAdmission.Admission empty = DurableAdmission.validateReady(emptyReady,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, emptyDocument);
        PolicyFixtures.check(empty.candidates.isEmpty(), "empty candidates");
        PolicyFixtures.checkCode(PolicyFailure.INVALID, empty::requireActivatable);

        // Product identity mismatch is stale, not silently accepted.
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), true, document));

        // Legacy absent-envelope migration: automatic only, selection must match.
        String legacy = "{\"ids\":[\"awg1\",\"xr1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
            + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}";
        LegacyPlan legacyPlan = LegacyPlan.parseExactStored(legacy);
        PolicyFixtures.check(legacyPlan.generation.equals(PolicyPlan.digest(legacy)), "legacy generation is content-derived");
        Map<String, Object> legacyDocument = PolicyFixtures.document(null);
        DurableAdmission.Admission legacyAdmission = DurableAdmission.validateLegacy(legacyPlan,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(legacyDocument));
        PolicyFixtures.check(legacyAdmission.legacy && legacyAdmission.candidates.equals(List.of("awg1", "xr1")), "legacy admission");
        DurableAdmission.validateCandidate(legacyAdmission, "xr1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(legacyDocument));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateCandidate(legacyAdmission, "awg2",
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(legacyDocument)));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(legacyPlan,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(set(legacyDocument, "selected", "awg2"))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(legacyPlan,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(document(planMap))));
        // A versioned app document with no receipt is still not a legacy source
        // (crash cut or new app: fail closed, never fall back to the old raw plan).
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(legacyPlan,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(planMap))));
        Map<String, Object> manualVersioned = PolicyFixtures.document(PolicyFixtures.plan(List.of("awg1"), true));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(legacyPlan,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(manualVersioned)));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateCandidate(legacyAdmission, "awg1",
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(planMap))));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> LegacyPlan.parseExactStored(
            legacy.replace("\"automatic\"", "\"selectedOnly\"")));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(
            LegacyPlan.parseExactStored(legacy.replace("\"awg1\",\"xr1\"", "\"xr1\"")),
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(legacyDocument)));

        System.out.println("PASS native admission: known-clean boot/Tile path without Flutter, exact vault digests, "
            + "routing/priority/selected/settings divergence, consent/revocation, malformed/mixed receipt pairs, "
            + "late-automatic-resurrection, required routing, empty plan, publication-ACK re-derivation, legacy only against a pre-versioned document");
    }

    private static Map<String, Object> set(Map<String, Object> source, String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(source);
        copy.put(key, value);
        return copy;
    }

    private PolicyAdmissionTest() { }
}
