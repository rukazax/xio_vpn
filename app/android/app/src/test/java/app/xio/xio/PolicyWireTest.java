package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Strict-wire proof for the schema-2 plan, envelope and activation receipt. */
public final class PolicyWireTest {
    private static Map<String, Object> mutate(Map<String, Object> source, String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(source);
        copy.put(key, value);
        return copy;
    }

    private static Map<String, Object> planFrom(String text) {
        return StrictJson.asObject(StrictJson.parse(text), "plan");
    }

    public static void main(String[] args) {
        // WIRE-V2 golden digests: the trailing newline is part of the bytes.
        PolicyFixtures.check(PolicyPlan.configDigest(PolicyFixtures.AWG_TRAILING).equals(PolicyFixtures.AWG_TRAILING_DIGEST), "trailing-LF golden");
        PolicyFixtures.check(PolicyPlan.configDigest(PolicyFixtures.AWG_NO_TRAILING).equals(PolicyFixtures.AWG_NO_TRAILING_DIGEST), "no-trailing-LF golden");
        PolicyFixtures.check(PolicyPlan.configDigest(PolicyFixtures.VLESS).equals(PolicyFixtures.VLESS_DIGEST), "vless golden");
        PolicyFixtures.check(PolicyPlan.configDigest("").equals(PolicyFixtures.EMPTY_DIGEST), "empty golden");
        PolicyFixtures.check(!PolicyPlan.configDigest(PolicyFixtures.AWG_TRAILING).equals(PolicyPlan.configDigest(PolicyFixtures.AWG_NO_TRAILING)), "newline changes digest");

        // Canonical plan round-trips byte-identically.
        Map<String, Object> automatic = PolicyFixtures.plan(List.of("awg1", "xr1"), false);
        PolicyPlan plan = PolicyFixtures.parsePlan(automatic);
        PolicyFixtures.check(plan.schema == 2 && plan.selectedId.equals("awg1"), "plan identity");
        PolicyFixtures.check(plan.canonicalJson().equals(StrictJson.canonical(plan.toJson())), "canonical stable");
        PolicyFixtures.check(PolicyPlan.parse(StrictJson.parse(plan.canonicalJson()), "plan").equals(plan), "round-trip equal");
        PolicyFixtures.check(plan.profile("awg1").configDigest.equals(PolicyFixtures.AWG_TRAILING_DIGEST), "embedded digest");
        PolicyFixtures.check(!plan.manual(), "automatic mode");
        PolicyFixtures.check(plan.routing.equals(RoutingCanon.absent()), "canonical all routing");
        PolicyFixtures.check(plan.consentRevision.equals("2026-10-18") && "2026-10-18".equals(plan.vpnDisclosure), "consent copy");

        PolicyPlan manual = PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1"), true));
        PolicyFixtures.check(manual.manual() && manual.ids.size() == 1 && manual.selectedId.equals(manual.ids.get(0)), "manual single candidate");
        PolicyPlan empty = PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of(), false));
        PolicyFixtures.check(empty.ids.isEmpty() && empty.selectedId == null, "empty plan parses");

        // Schema and key exactness.
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "schema", 1)));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "schema", "2")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "extra", true)));


        // Budget and mode exactness: no coercion, no loosening.
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "roundMillis", 29999)));
        Map<String, Object> fractional = planFrom(StrictJson.write(automatic).replace("\"roundMillis\":30000", "\"roundMillis\":30000.0"));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(fractional));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "policy", PolicyFixtures.policy("manual"))));
        Map<String, Object> policyExtra = new LinkedHashMap<>(PolicyFixtures.policy("automatic"));
        policyExtra.put("extra", 1);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "policy", policyExtra)));

        // ids/profiles: same length, same order, unique, protocol-consistent.
        Map<String, Object> truncated = new LinkedHashMap<>(automatic);
        truncated.put("profiles", PolicyFixtures.profiles(List.of("awg1")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(truncated));
        Map<String, Object> duplicated = new LinkedHashMap<>(automatic);
        duplicated.put("ids", List.of("awg1", "awg1"));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(duplicated));
        List<Object> mismatched = PolicyFixtures.profiles(List.of("awg1", "xr1"));
        mismatched.set(0, PolicyFixtures.profiles(List.of("xr1")).get(0));
        Map<String, Object> reordered = new LinkedHashMap<>(automatic);
        reordered.put("profiles", mismatched);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(reordered));
        Map<String, Object> alias = new LinkedHashMap<>(automatic);
        alias.put("profiles", List.of(aliasProfile("awg1", "wireguard")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(alias));
        Map<String, Object> wrongPrefix = new LinkedHashMap<>(automatic);
        wrongPrefix.put("profiles", List.of(aliasProfile("xr1", "awg")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(wrongPrefix));
        Map<String, Object> upperDigest = new LinkedHashMap<>(automatic);
        upperDigest.put("profiles", List.of(profile("awg1", "awg", "A" + PolicyFixtures.AWG_TRAILING_DIGEST.substring(1))));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(upperDigest));

        // Manual must be exactly the selection; automatic must start with it.
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1", "xr1"), true)));
        Map<String, Object> manualWrong = new LinkedHashMap<>(PolicyFixtures.plan(List.of("xr1"), true));
        manualWrong.put("selectedId", "awg1");
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(manualWrong));
        Map<String, Object> autoWrong = new LinkedHashMap<>(automatic);
        autoWrong.put("selectedId", "awg2");
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(autoWrong));
        Map<String, Object> noSelection = new LinkedHashMap<>(automatic);
        noSelection.put("selectedId", null);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(noSelection));

        // Routing: canonical, deduped, sorted; the plan is not repaired.
        Map<String, Object> sortedNetworks = new LinkedHashMap<>(automatic);
        sortedNetworks.put("routing", PolicyFixtures.routing("ipInclude", List.of(), List.of("10.0.0.0/8", "192.168.0.0/16"), List.of()));
        PolicyPlan ip = PolicyFixtures.parsePlan(sortedNetworks);
        PolicyFixtures.check(ip.routing.mode.equals("ipInclude") && ip.routing.networks.equals(List.of("10.0.0.0/8", "192.168.0.0/16")), "sorted networks accepted");
        Map<String, Object> unsorted = new LinkedHashMap<>(automatic);
        unsorted.put("routing", PolicyFixtures.routing("ipInclude", List.of(), List.of("192.168.0.0/16", "10.0.0.0/8"), List.of()));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(unsorted));
        Map<String, Object> unsortedDomains = new LinkedHashMap<>(automatic);
        unsortedDomains.put("routing", PolicyFixtures.routing("ipExclude", List.of(), List.of(), List.of("b.example.com", "a.example.com")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(unsortedDomains));
        Map<String, Object> unsortedPackages = new LinkedHashMap<>(automatic);
        unsortedPackages.put("routing", PolicyFixtures.routing("include", List.of("z.app", "a.app"), List.of(), List.of()));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(unsortedPackages));
        Map<String, Object> includeEmpty = new LinkedHashMap<>(automatic);
        includeEmpty.put("routing", PolicyFixtures.routing("include", List.of(), List.of(), List.of()));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(includeEmpty));
        Map<String, Object> ipEmpty = new LinkedHashMap<>(automatic);
        ipEmpty.put("routing", PolicyFixtures.routing("ipInclude", List.of(), List.of(), List.of()));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(ipEmpty));
        Map<String, Object> badNetwork = new LinkedHashMap<>(automatic);
        badNetwork.put("routing", PolicyFixtures.routing("ipInclude", List.of(), List.of("example.com"), List.of()));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(badNetwork));

        // WIRE-V2: an Android schema-2 plan always carries routing; null is invalid
        // even for the default automatic/all policy (no "null means all" relaxation).
        Map<String, Object> nullRouting = new LinkedHashMap<>(automatic);
        nullRouting.put("routing", null);
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(nullRouting));
        Map<String, Object> nullRoutingAll = new LinkedHashMap<>(PolicyFixtures.plan(List.of("awg1"), false));
        nullRoutingAll.put("routing", null);
        PolicyFixtures.check(PolicyFixtures.parsePlan(PolicyFixtures.plan(List.of("awg1"), false)).routing.mode.equals("all"), "fixture is automatic/all");
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(nullRoutingAll));
        Map<String, Object> missingRouting = new LinkedHashMap<>(automatic);
        missingRouting.remove("routing");
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(missingRouting));

        // priorityProtocol is verbatim and may be null; non-strings are invalid.
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "priorityProtocol", 4)));
        PolicyPlan verbatim = PolicyFixtures.parsePlan(mutate(automatic, "priorityProtocol", "future-protocol"));
        PolicyFixtures.check(verbatim.priorityProtocol.equals("future-protocol"), "priority is not revalidated against the list");

        // C5 site and bounded timeout.
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "site", "http://youtube.com")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "site", "https://user:pass@youtube.com")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "site", "https://youtube.com/#fragment")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "timeoutSeconds", 4)));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "timeoutSeconds", 61)));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "siteCheckEnabled", "true")));
        PolicyFixtures.checkInvalid(() -> PolicyFixtures.parsePlan(mutate(automatic, "consentRevision", "2026-10-19")));
        PolicyFixtures.check(PolicyFixtures.parsePlan(mutate(automatic, "consentRevision", "")).consentRevision.isEmpty(), "empty consent record parses");

        // Envelope and receipt strictness.
        PolicyEnvelope ready = PolicyFixtures.envelope(automatic, PublicationPhase.READY, PolicyFixtures.TX, PolicyFixtures.GEN);
        PolicyEnvelope reparsed = PolicyEnvelope.parse(StrictJson.parse(ready.canonicalJson()), "envelope");
        PolicyFixtures.check(reparsed.phase == PublicationPhase.READY && reparsed.sameCommit(ready), "envelope round-trip");
        PolicyFixtures.check(reparsed.receipt().sameCommit(ready.receipt()), "receipt identity");
        for (PublicationPhase phase : new PublicationPhase[]{PublicationPhase.PENDING, PublicationPhase.PENDING_UNKNOWN, PublicationPhase.READY}) {
            PolicyEnvelope envelope = new PolicyEnvelope(phase, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
                PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, plan, null);
            PolicyFixtures.check(PolicyEnvelope.parse(StrictJson.parse(envelope.canonicalJson()), "e").phase == phase, "phase " + phase.wire);
        }
        PolicyFixtures.checkInvalid(() -> new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, null, null));
        PolicyFixtures.checkInvalid(() -> new PolicyEnvelope(PublicationPhase.PENDING, "G" + PolicyFixtures.STORE.substring(1),
            PolicyFixtures.INSTANCE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, plan, null));
        PolicyFixtures.checkInvalid(() -> new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX.substring(1), PolicyFixtures.GEN, null, plan, null));
        Map<String, Object> envelopeJson = new LinkedHashMap<>(StrictJson.asObject(StrictJson.parse(ready.canonicalJson()), "envelope"));
        PolicyFixtures.checkInvalid(() -> PolicyEnvelope.parse(mutate(envelopeJson, "schema", 2), "envelope"));
        PolicyFixtures.checkInvalid(() -> PolicyEnvelope.parse(mutate(envelopeJson, "extra", 1), "envelope"));
        PolicyFixtures.checkInvalid(() -> PolicyEnvelope.parse(mutate(envelopeJson, "phase", "automatic"), "envelope"));
        Map<String, Object> receipt = new LinkedHashMap<>(ready.receipt().toJson());
        PolicyFixtures.checkInvalid(() -> PolicyReceipt.parse(mutate(receipt, "version", 2), "receipt"));
        PolicyFixtures.checkInvalid(() -> PolicyReceipt.parse(mutate(receipt, "storeIdentity", "x"), "receipt"));
        PolicyReceipt parsedReceipt = PolicyReceipt.parse(StrictJson.parse(StrictJson.write(receipt)), "receipt");
        PolicyFixtures.check(parsedReceipt.sameCommit(ready.receipt()), "receipt parse");

        // Canonical routing helper is the same code path SplitRouting will delegate to.
        RoutingCanon.Snapshot canonical = RoutingCanon.canonical("include", List.of("z.app", "a.app"), List.of(), List.of());
        PolicyFixtures.check(canonical.packages.equals(List.of("a.app", "z.app")), "packages sorted");
        RoutingCanon.Snapshot persisted = RoutingCanon.fromPersistedJson(
            "{\"schema\":1,\"revision\":\"r\",\"mode\":\"ipInclude\",\"packages\":[],\"networks\":[\"192.168.0.0/16\",\"10.0.0.0/8\"],\"domains\":[\"B.example.com\"],\"resolved\":[\"203.0.113.1/32\"]}");
        PolicyFixtures.check(persisted.networks.equals(List.of("10.0.0.0/8", "192.168.0.0/16")), "persisted networks canonical");
        PolicyFixtures.check(persisted.domains.equals(List.of("b.example.com")), "persisted domains canonical");
        PolicyFixtures.check(persisted.routes().size() == 2, "resolved overlay excluded from snapshot");

        System.out.println("PASS policy wire: schema2 plan, golden config digests (trailing LF), exact types/budget, "
            + "ids/profiles identity, manual/automatic selection rules, canonical sorted routing, verbatim priority, "
            + "C5 site, envelope/receipt strictness");
    }

    private static Object profile(String id, String protocol, String digest) {
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("id", id);
        profile.put("protocol", protocol);
        profile.put("endpoint", PolicyFixtures.endpointOf(id));
        profile.put("configDigest", digest);
        return profile;
    }

    private static Object aliasProfile(String id, String protocol) {
        return profile(id, protocol, PolicyFixtures.digestOf(id));
    }

    private PolicyWireTest() { }
}
