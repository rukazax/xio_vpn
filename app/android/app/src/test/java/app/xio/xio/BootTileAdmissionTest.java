package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * G3 positive/negative proof for the autonomous boot/Tile path.
 *
 * <p>A fresh Android process (no Flutter isolate) loads the envelope as the
 * process's first (and therefore durable) read, re-proves it against the real
 * durable document and vault, and only then admits a candidate. The positive
 * case must work: "unknown" is not an acceptable steady state. The negative
 * cases must stay blocked with the same code path.
 */
public final class BootTileAdmissionTest {
    /** Fresh-process store: the first cached read is exactly what is on disk. */
    static final class DiskStore implements PolicyJournal.Store {
        String disk;
        DiskStore(String disk) { this.disk = disk; }
        public String cached() { return disk; }
        public boolean commit(String value) { disk = value; return true; }
    }

    private static PolicyJournal boot(String envelopeJson) {
        PolicyJournal journal = new PolicyJournal(new DiskStore(envelopeJson), new PolicyJournal.Gate() {
            public void reservePolicy(String transactionId) { }
            public void revokePolicy(String transactionId) { }
            public void releasePolicy(String transactionId) { }
        });
        journal.load();
        return journal;
    }

    private static PolicyEnvelope readyEnvelope(Map<String, Object> plan) {
        return new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, PolicyFixtures.parsePlan(plan), null);
    }

    public static void main(String[] args) throws Exception {
        Map<String, Object> plan = PolicyFixtures.plan(List.of("awg1", "xr1"), false);
        PolicyEnvelope ready = readyEnvelope(plan);
        String document = PolicyFixtures.documentText(PolicyFixtures.document(plan));

        // --- POSITIVE: restart with a valid durable READY pair, no Flutter. ----
        PolicyJournal journal = boot(ready.canonicalJson());
        PolicyFixtures.check(journal.status() == PolicyJournal.Status.READY, "boot loads READY from disk");
        PolicyFixtures.check(journal.readyForAdmission(), "boot READY is process-confirmed without any Flutter call");
        PolicyEnvelope loaded = journal.revalidatable();
        PolicyFixtures.check(loaded != null, "boot envelope may be validated");
        DurableAdmission.Admission admission = DurableAdmission.validateReady(loaded, PolicyFixtures.allRoutingSource(),
            PolicyFixtures.vault(), false, document);
        admission.requireActivatable();
        PolicyFixtures.check(admission.candidates.equals(List.of("awg1", "xr1")), "boot candidate list");
        PolicyReceipt receipt = journal.readyReceipt(PolicyFixtures.INSTANCE);
        PolicyFixtures.check(receipt.transactionId.equals(PolicyFixtures.TX)
            && receipt.planGeneration.equals(PolicyFixtures.GEN)
            && receipt.storeIdentity.equals(PolicyFixtures.STORE), "boot receipt identity");
        PolicyFixtures.check(receipt.instanceNonce.equals(PolicyFixtures.INSTANCE), "boot receipt uses this engine lifetime");
        DurableAdmission.validateCandidate(admission, "awg1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        DurableAdmission.validateCandidate(admission, "xr1", PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document);
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateCandidate(admission, "awg2",
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, document));

        // Manual plan: exactly the selected profile, restart included.
        Map<String, Object> manualPlan = PolicyFixtures.plan(List.of("awg1"), true);
        PolicyJournal manualJournal = boot(readyEnvelope(manualPlan).canonicalJson());
        PolicyFixtures.check(manualJournal.readyForAdmission(), "manual boot READY");
        DurableAdmission.Admission manual = DurableAdmission.validateReady(manualJournal.revalidatable(),
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.document(manualPlan)));
        manual.requireActivatable();
        PolicyFixtures.check(manual.candidates.equals(List.of("awg1")) && manual.policy.selectedOnly(), "manual boot candidate");

        // Process restart while a publication was pending: not admissible.
        PolicyEnvelope pending = new PolicyEnvelope(PublicationPhase.PENDING, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, PolicyFixtures.parsePlan(plan), null);
        PolicyJournal pendingBoot = boot(pending.canonicalJson());
        PolicyFixtures.check(pendingBoot.status() == PolicyJournal.Status.PENDING && !pendingBoot.readyForAdmission(),
            "pending restart stays blocked");
        PolicyFixtures.check(pendingBoot.revalidatable() == null, "pending restart has no revalidatable plan");

        // Process restart into a blocked envelope: not admissible.
        PolicyEnvelope blocked = new PolicyEnvelope(PublicationPhase.BLOCKED, PolicyFixtures.STORE, PolicyFixtures.INSTANCE,
            PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, null, "Publication revoked");
        PolicyJournal blockedBoot = boot(blocked.canonicalJson());
        PolicyFixtures.check(blockedBoot.status() == PolicyJournal.Status.BLOCKED && !blockedBoot.readyForAdmission(),
            "blocked restart stays blocked");

        // Malformed persisted envelope: blocked, never guessed.
        PolicyJournal malformedBoot = boot("{\"schema\":1,\"phase\":\"ready\"}");
        PolicyFixtures.check(malformedBoot.status() == PolicyJournal.Status.BLOCKED
            && malformedBoot.envelope() == null && !malformedBoot.readyForAdmission(), "malformed restart stays blocked");

        // A READY envelope with no/incorrect durable document is never admitted.
        PolicyFixtures.checkCode(PolicyFailure.UNKNOWN, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.document(null))));
        Map<String, Object> versionedNoMarker = PolicyFixtures.document(plan);
        versionedNoMarker.remove("connectionPolicy");
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false, PolicyFixtures.documentText(versionedNoMarker)));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            PolicyFixtures.allRoutingSource(), vaultWith("awg1", PolicyFixtures.AWG_NO_TRAILING)::get, false, document));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
            () -> RoutingCanon.canonical("include", List.of("a.app"), List.of(), List.of()), PolicyFixtures.vault(), false,
            document));

        // Exact crash pair for the receipt-required reconcile:
        // cut A — native pending ACK, process dies before the app's document rename,
        // so the durable document still has no receipt for this plan => blocked;
        // cut B — the app's owned rename has written connectionPolicy + the NEW receipt
        // => the same reconcile proposal validates and may ACK.
        String tx2 = "77777777777777777777777777777777", gen2 = "88888888888888888888888888888888";
        Map<String, Object> recoveredPlanMap = PolicyFixtures.plan(List.of("awg1"), true);
        PolicyPlan recoveredPlan = PolicyFixtures.parsePlan(recoveredPlanMap);
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(recoveredPlan, tx2, gen2,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(recoveredPlanMap))));
        DurableAdmission.validateProposal(recoveredPlan, tx2, gen2, PolicyFixtures.allRoutingSource(),
            PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentWithReceipt(recoveredPlanMap, tx2, gen2)));
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(recoveredPlan, tx2, gen2,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentWithReceipt(recoveredPlanMap, tx2, PolicyFixtures.GEN))));

        // Versioned document + no envelope + an old raw plan: Tile must not fall
        // back to legacy automatic (the predicate is source-asserted in
        // PolicyWiringTest; the admission rule is proven here).
        LegacyPlan legacy = LegacyPlan.parseExactStored(
            "{\"ids\":[\"awg1\",\"xr1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
                + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}");
        PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(legacy,
            PolicyFixtures.allRoutingSource(), PolicyFixtures.vault(), false,
            PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(plan))));

        System.out.println("PASS boot/Tile without Flutter: durable READY becomes process-confirmed and admits automatic and "
            + "manual candidates; pending/blocked/malformed restarts, missing marker, digest/routing divergence and a "
            + "versioned document without envelope all stay blocked");
    }

    private static Map<String, String> vaultWith(String id, String raw) {
        Map<String, String> vault = new LinkedHashMap<>(PolicyFixtures.VAULT);
        vault.put(id, raw);
        return vault;
    }

    private BootTileAdmissionTest() { }
}
