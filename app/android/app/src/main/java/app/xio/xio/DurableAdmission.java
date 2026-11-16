package app.xio.xio;

import java.util.ArrayList;
import java.util.List;

/**
 * Re-derives admission identity from actual stored native state and compares it
 * with the committed plan before any stop/setup/effect.
 *
 * <p>This is deliberately read-only: native validates the app's durable document
 * and the vault, it never rewrites them. Every mismatch is {@code POLICY_STALE}
 * and no effect may follow it.
 */
public final class DurableAdmission {
    /** Exact saved/base config text for a profile id, as {@code readConfig} returns it. */
    public interface ConfigSource { String read(String id); }

    /** The canonical routing policy the native side would report to {@code routingGet}. */
    public interface RoutingSource { RoutingCanon.Snapshot read(); }

    public static final class Admission {
        public final PolicyPlan plan;
        public final PolicyReceipt receipt;
        public final String generation;
        public final List<String> candidates;
        public final ConnectionPolicy policy;
        public final String site;
        public final boolean siteCheckEnabled;
        public final int timeoutSeconds;
        public final RoutingCanon.Snapshot routing;
        public final String priorityProtocol;
        public final boolean legacy;

        Admission(PolicyPlan plan, PolicyReceipt receipt, String generation, List<String> candidates,
                  ConnectionPolicy policy, String site, boolean siteCheckEnabled, int timeoutSeconds,
                  RoutingCanon.Snapshot routing, String priorityProtocol, boolean legacy) {
            this.plan = plan;
            this.receipt = receipt;
            this.generation = generation;
            this.candidates = List.copyOf(candidates);
            this.policy = policy;
            this.site = site;
            this.siteCheckEnabled = siteCheckEnabled;
            this.timeoutSeconds = timeoutSeconds;
            this.routing = routing;
            this.priorityProtocol = priorityProtocol;
            this.legacy = legacy;
        }

        public void requireActivatable() {
            if (candidates.isEmpty())
                throw PolicyFailure.invalid("No admissible profile for this saved policy");
        }
    }

    // ------------------------------------------------------------- READY plan

    public static Admission validateReady(PolicyEnvelope envelope, RoutingSource routingSource,
                                          ConfigSource configs, boolean nativeClientOnly, String documentText) {
        if (envelope == null) throw PolicyFailure.unknown("No committed connection policy");
        if (envelope.phase != PublicationPhase.READY)
            throw PolicyFailure.unknown("Connection policy is not ready (" + envelope.phase.wire + ")");
        PolicyPlan plan = envelope.plan;
        if (plan == null) throw PolicyFailure.invalid("Committed policy has no plan");
        DurableDocument document = parseDocument(documentText);
        checkCommittedReceipt(document, envelope);
        RoutingCanon.Snapshot routing = routing(routingSource);
        checkPolicyIdentity(plan, document, routing, configs, nativeClientOnly);
        for (String id : plan.ids)
            checkProfile(id, plan, document, configs, nativeClientOnly);
        return new Admission(plan, envelope.receipt(), envelope.planGeneration, plan.ids, plan.policy,
            plan.site, plan.siteCheckEnabled, plan.timeoutSeconds, routing, plan.priorityProtocol, false);
    }

    /**
     * Re-check one candidate immediately before an effect. Uses the same captured
     * plan/receipt but reads the stored document, routing and exact saved config
     * again, so a concurrent vault/routing edit is {@code POLICY_STALE}, not a
     * stale connection.
     */
    public static void validateCandidate(Admission admission, String attemptedId, RoutingSource routingSource,
                                         ConfigSource configs, boolean nativeClientOnly, String documentText) {
        if (admission == null) throw PolicyFailure.unknown("No admitted connection policy");
        if (admission.plan == null) {
            validateLegacyCandidate(admission, attemptedId, documentText, configs, nativeClientOnly);
            return;
        }
        if (!admission.candidates.contains(attemptedId)) throw PolicyFailure.stale("Candidate is not in the committed plan");
        DurableDocument document = parseDocument(documentText);
        RoutingCanon.Snapshot routing = routing(routingSource);
        checkPolicyIdentity(admission.plan, document, routing, configs, nativeClientOnly);
        checkProfile(attemptedId, admission.plan, document, configs, nativeClientOnly);
        if (!routing.equals(admission.routing)) throw PolicyFailure.stale("Routing policy changed");
    }

    private static void checkCommittedReceipt(DurableDocument document, PolicyEnvelope envelope) {
        if (!document.hasPlanReceiptKey)
            throw PolicyFailure.unknown("Saved document has no committed plan receipt");
        DurableDocument.Receipt receipt = document.receipt;
        if (receipt == null) throw PolicyFailure.invalid("Saved document has a null committed plan receipt");
        if (!receipt.transactionId.equals(envelope.transactionId)
            || !receipt.planGeneration.equals(envelope.planGeneration)
            || !receipt.plan.canonicalJson().equals(envelope.plan.canonicalJson()))
            throw PolicyFailure.stale("Saved document receipt does not match the native envelope");
    }
    private static void checkPolicyIdentity(PolicyPlan plan, DurableDocument document, RoutingCanon.Snapshot routing,
                                            ConfigSource configs, boolean nativeClientOnly) {
        if (plan.clientOnly != nativeClientOnly) throw PolicyFailure.stale("Plan was built for a different product");
        if (!document.consentReady()) throw PolicyFailure.invalid("Legal acknowledgement and VPN disclosure are required");
        // A versioned plan is only admissible against a versioned document: the
        // durable connectionPolicy marker must exist and agree exactly.
        if (!document.hasConnectionPolicy)
            throw PolicyFailure.stale("Saved document has no connection policy marker");
        if (!plan.policy.mode.equals(document.connectionPolicyMode))
            throw PolicyFailure.stale("Saved connection policy mode changed");
        if (!plan.consentRevision.equals("2026-10-18") || !"2026-10-18".equals(plan.vpnDisclosure))
            throw PolicyFailure.stale("Plan consent revision is not current");
        if (!java.util.Objects.equals(document.selectedId, plan.selectedId))
            throw PolicyFailure.stale("Selected profile changed");
        if (!plan.site.equals(document.checkSite) || plan.siteCheckEnabled != document.siteCheckEnabled)
            throw PolicyFailure.stale("Website-verification settings changed");
        if (plan.timeoutSeconds != document.timeoutSeconds) throw PolicyFailure.stale("Protocol timeout changed");
        if (!java.util.Objects.equals(plan.priorityProtocol, document.priorityProtocol))
            throw PolicyFailure.stale("Protocol priority changed");
        if (!plan.routing.equals(routing)) throw PolicyFailure.stale("Routing policy changed");
        if (plan.ids.isEmpty()) return;
        if (plan.manual() && (plan.ids.size() != 1 || !plan.selectedId.equals(plan.ids.get(0))))
            throw PolicyFailure.invalid("A manual plan must name exactly the selected profile");
        if (!plan.manual() && !plan.selectedId.equals(plan.ids.get(0)))
            throw PolicyFailure.stale("Automatic plan does not start with the selection");
        if (plan.manual() && plan.selectedId == null)
            throw PolicyFailure.invalid("A manual plan has no selection");
    }

    private static void checkProfile(String id, PolicyPlan plan, DurableDocument document, ConfigSource configs,
                                     boolean nativeClientOnly) {
        PolicyPlan.Profile expected = plan.profile(id);
        if (expected == null) throw PolicyFailure.invalid("Plan has no metadata for " + id);
        DurableDocument.Profile stored = document.profiles.get(id);
        if (stored == null) throw PolicyFailure.stale("Saved profile no longer exists: " + id);
        if (!stored.protocol.equals(expected.protocol)) throw PolicyFailure.stale("Profile protocol changed: " + id);
        if (!stored.endpoint.equals(expected.endpoint)) throw PolicyFailure.stale("Profile endpoint changed: " + id);
        if (!NativeProtocols.idMatches(expected.protocol, id)) throw PolicyFailure.invalid("Unsupported profile " + id);
        if (!document.eligible(id, nativeClientOnly)) throw PolicyFailure.stale("Profile is not eligible: " + id);
        String exact;
        try { exact = configs.read(id); }
        catch (RuntimeException failure) { throw new PolicyFailure(PolicyFailure.STALE, "Saved configuration unreadable: " + id, failure); }
        if (exact == null) throw PolicyFailure.stale("Saved configuration missing: " + id);
        if (PolicyText.isWhitespaceOnly(exact)) throw PolicyFailure.stale("Saved configuration is empty: " + id);
        if (!PolicyPlan.configDigest(exact).equals(expected.configDigest))
            throw PolicyFailure.stale("Saved configuration changed: " + id);
    }

    // -------------------------------------------------------- publication ACK

    /**
     * Re-derives the stored identity for a publication ACK. A commit or reconcile
     * may only be acknowledged after the durable document, its committed receipt,
     * the routing snapshot, the selection and every saved config match the
     * proposal; otherwise the caller writes a BLOCKED envelope and never reports
     * "mode confirmed".
     *
     * <p>Both `policyCommit` and `policyReconcile` require the exact durable
     * {@code connectionPlanReceipt}: an ACK without it would create a state that
     * the boot validator then rejects. A missing receipt stays blocked and is not
     * treated as a consistent snapshot; establishing a new receipt is an owned
     * publication performed by the app, never by native.
     */
    public static void validateProposal(PolicyPlan plan, String transactionId, String planGeneration,
                                        RoutingSource routingSource, ConfigSource configs, boolean nativeClientOnly,
                                        String documentText) {
        if (plan == null) throw PolicyFailure.invalid("Proposal has no plan");
        PolicyReceipt.requireHex(transactionId, 32, "transactionId");
        PolicyReceipt.requireHex(planGeneration, 32, "planGeneration");
        DurableDocument document = parseDocument(documentText);
        if (!document.hasPlanReceiptKey)
            throw PolicyFailure.stale("Saved document has no committed plan receipt");
        if (document.receipt == null)
            throw PolicyFailure.invalid("Saved document has a null committed plan receipt");
        DurableDocument.Receipt receipt = document.receipt;
        if (!receipt.transactionId.equals(transactionId)
            || !receipt.planGeneration.equals(planGeneration)
            || !receipt.plan.canonicalJson().equals(plan.canonicalJson()))
            throw PolicyFailure.stale("Saved document receipt does not match this proposal");
        checkPolicyIdentity(plan, document, routing(routingSource), configs, nativeClientOnly);
        for (String id : plan.ids) checkProfile(id, plan, document, configs, nativeClientOnly);
    }

    /** Legacy automatic is legal only against a genuinely pre-versioned document. */
    public static void requireLegacyState(DurableDocument document) {
        if (document.hasConnectionPolicy)
            throw PolicyFailure.stale("Saved document already carries a connection policy");
        if (document.hasPlanReceiptKey)
            throw PolicyFailure.stale("Saved document already carries a plan receipt boundary");
    }

    /**
     * Display-only candidate ids for active-id reconciliation.
     *
     * <p>The old raw plan may influence authoritative status only when it would
     * also be admissible: no versioned envelope of any phase, no connectionPolicy
     * marker and no receipt key (even a null one). A pending/blocked/malformed
     * versioned state or a versioned document returns {@code null}.
     */
    public static java.util.List<String> legacyIdsIfPristine(boolean versionedOwnership, String rawPlan, String documentText) {
        if (versionedOwnership || rawPlan == null || documentText == null) return null;
        LegacyPlan legacy;
        try { legacy = LegacyPlan.parseExactStored(rawPlan); }
        catch (RuntimeException failure) { return null; }
        DurableDocument document;
        try { document = DurableDocument.parse(documentText); }
        catch (RuntimeException failure) { return null; }
        try { requireLegacyState(document); }
        catch (PolicyFailure failure) { return null; }
        return legacy.ids;
    }
    // ----------------------------------------------------------- legacy plan

    public static Admission validateLegacy(LegacyPlan legacy, RoutingSource routingSource, ConfigSource configs,
                                           boolean nativeClientOnly, String documentText) {
        DurableDocument document = parseDocument(documentText);
        requireLegacyState(document);
        if (!document.consentReady()) throw PolicyFailure.invalid("Legal acknowledgement and VPN disclosure are required");
        if (!document.selectedId.equals(legacy.ids.get(0)))
            throw PolicyFailure.stale("Legacy plan does not start with the selected profile");
        if (!legacy.site.equals(document.checkSite) || legacy.siteCheckEnabled != document.siteCheckEnabled)
            throw PolicyFailure.stale("Website-verification settings changed");
        if (legacy.timeoutSeconds != document.timeoutSeconds) throw PolicyFailure.stale("Protocol timeout changed");
        RoutingCanon.Snapshot routing = routing(routingSource);
        for (String id : legacy.ids) {
            DurableDocument.Profile stored = document.profiles.get(id);
            if (stored == null) throw PolicyFailure.stale("Saved profile no longer exists: " + id);
            if (!NativeProtocols.idMatches(stored.protocol, id)) throw PolicyFailure.invalid("Unsupported profile " + id);
            if (!document.eligible(id, nativeClientOnly)) throw PolicyFailure.stale("Profile is not eligible: " + id);
            String exact;
            try { exact = configs.read(id); }
            catch (RuntimeException failure) { throw new PolicyFailure(PolicyFailure.STALE, "Saved configuration unreadable: " + id, failure); }
            if (exact == null) throw PolicyFailure.stale("Saved configuration missing: " + id);
            if (PolicyText.isWhitespaceOnly(exact)) throw PolicyFailure.stale("Saved configuration is empty: " + id);
        }
        return new Admission(null, null, legacy.generation, legacy.ids, ConnectionPolicy.automatic(), legacy.site,
            legacy.siteCheckEnabled, legacy.timeoutSeconds, routing, document.priorityProtocol, true);
    }

    private static void validateLegacyCandidate(Admission admission, String attemptedId, String documentText,
                                                ConfigSource configs, boolean nativeClientOnly) {
        if (!admission.candidates.contains(attemptedId)) throw PolicyFailure.stale("Candidate is not in the legacy plan");
        DurableDocument document = parseDocument(documentText);
        requireLegacyState(document);
        if (!document.consentReady()) throw PolicyFailure.invalid("Legal acknowledgement and VPN disclosure are required");
        if (!document.selectedId.equals(admission.candidates.get(0)))
            throw PolicyFailure.stale("Selected profile changed");
        DurableDocument.Profile stored = document.profiles.get(attemptedId);
        if (stored == null) throw PolicyFailure.stale("Saved profile no longer exists: " + attemptedId);
        if (!NativeProtocols.idMatches(stored.protocol, attemptedId))
            throw PolicyFailure.invalid("Unsupported profile " + attemptedId);
        if (!document.eligible(attemptedId, nativeClientOnly)) throw PolicyFailure.stale("Profile is not eligible: " + attemptedId);
        String exact;
        try { exact = configs.read(attemptedId); }
        catch (RuntimeException failure) { throw new PolicyFailure(PolicyFailure.STALE, "Saved configuration unreadable: " + attemptedId, failure); }
        if (exact == null) throw PolicyFailure.stale("Saved configuration missing: " + attemptedId);
        if (PolicyText.isWhitespaceOnly(exact)) throw PolicyFailure.stale("Saved configuration is empty: " + attemptedId);
    }

    // --------------------------------------------------------------- helpers

    private static DurableDocument parseDocument(String documentText) {
        if (documentText == null) throw PolicyFailure.unknown("Saved app document is unavailable");
        try { return DurableDocument.parse(documentText); }
        catch (StrictJson.Invalid failure) { throw PolicyFailure.invalid(failure.getMessage()); }
    }

    private static RoutingCanon.Snapshot routing(RoutingSource source) {
        if (source == null) throw PolicyFailure.invalid("Routing policy source is unavailable");
        try {
            RoutingCanon.Snapshot snapshot = source.read();
            if (snapshot == null) return RoutingCanon.absent();
            return snapshot;
        } catch (PolicyFailure failure) { throw failure; }
        catch (RuntimeException failure) { throw PolicyFailure.invalid("Routing policy is unreadable"); }
    }

    /** C5 website opt-out stays typed: an opted-out plan never opens the website. */
    public static boolean siteCheckEnabled(PolicyPlan plan) { return plan.siteCheckEnabled; }

    public static List<String> candidatesFor(PolicyPlan plan) { return new ArrayList<>(plan.ids); }

    private DurableAdmission() { }
}

