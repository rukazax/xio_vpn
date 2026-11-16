package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The single versioned native policy envelope. It is the only admission
 * authority: the old raw {@code connectionPlan} preference is never read as one.
 *
 * <p>A {@code READY} envelope names exactly one committed plan generation and
 * transaction; {@code PENDING}/{@code PENDING_UNKNOWN} name a proposal whose
 * durable outcome is not yet proven; {@code BLOCKED} refuses admission.
 */
public final class PolicyEnvelope {
    public static final int SCHEMA = 1;

    public final PublicationPhase phase;
    public final String storeIdentity;
    public final String instanceNonce;
    public final String controllerNonce;
    public final String transactionId;
    public final String planGeneration;
    public final String expectedGeneration;
    public final PolicyPlan plan;
    public final String reason;

    public PolicyEnvelope(PublicationPhase phase, String storeIdentity, String instanceNonce, String controllerNonce,
                          String transactionId, String planGeneration, String expectedGeneration,
                          PolicyPlan plan, String reason) {
        if (phase == null) throw new StrictJson.Invalid("phase: missing");
        this.phase = phase;
        this.storeIdentity = PolicyReceipt.requireHex(storeIdentity, 64, "storeIdentity");
        this.instanceNonce = PolicyReceipt.requireHex(instanceNonce, 32, "instanceNonce");
        this.controllerNonce = PolicyReceipt.requireHex(controllerNonce, 32, "controllerNonce");
        this.transactionId = PolicyReceipt.requireHex(transactionId, 32, "transactionId");
        this.planGeneration = PolicyReceipt.requireHex(planGeneration, 32, "planGeneration");
        this.expectedGeneration = expectedGeneration == null ? null
            : PolicyReceipt.requireHex(expectedGeneration, 32, "expectedGeneration");
        if (phase != PublicationPhase.BLOCKED && plan == null)
            throw new StrictJson.Invalid("plan: required for phase " + phase.wire);
        this.plan = plan;
        if (reason != null && (reason.isEmpty() || reason.length() > 200))
            throw new StrictJson.Invalid("reason: invalid length");
        this.reason = reason;
    }

    public static PolicyEnvelope parse(Object value, String path) {
        Map<String, Object> json = StrictJson.asObject(value, path);
        StrictJson.exactKeys(json, path, "schema", "phase", "storeIdentity", "instanceNonce", "controllerNonce",
            "transactionId", "planGeneration", "expectedGeneration", "plan", "reason");
        long schema = StrictJson.integer(json.get("schema"), path + ".schema");
        if (schema != SCHEMA) throw new StrictJson.Invalid(path + ".schema: unsupported");
        PublicationPhase phase = PublicationPhase.parse(StrictJson.string(json.get("phase"), path + ".phase"));
        Object rawPlan = json.get("plan");
        PolicyPlan plan = rawPlan == null ? null : PolicyPlan.parse(rawPlan, path + ".plan");
        String reason = StrictJson.stringOrNull(json.get("reason"), path + ".reason");
        return new PolicyEnvelope(phase,
            StrictJson.string(json.get("storeIdentity"), path + ".storeIdentity"),
            StrictJson.string(json.get("instanceNonce"), path + ".instanceNonce"),
            StrictJson.string(json.get("controllerNonce"), path + ".controllerNonce"),
            StrictJson.string(json.get("transactionId"), path + ".transactionId"),
            StrictJson.string(json.get("planGeneration"), path + ".planGeneration"),
            StrictJson.stringOrNull(json.get("expectedGeneration"), path + ".expectedGeneration"),
            plan, reason);
    }

    public PolicyReceipt receipt() {
        return new PolicyReceipt(storeIdentity, instanceNonce, controllerNonce, transactionId, planGeneration);
    }

    /** Same committed generation, same committed bytes. */
    public boolean sameCommit(PolicyEnvelope other) {
        return other != null && phase == PublicationPhase.READY && other.phase == PublicationPhase.READY
            && receipt().sameCommit(other.receipt()) && plan.canonicalJson().equals(other.plan.canonicalJson());
    }

    Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("schema", SCHEMA);
        json.put("phase", phase.wire);
        json.put("storeIdentity", storeIdentity);
        json.put("instanceNonce", instanceNonce);
        json.put("controllerNonce", controllerNonce);
        json.put("transactionId", transactionId);
        json.put("planGeneration", planGeneration);
        json.put("expectedGeneration", expectedGeneration);
        json.put("plan", plan == null ? null : plan.toJson());
        json.put("reason", reason);
        return json;
    }

    public String canonicalJson() { return StrictJson.canonical(toJson()); }
}
