package app.xio.xio;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The activation attachment: the exact committed generation a foreground or tile
 * request was admitted against. It is captured with the plan and carried through
 * every candidate; it is never re-sampled at execution time.
 */
public final class PolicyReceipt {
    public static final int VERSION = 1;

    public final String storeIdentity;
    public final String instanceNonce;
    public final String controllerNonce;
    public final String transactionId;
    public final String planGeneration;

    public PolicyReceipt(String storeIdentity, String instanceNonce, String controllerNonce,
                         String transactionId, String planGeneration) {
        this.storeIdentity = requireHex(storeIdentity, 64, "receipt.storeIdentity");
        this.instanceNonce = requireHex(instanceNonce, 32, "receipt.instanceNonce");
        this.controllerNonce = requireHex(controllerNonce, 32, "receipt.controllerNonce");
        this.transactionId = requireHex(transactionId, 32, "receipt.transactionId");
        this.planGeneration = requireHex(planGeneration, 32, "receipt.planGeneration");
    }

    public static PolicyReceipt parse(Object value, String path) {
        Map<String, Object> json = StrictJson.asObject(value, path);
        StrictJson.exactKeys(json, path, "version", "storeIdentity", "instanceNonce", "controllerNonce",
            "transactionId", "planGeneration");
        long version = StrictJson.integer(json.get("version"), path + ".version");
        if (version != VERSION) throw new StrictJson.Invalid(path + ".version: unsupported");
        return new PolicyReceipt(
            StrictJson.string(json.get("storeIdentity"), path + ".storeIdentity"),
            StrictJson.string(json.get("instanceNonce"), path + ".instanceNonce"),
            StrictJson.string(json.get("controllerNonce"), path + ".controllerNonce"),
            StrictJson.string(json.get("transactionId"), path + ".transactionId"),
            StrictJson.string(json.get("planGeneration"), path + ".planGeneration"));
    }

    public static PolicyReceipt fromEnvelope(PolicyEnvelope envelope) {
        return new PolicyReceipt(envelope.storeIdentity, envelope.instanceNonce, envelope.controllerNonce,
            envelope.transactionId, envelope.planGeneration);
    }

    /** Content identity only: `instanceNonce` is compared separately by the caller. */
    public boolean sameCommit(PolicyReceipt other) {
        return storeIdentity.equals(other.storeIdentity) && transactionId.equals(other.transactionId)
            && planGeneration.equals(other.planGeneration);
    }

    public Map<String, Object> toJson() {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("version", VERSION);
        json.put("storeIdentity", storeIdentity);
        json.put("instanceNonce", instanceNonce);
        json.put("controllerNonce", controllerNonce);
        json.put("transactionId", transactionId);
        json.put("planGeneration", planGeneration);
        return json;
    }

    static String requireHex(String value, int length, String path) {
        if (value == null || value.length() != length) throw new StrictJson.Invalid(path + ": expected " + length + " lowercase hex");
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                throw new StrictJson.Invalid(path + ": expected lowercase hex");
        }
        return value;
    }
}
