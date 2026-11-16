package app.xio.xio;

import java.util.List;
import java.util.Map;

/** The raw legacy mirror may drive display only while it is also admissible. */
public final class LegacyDisplayTest {
    private static final String LEGACY =
        "{\"ids\":[\"awg1\",\"xr1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
            + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}";

    public static void main(String[] args) {
        Map<String, Object> plan = PolicyFixtures.plan(List.of("awg1", "xr1"), false);
        String pristine = PolicyFixtures.documentText(PolicyFixtures.document(null));
        String versionedNoReceipt = PolicyFixtures.documentText(PolicyFixtures.documentNoReceipt(plan));
        String versioned = PolicyFixtures.documentText(PolicyFixtures.document(plan));

        // Valid pristine legacy: the only case that may influence activeId.
        List<String> ids = DurableAdmission.legacyIdsIfPristine(false, LEGACY, pristine);
        PolicyFixtures.check(ids != null && ids.equals(List.of("awg1", "xr1")), "pristine legacy ids");

        // Any versioned envelope phase wins over the mirror, independently of the
        // document: pending, blocked and malformed all mean versionedOwnership.
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(true, LEGACY, pristine) == null,
            "versioned ownership hides the raw mirror");
        for (boolean versionedOwnership : new boolean[]{true}) {
            PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(versionedOwnership, LEGACY, versionedNoReceipt) == null,
                "pending/blocked + versioned document is not display authority");
        }

        // A versioned document (marker or receipt) also refuses the mirror.
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, LEGACY, versionedNoReceipt) == null,
            "connectionPolicy marker refuses the mirror");
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, LEGACY, versioned) == null,
            "committed receipt refuses the mirror");

        // A present receipt key with a null value is still the versioned boundary.
        String nullReceiptNoMarker = PolicyFixtures.documentText(PolicyFixtures.documentNullReceipt(false, plan));
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, LEGACY, nullReceiptNoMarker) == null,
            "present null receipt key refuses the mirror");

        // Malformed/absent inputs never produce ids.
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, null, pristine) == null, "absent raw plan");
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, LEGACY, null) == null, "absent document");
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, "{}", pristine) == null, "malformed raw plan");
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false, LEGACY, "{not json") == null, "malformed document");
        PolicyFixtures.check(DurableAdmission.legacyIdsIfPristine(false,
            LEGACY.replace("\"automatic\"", "\"selectedOnly\""), pristine) == null, "manual raw plan is never display authority");

        System.out.println("PASS legacy display gate: pristine legacy only; versioned envelope (pending/blocked/malformed), "
            + "connectionPolicy marker and committed receipt all hide the raw mirror");
    }

    private LegacyDisplayTest() { }
}
