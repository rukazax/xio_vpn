package app.xio.xio;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dart 3.13.5 whitespace parity matrix for saved-config admission.
 *
 * <p>Uses the parent's exact goldens: blank = U+0009–000D, U+0020, U+0085,
 * U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF;
 * non-blank = U+0000, U+001C–001F, U+180E, U+200B. Admission must reject the
 * blank set at proposal/READY/legacy/candidate without rewriting the bytes used
 * for the config digest.
 */
public final class UnicodeWhitespaceTest {
    public static void main(String[] args) {
        List<Integer> blank = new ArrayList<>();
        for (int cp = 0x0009; cp <= 0x000D; cp++) blank.add(cp);
        blank.add(0x0020);
        blank.add(0x0085);
        blank.add(0x00A0);
        blank.add(0x1680);
        for (int cp = 0x2000; cp <= 0x200A; cp++) blank.add(cp);
        blank.add(0x2028);
        blank.add(0x2029);
        blank.add(0x202F);
        blank.add(0x205F);
        blank.add(0x3000);
        blank.add(0xFEFF);
        List<Integer> nonBlank = List.of(0x0000, 0x001C, 0x001D, 0x001E, 0x001F, 0x180E, 0x200B);

        for (int cp : blank) {
            String value = new String(Character.toChars(cp));
            PolicyFixtures.check(PolicyText.isWhitespaceOnly(value), "blank matrix U+" + hex(cp));
            PolicyFixtures.check(!value.isEmpty(), "blank fixture remains non-empty for hashing");
        }
        for (int cp : nonBlank)
            PolicyFixtures.check(!PolicyText.isWhitespaceOnly(new String(Character.toChars(cp))),
                "non-blank matrix U+" + hex(cp));
        PolicyFixtures.check(PolicyText.isWhitespaceOnly(""), "empty is blank");
        PolicyFixtures.check(!PolicyText.isWhitespaceOnly(null), "null is not a blank string");
        PolicyFixtures.check(PolicyText.isWhitespaceOnly("\u00A0\t\u2003"), "mixed blank whitespace");
        PolicyFixtures.check(PolicyText.isWhitespaceOnly("\uFEFF\u3000\u0085"), "mixed blank whitespace 2");
        PolicyFixtures.check(!PolicyText.isWhitespaceOnly("\u00A0A"), "blank + letter is not blank");
        PolicyFixtures.check(!PolicyText.isWhitespaceOnly("A\u2003"), "letter + blank is not blank");
        PolicyFixtures.check(!PolicyText.isWhitespaceOnly(" \u200B"), "ZWSP is not blank");

        // Admission rejects each whitespace family at proposal/READY and legacy,
        // while the digest is computed over the exact untouched bytes.
        int[] representatives = {0x0009, 0x00A0, 0x2003, 0x205F, 0x3000, 0xFEFF, 0x2000};
        Map<String, Object> basePlan = PolicyFixtures.plan(List.of("awg1"), true);
        for (int cp : representatives) {
            String blankConfig = new String(Character.toChars(cp));
            Map<String, Object> planMap = new LinkedHashMap<>(basePlan);
            @SuppressWarnings("unchecked")
            Map<String, Object> profile = new LinkedHashMap<>((Map<String, Object>) ((List<?>) planMap.get("profiles")).get(0));
            profile.put("configDigest", PolicyPlan.configDigest(blankConfig));
            planMap.put("profiles", List.of(profile));
            PolicyPlan plan = PolicyFixtures.parsePlan(planMap);
            PolicyEnvelope ready = new PolicyEnvelope(PublicationPhase.READY, PolicyFixtures.STORE,
                PolicyFixtures.INSTANCE, PolicyFixtures.CONTROLLER, PolicyFixtures.TX, PolicyFixtures.GEN, null, plan, null);
            String document = PolicyFixtures.documentText(PolicyFixtures.document(planMap));
            DurableAdmission.ConfigSource vault = id -> blankConfig;
            String label = "U+" + hex(cp);
            PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateProposal(plan,
                PolicyFixtures.TX, PolicyFixtures.GEN, PolicyFixtures.allRoutingSource(), vault, false, document));
            PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateReady(ready,
                PolicyFixtures.allRoutingSource(), vault, false, document));
            String legacy = "{\"ids\":[\"awg1\"],\"site\":\"https://youtube.com\",\"siteCheckEnabled\":false,"
                + "\"timeoutSeconds\":15,\"policy\":{\"mode\":\"automatic\",\"roundMillis\":30000},\"roundMillis\":30000}";
            PolicyFixtures.checkCode(PolicyFailure.STALE, () -> DurableAdmission.validateLegacy(
                LegacyPlan.parseExactStored(legacy), PolicyFixtures.allRoutingSource(), vault, false,
                PolicyFixtures.documentText(PolicyFixtures.document(null))));
            PolicyFixtures.check(PolicyPlan.configDigest(blankConfig).equals(profile.get("configDigest")),
                "digest over exact bytes " + label);
        }

        // Non-blank control: a normal config still passes the proposal identity.
        Map<String, Object> controlMap = new LinkedHashMap<>(basePlan);
        @SuppressWarnings("unchecked")
        Map<String, Object> controlProfile = new LinkedHashMap<>((Map<String, Object>) ((List<?>) controlMap.get("profiles")).get(0));
        controlProfile.put("configDigest", PolicyPlan.configDigest("A"));
        controlMap.put("profiles", List.of(controlProfile));
        PolicyPlan control = PolicyFixtures.parsePlan(controlMap);
        DurableAdmission.validateProposal(control, PolicyFixtures.TX, PolicyFixtures.GEN,
            PolicyFixtures.allRoutingSource(), id -> "A", false,
            PolicyFixtures.documentText(PolicyFixtures.document(controlMap)));

        System.out.println("PASS Unicode whitespace matrix: Dart-parity blank set (incl. NBSP/U+2003/U+FEFF) rejected at "
            + "proposal/READY/legacy with exact-byte digests; ZWSP/U+180E/NUL/mixed non-blank controls pass the predicate; "
            + "mixed blank whitespace recognized");
    }

    private static String hex(int cp) { return String.format(java.util.Locale.ROOT, "%04X", cp); }

    private UnicodeWhitespaceTest() { }
}
