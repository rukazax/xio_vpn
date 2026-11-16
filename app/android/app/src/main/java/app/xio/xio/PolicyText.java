package app.xio.xio;

/**
 * Blank/whitespace predicate shared by every saved-config admission path.
 *
 * <p>Dart's {@code String.trim().isEmpty()} uses the Unicode whitespace set, not
 * ASCII-only {@link String#trim()}. The parent's Dart 3.13.5 parity probe fixes
 * the matrix: blank = U+0009–000D, U+0020, U+0085, U+00A0, U+1680,
 * U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF; non-blank =
 * U+0000, U+001C–001F, U+180E, U+200B. The predicate is applied to the exact
 * saved string; hashing never trims or rewrites those bytes.
 */
public final class PolicyText {
    public static boolean isWhitespaceCodePoint(int codePoint) {
        return (codePoint >= 0x0009 && codePoint <= 0x000D)
            || codePoint == 0x0020
            || codePoint == 0x0085
            || codePoint == 0x00A0
            || codePoint == 0x1680
            || (codePoint >= 0x2000 && codePoint <= 0x200A)
            || codePoint == 0x2028
            || codePoint == 0x2029
            || codePoint == 0x202F
            || codePoint == 0x205F
            || codePoint == 0x3000
            || codePoint == 0xFEFF;
    }

    /** Empty or composed solely of Dart-trim whitespace. {@code null} is not blank. */
    public static boolean isWhitespaceOnly(String value) {
        if (value == null) return false;
        for (int index = 0; index < value.length(); ) {
            int codePoint = value.codePointAt(index);
            if (!isWhitespaceCodePoint(codePoint)) return false;
            index += Character.charCount(codePoint);
        }
        return true;
    }

    private PolicyText() { }
}
