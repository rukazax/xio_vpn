package app.xio.xio;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Exact-shape JSON for the durable connection-policy wire.
 *
 * <p>{@code org.json} coerces types ({@code optLong}, {@code optString},
 * {@code optBoolean}) and that coercion is exactly how a present but malformed
 * saved policy used to degrade into "automatic". This reader never coerces:
 * every caller states the exact Java shape it expects, numbers keep their
 * literal so {@code 30000.0} or {@code 3e4} cannot pass as the integer 30000,
 * unknown and duplicate object keys are errors, and trailing input is an error.
 */
public final class StrictJson {
    public static final class Invalid extends IllegalArgumentException {
        public Invalid(String message) { super(message); }
    }

    /** A JSON number that has not been converted yet: validation decides. */
    public static final class Num {
        public final String literal;
        Num(String literal) { this.literal = literal; }
        @Override public String toString() { return literal; }
        @Override public boolean equals(Object other) { return other instanceof Num otherNum && literal.equals(otherNum.literal); }
        @Override public int hashCode() { return literal.hashCode(); }
    }

    private static final int MAX_LENGTH = 262144;

    private final String text;
    private int at;

    private StrictJson(String text) { this.text = text; }

    public static Object parse(String text) {
        if (text == null) throw new Invalid("Expected JSON value");
        if (text.length() > MAX_LENGTH) throw new Invalid("JSON document too large");
        StrictJson reader = new StrictJson(text);
        reader.space();
        Object value = reader.value(0);
        reader.space();
        if (reader.at != text.length()) throw new Invalid("Trailing data after JSON value");
        return value;
    }

    // ---------------------------------------------------------------- reading

    private Object value(int depth) {
        if (depth > 32) throw new Invalid("JSON nesting too deep");
        if (at >= text.length()) throw new Invalid("Unexpected end of JSON");
        char next = text.charAt(at);
        if (next == '{') return object(depth);
        if (next == '[') return array(depth);
        if (next == '"') return string();
        if (next == 't') return literal("true", Boolean.TRUE);
        if (next == 'f') return literal("false", Boolean.FALSE);
        if (next == 'n') return literal("null", null);
        if (next == '-' || (next >= '0' && next <= '9')) return number();
        throw new Invalid("Unexpected character in JSON at " + at);
    }

    private Object literal(String expected, Object value) {
        if (!text.startsWith(expected, at)) throw new Invalid("Invalid JSON literal at " + at);
        at += expected.length();
        return value;
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> result = new LinkedHashMap<>();
        at++;
        space();
        if (peek() == '}') { at++; return result; }
        while (true) {
            space();
            if (peek() != '"') throw new Invalid("Expected object key at " + at);
            String key = string();
            if (result.containsKey(key)) throw new Invalid("Duplicate JSON key: " + key);
            space();
            expect(':');
            space();
            result.put(key, value(depth + 1));
            space();
            char next = peek();
            if (next == ',') { at++; continue; }
            if (next == '}') { at++; return result; }
            throw new Invalid("Expected , or } at " + at);
        }
    }

    private List<Object> array(int depth) {
        List<Object> result = new ArrayList<>();
        at++;
        space();
        if (peek() == ']') { at++; return result; }
        while (true) {
            space();
            result.add(value(depth + 1));
            space();
            char next = peek();
            if (next == ',') { at++; continue; }
            if (next == ']') { at++; return result; }
            throw new Invalid("Expected , or ] at " + at);
        }
    }

    private String string() {
        at++;
        StringBuilder out = new StringBuilder();
        while (true) {
            if (at >= text.length()) throw new Invalid("Unterminated JSON string");
            char c = text.charAt(at++);
            if (c == '"') return out.toString();
            if (c < 0x20) throw new Invalid("Raw control character in JSON string");
            if (c != '\\') { out.append(c); continue; }
            if (at >= text.length()) throw new Invalid("Unterminated JSON escape");
            char escape = text.charAt(at++);
            switch (escape) {
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case '/': out.append('/'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'u': {
                    if (at + 4 > text.length()) throw new Invalid("Short unicode escape");
                    int value = 0;
                    for (int index = 0; index < 4; index++) {
                        int digit = Character.digit(text.charAt(at++), 16);
                        if (digit < 0) throw new Invalid("Invalid unicode escape");
                        value = (value << 4) | digit;
                    }
                    out.append((char) value);
                    break;
                }
                default: throw new Invalid("Invalid JSON escape");
            }
        }
    }

    private Num number() {
        int start = at;
        if (peek() == '-') at++;
        if (at >= text.length()) throw new Invalid("Truncated JSON number");
        char first = text.charAt(at);
        if (first == '0') at++;
        else if (first >= '1' && first <= '9') { while (at < text.length() && digital(text.charAt(at))) at++; }
        else throw new Invalid("Invalid JSON number");
        if (at < text.length() && text.charAt(at) == '.') {
            at++;
            if (at >= text.length() || !digital(text.charAt(at))) throw new Invalid("Invalid JSON fraction");
            while (at < text.length() && digital(text.charAt(at))) at++;
        }
        if (at < text.length() && (text.charAt(at) == 'e' || text.charAt(at) == 'E')) {
            at++;
            if (at < text.length() && (text.charAt(at) == '+' || text.charAt(at) == '-')) at++;
            if (at >= text.length() || !digital(text.charAt(at))) throw new Invalid("Invalid JSON exponent");
            while (at < text.length() && digital(text.charAt(at))) at++;
        }
        return new Num(text.substring(start, at));
    }

    private boolean digital(char c) { return c >= '0' && c <= '9'; }

    private void space() {
        while (at < text.length()) {
            char c = text.charAt(at);
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') at++;
            else return;
        }
    }

    private char peek() {
        if (at >= text.length()) throw new Invalid("Unexpected end of JSON");
        return text.charAt(at);
    }

    private void expect(char c) {
        if (at >= text.length() || text.charAt(at) != c) throw new Invalid("Expected " + c + " at " + at);
        at++;
    }

    // --------------------------------------------------------------- writing

    /** Deterministic serialization: object keys sorted, numbers keep their literal. */
    public static String write(Object value) { return emit(value); }

    /** Same bytes regardless of insertion order; used for content hashes. */
    public static String canonical(Object value) { return emit(value); }

    private static String emit(Object value) {
        StringBuilder out = new StringBuilder();
        emit(value, out);
        return out.toString();
    }

    private static void emit(Object value, StringBuilder out) {
        if (value == null) { out.append("null"); return; }
        if (value instanceof String text) { quote(text, out); return; }
        if (value instanceof Boolean flag) { out.append(flag ? "true" : "false"); return; }
        if (value instanceof Num number) { out.append(number.literal); return; }
        if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
            out.append(value); return;
        }
        if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) throw new Invalid("Non-string JSON key");
                sorted.put(key, entry.getValue());
            }
            out.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> entry : sorted.entrySet()) {
                if (!first) out.append(',');
                first = false;
                quote(entry.getKey(), out);
                out.append(':');
                emit(entry.getValue(), out);
            }
            out.append('}');
            return;
        }
        if (value instanceof Collection<?> list) {
            out.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) out.append(',');
                first = false;
                emit(item, out);
            }
            out.append(']');
            return;
        }
        throw new Invalid("Unsupported JSON value type: " + value.getClass().getName());
    }

    private static void quote(String text, StringBuilder out) {
        out.append('"');
        for (int index = 0; index < text.length(); index++) {
            char c = text.charAt(index);
            switch (c) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                default:
                    if (c < 0x20 || c == 0x7f) out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        out.append('"');
    }

    // ------------------------------------------------------------ accessors

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object value, String path) {
        if (!(value instanceof Map)) throw new Invalid(path + ": expected object");
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> array(Object value, String path) {
        if (!(value instanceof List)) throw new Invalid(path + ": expected array");
        return (List<Object>) value;
    }

    public static String string(Object value, String path) {
        if (!(value instanceof String text)) throw new Invalid(path + ": expected string");
        return text;
    }

    public static String stringOrNull(Object value, String path) {
        if (value == null) return null;
        return string(value, path);
    }

    public static boolean bool(Object value, String path) {
        if (!(value instanceof Boolean flag)) throw new Invalid(path + ": expected boolean");
        return flag;
    }

    /** Accepts only an exact integer literal; no fractions, exponents or coercion. */
    public static long integer(Object value, String path) {
        if (value instanceof Num number) {
            if (!number.literal.matches("-?(0|[1-9][0-9]*)"))
                throw new Invalid(path + ": expected integer");
            try { return Long.parseLong(number.literal); }
            catch (NumberFormatException failure) { throw new Invalid(path + ": integer out of range"); }
        }
        if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte)
            return ((Number) value).longValue();
        throw new Invalid(path + ": expected integer");
    }

    public static int integerInt(Object value, String path) {
        long number = integer(value, path);
        if (number < Integer.MIN_VALUE || number > Integer.MAX_VALUE) throw new Invalid(path + ": integer out of range");
        return (int) number;
    }

    /** Requires exactly these keys: unknown keys and missing keys both fail. */
    public static void exactKeys(Map<String, Object> object, String path, String... keys) {
        java.util.Set<String> expected = new java.util.LinkedHashSet<>(List.of(keys));
        for (String key : object.keySet()) if (!expected.contains(key)) throw new Invalid(path + ": unexpected key " + key);
        for (String key : expected) if (!object.containsKey(key)) throw new Invalid(path + ": missing key " + key);
    }

    /** Required keys must be present; any key outside required+optional is an error. */
    public static void keys(Map<String, Object> object, String path, Collection<String> required, Collection<String> optional) {
        for (String key : object.keySet())
            if (!required.contains(key) && !optional.contains(key)) throw new Invalid(path + ": unexpected key " + key);
        for (String key : required) if (!object.containsKey(key)) throw new Invalid(path + ": missing key " + key);
    }
}
