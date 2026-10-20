import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader and writer.
 *
 * The project has no JSON library, and the new commands receive their
 * input (keys, tokens, trapdoors, index entries) as a JSON file.
 *
 * Objects  -> LinkedHashMap<String, Object>
 * Arrays   -> ArrayList<Object>
 * Numbers  -> Long or Double
 */
public final class Json {

    private final String text;
    private int pos;

    private Json(String text) {
        this.text = text;
    }

    public static Object parse(String text) {

        Json parser = new Json(text);

        parser.skipWhitespace();

        Object value = parser.readValue();

        parser.skipWhitespace();

        if (parser.pos != text.length()) {
            throw new IllegalArgumentException(
                    "Unexpected data after JSON value");
        }

        return value;
    }

    private Object readValue() {

        if (pos >= text.length()) {
            throw new IllegalArgumentException(
                    "Unexpected end of JSON");
        }

        char c = text.charAt(pos);

        if (c == '{') return readObject();
        if (c == '[') return readArray();
        if (c == '"') return readString();

        if (text.startsWith("true", pos)) {
            pos += 4;
            return Boolean.TRUE;
        }

        if (text.startsWith("false", pos)) {
            pos += 5;
            return Boolean.FALSE;
        }

        if (text.startsWith("null", pos)) {
            pos += 4;
            return null;
        }

        return readNumber();
    }

    private Map<String, Object> readObject() {

        Map<String, Object> result = new LinkedHashMap<>();

        pos++; // {

        skipWhitespace();

        if (peek() == '}') {
            pos++;
            return result;
        }

        while (true) {

            skipWhitespace();

            String key = readString();

            skipWhitespace();
            expect(':');
            skipWhitespace();

            result.put(key, readValue());

            skipWhitespace();

            char c = next();

            if (c == '}') return result;

            if (c != ',') {
                throw new IllegalArgumentException(
                        "Expected ',' or '}' in JSON object");
            }
        }
    }

    private List<Object> readArray() {

        List<Object> result = new ArrayList<>();

        pos++; // [

        skipWhitespace();

        if (peek() == ']') {
            pos++;
            return result;
        }

        while (true) {

            skipWhitespace();

            result.add(readValue());

            skipWhitespace();

            char c = next();

            if (c == ']') return result;

            if (c != ',') {
                throw new IllegalArgumentException(
                        "Expected ',' or ']' in JSON array");
            }
        }
    }

    private String readString() {

        expect('"');

        StringBuilder out = new StringBuilder();

        while (true) {

            char c = next();

            if (c == '"') return out.toString();

            if (c != '\\') {
                out.append(c);
                continue;
            }

            char escaped = next();

            switch (escaped) {
                case '"':  out.append('"');  break;
                case '\\': out.append('\\'); break;
                case '/':  out.append('/');  break;
                case 'b':  out.append('\b'); break;
                case 'f':  out.append('\f'); break;
                case 'n':  out.append('\n'); break;
                case 'r':  out.append('\r'); break;
                case 't':  out.append('\t'); break;
                case 'u':
                    if (pos + 4 > text.length()) {
                        throw new IllegalArgumentException(
                                "Bad unicode escape");
                    }
                    out.append((char) Integer.parseInt(
                            text.substring(pos, pos + 4), 16));
                    pos += 4;
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Bad escape in JSON string");
            }
        }
    }

    private Object readNumber() {

        int start = pos;

        while (pos < text.length()
                && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) {
            pos++;
        }

        String number = text.substring(start, pos);

        if (number.isEmpty()) {
            throw new IllegalArgumentException(
                    "Unexpected character in JSON at " + start);
        }

        if (number.contains(".")
                || number.contains("e")
                || number.contains("E")) {
            return Double.parseDouble(number);
        }

        return Long.parseLong(number);
    }

    private void skipWhitespace() {
        while (pos < text.length()
                && Character.isWhitespace(text.charAt(pos))) {
            pos++;
        }
    }

    private char peek() {
        if (pos >= text.length()) {
            throw new IllegalArgumentException(
                    "Unexpected end of JSON");
        }
        return text.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char expected) {
        if (next() != expected) {
            throw new IllegalArgumentException(
                    "Expected '" + expected + "' in JSON");
        }
    }

    // ------------------------------------------------
    // WRITER
    // ------------------------------------------------

    public static String write(Object value) {

        StringBuilder out = new StringBuilder();

        writeValue(out, value);

        return out.toString();
    }

    private static void writeValue(StringBuilder out, Object value) {

        if (value == null) {
            out.append("null");
        } else if (value instanceof Map) {

            out.append('{');

            boolean first = true;

            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {

                if (!first) out.append(',');

                first = false;

                writeString(out, String.valueOf(entry.getKey()));
                out.append(':');
                writeValue(out, entry.getValue());
            }

            out.append('}');

        } else if (value instanceof Iterable) {

            out.append('[');

            boolean first = true;

            for (Object item : (Iterable<?>) value) {

                if (!first) out.append(',');

                first = false;

                writeValue(out, item);
            }

            out.append(']');

        } else if (value instanceof Number
                || value instanceof Boolean) {
            out.append(value);
        } else {
            writeString(out, value.toString());
        }
    }

    private static void writeString(StringBuilder out, String value) {

        out.append('"');

        for (int i = 0; i < value.length(); i++) {

            char c = value.charAt(i);

            switch (c) {
                case '"':  out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n");  break;
                case '\r': out.append("\\r");  break;
                case '\t': out.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }

        out.append('"');
    }
}
