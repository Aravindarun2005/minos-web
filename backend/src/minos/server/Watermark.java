package minos.server;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Leak tracing for text documents (project extension, not part of Minos).
 *
 * Every copy of a text document given to a user (download or browser view)
 * carries a hidden fingerprint at the end of every non-empty line: a run of
 * 56 spaces and tabs (space = 0, tab = 1). Editors such as Windows Notepad
 * draw spaces and tabs as nothing, so the copy looks exactly like the
 * original. The 56 bits are
 *
 *     copyId (4 random bytes)  ||  tag (first 3 bytes of HMAC-SHA256(key, copyId))
 *
 * The copy id is random, so reading it reveals nothing about the user; the
 * Minos Server keeps the table copyId -> (user, document, version, time).
 * The tag is made with a key known only to the Minos Server, so a mark
 * cannot be changed or invented to blame another user: such a mark fails
 * verification and is reported as invalid.
 *
 * Earlier versions used invisible Unicode characters (zero-width spaces,
 * then variation selectors). Windows Notepad draws those as marks or boxes,
 * so they are no longer written, but they are still read and removed.
 *
 * Spaces and tabs do not appear in screenshots or printouts, and some apps
 * remove them when text is pasted; those cases are traced by the visible
 * per-copy wording differences (TextVariation).
 */
public final class Watermark {

    /** First variation selector used (VS17); values 0..15 map to U+E0100..U+E010F. */
    static final int VS_BASE = 0xE0100;

    // version 1 characters (read and removed only)
    static final char START = '\u2060';
    static final char ZERO = '\u200B';
    static final char ONE = '\u200C';
    static final char END = '\u200D';

    static final int ID_BYTES = 4;
    static final int TAG_BYTES = 3;
    static final int PAYLOAD_BITS = (ID_BYTES + TAG_BYTES) * 8;   // 56 spaces and tabs

    // older formats (read and removed only)
    static final int OLD_ID_BYTES = 6;
    static final int OLD_TAG_BYTES = 4;
    static final int OLD_PAYLOAD_BITS = (OLD_ID_BYTES + OLD_TAG_BYTES) * 8;
    static final int MARK_SYMBOLS = OLD_PAYLOAD_BITS / 4;

    private Watermark() {
    }

    static boolean isSelector(int cp) {
        return cp >= VS_BASE && cp < VS_BASE + 16;
    }

    static boolean isLegacy(int cp) {
        return cp == START || cp == ZERO || cp == ONE || cp == END;
    }

    // ------------------------------------------------------------------
    // Building one mark
    // ------------------------------------------------------------------

    static byte[] tag(byte[] key, byte[] copyId) {
        return tag(key, copyId, TAG_BYTES);
    }

    static byte[] tag(byte[] key, byte[] copyId, int tagBytes) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update("minos-watermark/v1".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] full = mac.doFinal(copyId);
            byte[] out = new byte[tagBytes];
            for (int i = 0; i < tagBytes; i++) {
                out[i] = full[i];
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** The hidden mark for one copy id: 56 spaces and tabs. */
    static String mark(byte[] key, byte[] copyId) {
        byte[] t = tag(key, copyId);
        byte[] payload = new byte[ID_BYTES + TAG_BYTES];
        System.arraycopy(copyId, 0, payload, 0, ID_BYTES);
        System.arraycopy(t, 0, payload, ID_BYTES, TAG_BYTES);
        StringBuilder sb = new StringBuilder(PAYLOAD_BITS);
        for (byte b : payload) {
            for (int bit = 7; bit >= 0; bit--) {
                sb.append(((b >> bit) & 1) == 1 ? '\t' : ' ');
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Embedding: one complete mark after the last character of every non-empty line
    // ------------------------------------------------------------------

    public static String embed(String text, byte[] key, byte[] copyId) {
        String clean = strip(text);
        String m = mark(key, copyId);
        StringBuilder out = new StringBuilder(clean.length() + 128);
        StringBuilder line = new StringBuilder();
        int i = 0;
        while (i < clean.length()) {
            char ch = clean.charAt(i);
            if (ch == '\r' || ch == '\n') {
                appendLine(out, line, m);
                out.append(ch);
                if (ch == '\r' && i + 1 < clean.length() && clean.charAt(i + 1) == '\n') {
                    out.append('\n');
                    i = i + 1;
                }
                line.setLength(0);
            } else {
                line.append(ch);
            }
            i = i + 1;
        }
        appendLine(out, line, m);
        return out.toString();
    }

    private static void appendLine(StringBuilder out, StringBuilder line, String mark) {
        // the line's own trailing spaces are dropped, so the mark is the whole trailing run
        int last = line.length();
        while (last > 0 && (line.charAt(last - 1) == ' ' || line.charAt(last - 1) == '\t')) last--;
        boolean hasText = false;
        for (int k = 0; k < last; k++) {
            if (!Character.isWhitespace(line.charAt(k))) hasText = true;
        }
        out.append(line, 0, hasText ? last : line.length());
        if (hasText) out.append(mark);
    }

    /** Length of the run of spaces and tabs that ends at `end` (exclusive). */
    private static int trailingRun(String text, int end) {
        int i = end;
        while (i > 0 && (text.charAt(i - 1) == ' ' || text.charAt(i - 1) == '\t')) i--;
        return end - i;
    }

    /** True when the spaces and tabs before `end` form a whitespace mark. */
    private static boolean isWhitespaceMark(String text, int end) {
        int run = trailingRun(text, end);
        if (run != PAYLOAD_BITS) return false;
        return text.substring(end - run, end).indexOf('\t') >= 0;   // a mark always has some tabs
    }

    /** Offsets where lines end (before \r, \n or the end of the text). */
    private static List<Integer> lineEnds(String text) {
        List<Integer> ends = new ArrayList<>();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\n' || (c == '\r' && (i + 1 >= text.length() || text.charAt(i + 1) != '\n'))) {
                ends.add(i > 0 && c == '\n' && text.charAt(i - 1) == '\r' ? i - 1 : i);
            }
        }
        ends.add(text.length());
        return ends;
    }

    /** Removes every watermark (used before storing edits and uploads, and before matching wording). */
    public static String strip(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            if (!isSelector(cp) && !isLegacy(cp)) out.appendCodePoint(cp);
            i += Character.charCount(cp);
        }
        String noChars = out.toString();
        List<Integer> ends = lineEnds(noChars);
        StringBuilder sb = new StringBuilder(noChars.length());
        int pos = 0;
        for (int end : ends) {
            if (end < pos) continue;
            if (isWhitespaceMark(noChars, end)) {
                sb.append(noChars, pos, end - PAYLOAD_BITS);
            } else {
                sb.append(noChars, pos, end);
            }
            pos = end;
        }
        sb.append(noChars, pos, noChars.length());
        return sb.toString();
    }

    /** True when the text contains any watermark. */
    public static boolean containsMarks(String text) {
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            if (isSelector(cp) || isLegacy(cp)) return true;
            i += Character.charCount(cp);
        }
        for (int end : lineEnds(text)) {
            if (isWhitespaceMark(text, end)) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Extraction
    // ------------------------------------------------------------------

    /** Result of reading the marks of a suspected leaked text. */
    public static final class Found {
        /** copy id (hex) -> number of lines carrying a valid mark for it */
        public final Map<String, Integer> valid = new LinkedHashMap<>();
        /** marks that were complete but failed the HMAC check (altered or forged) */
        public int invalid;
        /** watermark characters that did not form a complete mark */
        public boolean fragments;
    }

    public static Found extract(String text, byte[] key) {
        Found f = new Found();
        // current version: 56 trailing spaces and tabs
        for (int end : lineEnds(text)) {
            int run = trailingRun(text, end);
            if (run == 0) continue;
            if (isWhitespaceMark(text, end)) {
                byte[] payload = new byte[ID_BYTES + TAG_BYTES];
                int from = end - PAYLOAD_BITS;
                for (int b = 0; b < payload.length; b++) {
                    int v = 0;
                    for (int k = 0; k < 8; k++) v = (v << 1) | (text.charAt(from + b * 8 + k) == '\t' ? 1 : 0);
                    payload[b] = (byte) v;
                }
                check(f, key, payload, ID_BYTES, TAG_BYTES);
            } else if (run > 8 && text.substring(end - run, end).indexOf('\t') >= 0) {
                f.fragments = true;   // a damaged mark
            }
        }
        // older version: runs of variation selectors
        int i = 0;
        while (i < text.length()) {
            int cp = text.codePointAt(i);
            if (!isSelector(cp)) {
                i += Character.charCount(cp);
                continue;
            }
            List<Integer> run = new ArrayList<>();
            while (i < text.length() && isSelector(text.codePointAt(i))) {
                run.add(text.codePointAt(i) - VS_BASE);
                i += Character.charCount(text.codePointAt(i));
            }
            if (run.size() != MARK_SYMBOLS) {
                f.fragments = true;
                continue;
            }
            byte[] payload = new byte[OLD_ID_BYTES + OLD_TAG_BYTES];
            for (int b = 0; b < payload.length; b++) {
                payload[b] = (byte) ((run.get(2 * b) << 4) | run.get(2 * b + 1));
            }
            check(f, key, payload, OLD_ID_BYTES, OLD_TAG_BYTES);
        }
        // oldest version: START bits END (zero-width characters)
        i = 0;
        while (i < text.length()) {
            char ch = text.charAt(i);
            if (ch == START) {
                int j = i + 1;
                StringBuilder bits = new StringBuilder();
                while (j < text.length() && (text.charAt(j) == ZERO || text.charAt(j) == ONE)) {
                    bits.append(text.charAt(j) == ONE ? '1' : '0');
                    j = j + 1;
                }
                boolean closed = j < text.length() && text.charAt(j) == END;
                if (closed && bits.length() == OLD_PAYLOAD_BITS) {
                    byte[] payload = new byte[OLD_ID_BYTES + OLD_TAG_BYTES];
                    for (int b = 0; b < payload.length; b++) {
                        int v = 0;
                        for (int k = 0; k < 8; k++) {
                            v = (v << 1) | (bits.charAt(b * 8 + k) - '0');
                        }
                        payload[b] = (byte) v;
                    }
                    check(f, key, payload, OLD_ID_BYTES, OLD_TAG_BYTES);
                    i = j + 1;
                    continue;
                }
                f.fragments = true;
                i = j;
                continue;
            }
            if (ch == ZERO || ch == ONE || ch == END) {
                f.fragments = true;
            }
            i = i + 1;
        }
        return f;
    }

    private static void check(Found f, byte[] key, byte[] payload, int idBytes, int tagBytes) {
        byte[] copyId = new byte[idBytes];
        byte[] givenTag = new byte[tagBytes];
        System.arraycopy(payload, 0, copyId, 0, idBytes);
        System.arraycopy(payload, idBytes, givenTag, 0, tagBytes);
        if (java.security.MessageDigest.isEqual(givenTag, tag(key, copyId, tagBytes))) {
            String hex = hex(copyId);
            Integer n = f.valid.get(hex);
            f.valid.put(hex, n == null ? 1 : n + 1);
        } else {
            f.invalid = f.invalid + 1;
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    public static String hex(byte[] b) {
        char[] digits = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            sb.append(digits[(b[i] >> 4) & 0xF]).append(digits[b[i] & 0xF]);
        }
        return sb.toString();
    }
}
