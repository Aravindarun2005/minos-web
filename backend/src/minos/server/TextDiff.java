package minos.server;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Line-by-line comparison of two versions of a text document, used by the
 * owner to review a proposed change (maker-checker).
 *
 * The comparison is the classic Longest Common Subsequence (LCS) method:
 *
 *   1. Split both texts into lines a[0..n-1] and b[0..m-1].
 *   2. Fill a table L where L[i][j] is the length of the longest common
 *      subsequence of a[i..n-1] and b[j..m-1]:
 *          L[i][j] = L[i+1][j+1] + 1               if a[i] equals b[j]
 *          L[i][j] = max(L[i+1][j], L[i][j+1])     otherwise
 *   3. Walk from (0,0): equal lines are "same", otherwise take the step
 *      that keeps the longer common subsequence and report the skipped
 *      line as "removed" (from a) or "added" (from b).
 */
public final class TextDiff {

    /** Above this many table cells the texts are compared line by line in order. */
    private static final long MAX_TABLE_CELLS = 4_000_000L;

    private TextDiff() {
    }

    // ------------------------------------------------------------------
    // Is the file text?
    // ------------------------------------------------------------------

    public static boolean isText(String contentType, String fileName, byte[] bytes) {
        boolean looksLikeText = false;
        String type = contentType == null ? "" : contentType.toLowerCase();
        if (type.startsWith("text/")) {
            looksLikeText = true;
        }
        if (type.equals("application/json") || type.equals("application/xml")
                || type.equals("application/csv") || type.equals("application/javascript")) {
            looksLikeText = true;
        }
        String name = fileName == null ? "" : fileName.toLowerCase();
        String[] textEndings = {".txt", ".csv", ".md", ".json", ".xml", ".html", ".htm", ".log", ".java",
                ".js", ".css", ".py", ".sql", ".yaml", ".yml", ".ini", ".properties"};
        for (int i = 0; i < textEndings.length; i++) {
            if (name.endsWith(textEndings[i])) {
                looksLikeText = true;
            }
        }
        if (!looksLikeText) {
            return false;
        }
        // The bytes must also be valid UTF-8 and contain no NUL characters.
        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == 0) {
                return false;
            }
        }
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
        decoder.onMalformedInput(CodingErrorAction.REPORT);
        decoder.onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            decoder.decode(ByteBuffer.wrap(bytes));
            return true;
        } catch (CharacterCodingException e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Split a text into lines (\n, \r\n or \r)
    // ------------------------------------------------------------------

    static List<String> lines(String text) {
        List<String> out = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int i = 0;
        while (i < text.length()) {
            char ch = text.charAt(i);
            if (ch == '\r') {
                out.add(current.toString());
                current.setLength(0);
                if (i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    i = i + 1;
                }
            } else if (ch == '\n') {
                out.add(current.toString());
                current.setLength(0);
            } else {
                current.append(ch);
            }
            i = i + 1;
        }
        if (current.length() > 0) {
            out.add(current.toString());
        }
        return out;
    }

    // ------------------------------------------------------------------
    // LCS line diff
    // ------------------------------------------------------------------

    /** Returns a list of {type: same|added|removed, text, oldLine, newLine}. */
    public static List<Map<String, Object>> diff(String before, String after) {
        List<String> a = lines(before);
        List<String> b = lines(after);
        int n = a.size();
        int m = b.size();
        List<Map<String, Object>> out = new ArrayList<>();

        if ((long) (n + 1) * (long) (m + 1) > MAX_TABLE_CELLS) {
            // Very large files: compare position by position.
            int count = n > m ? n : m;
            for (int i = 0; i < count; i++) {
                String oldLine = i < n ? a.get(i) : null;
                String newLine = i < m ? b.get(i) : null;
                if (oldLine != null && newLine != null && oldLine.equals(newLine)) {
                    out.add(line("same", oldLine, i + 1, i + 1));
                } else {
                    if (oldLine != null) {
                        out.add(line("removed", oldLine, i + 1, 0));
                    }
                    if (newLine != null) {
                        out.add(line("added", newLine, 0, i + 1));
                    }
                }
            }
            return out;
        }

        // Step 2: fill the LCS table from the bottom-right corner.
        int[][] L = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                if (a.get(i).equals(b.get(j))) {
                    L[i][j] = L[i + 1][j + 1] + 1;
                } else {
                    int down = L[i + 1][j];
                    int right = L[i][j + 1];
                    if (down >= right) {
                        L[i][j] = down;
                    } else {
                        L[i][j] = right;
                    }
                }
            }
        }

        // Step 3: walk the table.
        int i = 0;
        int j = 0;
        while (i < n && j < m) {
            if (a.get(i).equals(b.get(j))) {
                out.add(line("same", a.get(i), i + 1, j + 1));
                i = i + 1;
                j = j + 1;
            } else if (L[i + 1][j] >= L[i][j + 1]) {
                out.add(line("removed", a.get(i), i + 1, 0));
                i = i + 1;
            } else {
                out.add(line("added", b.get(j), 0, j + 1));
                j = j + 1;
            }
        }
        while (i < n) {
            out.add(line("removed", a.get(i), i + 1, 0));
            i = i + 1;
        }
        while (j < m) {
            out.add(line("added", b.get(j), 0, j + 1));
            j = j + 1;
        }
        return out;
    }

    private static Map<String, Object> line(String type, String text, int oldLine, int newLine) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("text", text);
        m.put("oldLine", oldLine);
        m.put("newLine", newLine);
        return m;
    }

    // ------------------------------------------------------------------
    // One-line summary for logs: "2 lines added, 1 line removed"
    // ------------------------------------------------------------------

    public static String summary(byte[] before, byte[] after, String contentType, String fileName) {
        if (isText(contentType, fileName, before) && isText(contentType, fileName, after)) {
            List<Map<String, Object>> d = diff(new String(before, StandardCharsets.UTF_8),
                    new String(after, StandardCharsets.UTF_8));
            int added = 0;
            int removed = 0;
            for (int i = 0; i < d.size(); i++) {
                Object type = d.get(i).get("type");
                if ("added".equals(type)) {
                    added = added + 1;
                }
                if ("removed".equals(type)) {
                    removed = removed + 1;
                }
            }
            return added + (added == 1 ? " line added, " : " lines added, ")
                    + removed + (removed == 1 ? " line removed" : " lines removed");
        }
        return "File replaced (" + size(before.length) + " -> " + size(after.length) + ")";
    }

    private static String size(int bytes) {
        if (bytes < 1024) {
            return bytes + " bytes";
        }
        if (bytes < 1024 * 1024) {
            return (bytes / 1024) + " KB";
        }
        return (bytes / (1024 * 1024)) + " MB";
    }
}
