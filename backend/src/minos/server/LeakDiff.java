package minos.server;

import minos.common.Http;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shows how a leaked text differs from the owner's original (project
 * extension, part of leak tracing), in the same style as the review of a
 * suggested change: removed lines in red, added lines in green.
 *
 * Lines are compared by their canonical form (TextVariation.canonicalText):
 * the per-copy wording differences (2000 / 2,000, cannot / can't,
 * Re: / RE: ...), the hidden code, capital letters, spacing and punctuation
 * are ignored, so only real edits are shown. When text recognition
 * (Google Lens) joined the lines of a screenshot into one long line, the
 * words are first put back onto the original's lines.
 *
 * Long files are handled by pairing equal starts and ends first, then
 * comparing line by line (longest common subsequence) and, for very long
 * parts, splitting at lines that occur only once in both texts.
 */
public final class LeakDiff {

    /** Largest longest-common-subsequence table built in one go (cells). */
    static final long MAX_CELLS = 8_000_000L;
    /** Unchanged lines kept around each change; longer unchanged runs are folded. */
    static final int CONTEXT_LINES = 2;
    /** Removed runs longer than this are folded (an excerpt leaves most of the file out). */
    static final int MAX_REMOVED_SHOWN = 6;
    static final int MAX_ROWS = 600;

    private LeakDiff() {
    }

    // ------------------------------------------------------------------
    // Generic alignment of two key lists
    // ------------------------------------------------------------------

    /** Pairs (index in a, index in b) of equal keys, in order, as many as practical. */
    static List<int[]> align(List<String> a, List<String> b) {
        List<int[]> pairs = new ArrayList<>();
        align(a, b, 0, a.size(), 0, b.size(), pairs, 0);
        return pairs;
    }

    private static void align(List<String> a, List<String> b, int ai, int aj, int bi, int bj, List<int[]> pairs, int depth) {
        List<int[]> tail = new ArrayList<>();
        while (ai < aj && bi < bj && a.get(ai).equals(b.get(bi))) pairs.add(new int[]{ai++, bi++});
        while (ai < aj && bi < bj && a.get(aj - 1).equals(b.get(bj - 1))) tail.add(0, new int[]{--aj, --bj});
        int n = aj - ai, m = bj - bi;
        if (n > 0 && m > 0) {
            if ((long) n * m <= MAX_CELLS) {
                lcs(a, b, ai, aj, bi, bj, pairs);
            } else if (depth < 8) {
                byUniqueKeys(a, b, ai, aj, bi, bj, pairs, depth);
            }
        }
        pairs.addAll(tail);
    }

    private static void lcs(List<String> a, List<String> b, int ai, int aj, int bi, int bj, List<int[]> pairs) {
        int n = aj - ai, m = bj - bi;
        int[][] L = new int[n + 1][m + 1];
        for (int i = n - 1; i >= 0; i--) {
            for (int j = m - 1; j >= 0; j--) {
                L[i][j] = a.get(ai + i).equals(b.get(bi + j)) ? L[i + 1][j + 1] + 1 : Math.max(L[i + 1][j], L[i][j + 1]);
            }
        }
        int i = 0, j = 0;
        while (i < n && j < m) {
            if (a.get(ai + i).equals(b.get(bi + j))) {
                pairs.add(new int[]{ai + i, bi + j});
                i++;
                j++;
            } else if (L[i + 1][j] >= L[i][j + 1]) {
                i++;
            } else {
                j++;
            }
        }
    }

    /** Splits at keys that occur exactly once in both ranges, in the same order ("patience" alignment). */
    private static void byUniqueKeys(List<String> a, List<String> b, int ai, int aj, int bi, int bj, List<int[]> pairs, int depth) {
        Map<String, int[]> seen = new HashMap<>();   // key -> {count in a, pos in a, count in b, pos in b}
        for (int k = ai; k < aj; k++) {
            int[] e = seen.computeIfAbsent(a.get(k), x -> new int[4]);
            e[0]++;
            e[1] = k;
        }
        for (int k = bi; k < bj; k++) {
            int[] e = seen.get(b.get(k));
            if (e != null) {
                e[2]++;
                e[3] = k;
            }
        }
        List<int[]> cand = new ArrayList<>();
        for (int[] e : seen.values()) if (e[0] == 1 && e[2] == 1) cand.add(new int[]{e[1], e[3]});
        cand.sort((x, y) -> Integer.compare(x[0], y[0]));
        int c = cand.size();
        int[] tails = new int[c], prev = new int[c];
        int len = 0;
        for (int k = 0; k < c; k++) {
            int lo = 0, hi = len;
            while (lo < hi) {
                int mid = (lo + hi) >>> 1;
                if (cand.get(tails[mid])[1] < cand.get(k)[1]) lo = mid + 1; else hi = mid;
            }
            prev[k] = lo > 0 ? tails[lo - 1] : -1;
            tails[lo] = k;
            if (lo == len) len++;
        }
        if (len == 0) return;   // nothing in common that can be found cheaply: all different
        int[] chain = new int[len];
        for (int k = len - 1, t = tails[len - 1]; k >= 0; k--, t = prev[t]) chain[k] = t;
        int ga = ai, gb = bi;
        for (int t : chain) {
            int[] anchor = cand.get(t);
            align(a, b, ga, anchor[0], gb, anchor[1], pairs, depth + 1);
            pairs.add(new int[]{anchor[0], anchor[1]});
            ga = anchor[0] + 1;
            gb = anchor[1] + 1;
        }
        align(a, b, ga, aj, gb, bj, pairs, depth + 1);
    }

    // ------------------------------------------------------------------
    // Words (used to put joined lines back on their lines, and for misreads)
    // ------------------------------------------------------------------

    /** Lower-case letters and digits of a text, one entry per word. */
    static List<String> wordKeys(String text) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            if (!Character.isLetterOrDigit(text.charAt(i))) {
                i++;
                continue;
            }
            int j = i;
            while (j < text.length() && Character.isLetterOrDigit(text.charAt(j))) j++;
            out.add(text.substring(i, j).toLowerCase(java.util.Locale.ROOT));
            i = j;
        }
        return out;
    }

    /**
     * True when two lines differ only like a text-recognition slip: the same
     * number of words, each differing in at most one letter (never a digit).
     */
    static boolean possibleMisread(String x, String y) {
        List<String> a = wordKeys(x), b = wordKeys(y);
        if (a.size() != b.size() || a.isEmpty()) return false;
        int slips = 0;
        for (int k = 0; k < a.size(); k++) {
            String p = a.get(k), q = b.get(k);
            if (p.equals(q)) continue;
            if (p.length() != q.length() || p.length() < 2) return false;
            int diff = 0;
            for (int c = 0; c < p.length(); c++) {
                if (p.charAt(c) != q.charAt(c)) {
                    if (Character.isDigit(p.charAt(c)) || Character.isDigit(q.charAt(c))) return false;
                    diff++;
                }
            }
            if (diff > 1) return false;
            slips++;
        }
        return slips > 0;
    }

    /** Lines of a text (without line breaks); a final empty line is dropped. */
    static List<String> lines(String text) {
        List<String> out = new ArrayList<>(java.util.Arrays.asList(text.replace("\r\n", "\n").replace('\r', '\n').split("\n", -1)));
        if (!out.isEmpty() && out.get(out.size() - 1).isEmpty()) out.remove(out.size() - 1);
        return out;
    }

    /**
     * Google Lens and similar tools often return a whole screenshot as one long
     * line. Such text is cut back into the original's lines: each leaked word
     * is placed on the line of the original word it matches.
     */
    static List<String> reflow(List<String> original, String leaked) {
        List<String> origKeys = new ArrayList<>();
        List<Integer> origLine = new ArrayList<>();
        for (int l = 0; l < original.size(); l++) {
            for (String w : wordKeys(original.get(l))) {
                origKeys.add(w);
                origLine.add(l);
            }
        }
        // the leaked text as chunks separated by spaces ("a.b@c" is one chunk of several words)
        List<String> chunkText = new ArrayList<>();
        List<String> flat = new ArrayList<>();
        List<Integer> chunkOf = new ArrayList<>();
        int i = 0;
        while (i < leaked.length()) {
            if (Character.isWhitespace(leaked.charAt(i))) {
                i++;
                continue;
            }
            int j = i;
            while (j < leaked.length() && !Character.isWhitespace(leaked.charAt(j))) j++;
            String surface = leaked.substring(i, j);
            List<String> keys = wordKeys(surface);
            if (keys.isEmpty() && !chunkText.isEmpty()) {
                chunkText.set(chunkText.size() - 1, chunkText.get(chunkText.size() - 1) + " " + surface);
            } else {
                chunkText.add(surface);
                for (String k : keys) {
                    flat.add(k);
                    chunkOf.add(chunkText.size() - 1);
                }
            }
            i = j;
        }
        List<int[]> pairs = align(origKeys, flat);
        int[] lineOfChunk = new int[chunkText.size()];
        java.util.Arrays.fill(lineOfChunk, -1);
        for (int[] p : pairs) {
            int c = chunkOf.get(p[1]);
            if (lineOfChunk[c] < 0) lineOfChunk[c] = origLine.get(p[0]);
        }
        // unmatched chunks stay with the chunk before them (or after, at the start)
        int last = -1;
        for (int c = 0; c < lineOfChunk.length; c++) {
            if (lineOfChunk[c] >= 0) last = lineOfChunk[c];
            else if (last >= 0) lineOfChunk[c] = last;
        }
        int next = 0;
        for (int c = lineOfChunk.length - 1; c >= 0; c--) {
            if (lineOfChunk[c] >= 0) next = lineOfChunk[c];
            else lineOfChunk[c] = next;
        }
        List<String> out = new ArrayList<>();
        int current = Integer.MIN_VALUE;
        StringBuilder sb = new StringBuilder();
        for (int c = 0; c < chunkText.size(); c++) {
            if (lineOfChunk[c] != current && sb.length() > 0) {
                out.add(sb.toString());
                sb.setLength(0);
            }
            current = lineOfChunk[c];
            if (sb.length() > 0) sb.append(' ');
            sb.append(chunkText.get(c));
        }
        if (sb.length() > 0) out.add(sb.toString());
        return out;
    }

    // ------------------------------------------------------------------
    // The comparison
    // ------------------------------------------------------------------

    /** Canonical key of one line: ignores per-copy variations, case, spacing and punctuation. */
    static String key(String line) {
        return TextVariation.canonicalText(line);
    }

    /**
     * Compares a leaked text with the original. Returns rows for a red/green
     * view: {type: same | removed | added | misread | fold, text, line, count}.
     */
    public static Map<String, Object> compare(String original, String leaked) {
        String clean = TextVariation.normalizeOcr(Watermark.strip(leaked));
        List<String> a = lines(original);
        List<String> b = new ArrayList<>();
        for (String l : lines(clean)) b.add(l.replaceAll("[ \t]+$", ""));
        if (a.isEmpty() || wordKeys(clean).isEmpty()) {
            return Http.map("compared", false, "reason", "No words to compare.");
        }

        // joined lines (text recognition): put the words back on the original's lines
        boolean reflowed = false;
        int nonBlankA = 0;
        for (String l : a) if (!wordKeys(l).isEmpty()) nonBlankA++;
        double avgPerLine = wordKeys(original).size() / (double) Math.max(1, nonBlankA);
        int leakWords = wordKeys(clean).size(), nonBlankB = 0, longest = 0;
        for (String l : b) {
            int w = wordKeys(l).size();
            if (w > 0) nonBlankB++;
            longest = Math.max(longest, w);
        }
        double expectedLines = leakWords / Math.max(1.0, avgPerLine);
        if (longest > 3 * avgPerLine + 10 && nonBlankB * 2 < expectedLines) {
            b = reflow(a, clean);
            reflowed = true;
        }

        List<String> ka = new ArrayList<>(), kb = new ArrayList<>();
        for (String l : a) ka.add(key(l));
        for (String l : b) kb.add(key(l));
        List<int[]> pairs = align(ka, kb);
        List<int[]> walk = new ArrayList<>(pairs);
        walk.add(new int[]{a.size(), b.size()});   // end marker

        // rows in order: {type, text, original line number (0 when added), original text for misreads}
        List<Object[]> raw = new ArrayList<>();
        int i = 0, j = 0;
        for (int[] p : walk) {
            List<String> rem = new ArrayList<>(), add = new ArrayList<>();
            int remFrom = i;
            while (i < p[0]) rem.add(a.get(i++));
            while (j < p[1]) add.add(b.get(j++));
            // a removed line facing an added line that differs by one misread letter only
            int k = 0;
            for (; k < rem.size() && k < add.size(); k++) {
                if (possibleMisread(rem.get(k), add.get(k))) {
                    raw.add(new Object[]{"misread", add.get(k), remFrom + k + 1, rem.get(k)});
                } else {
                    break;
                }
            }
            for (int r = k; r < rem.size(); r++) raw.add(new Object[]{"removed", rem.get(r), remFrom + r + 1, null});
            for (int r = k; r < add.size(); r++) raw.add(new Object[]{"added", add.get(r), 0, null});
            if (p[0] < a.size() && p[1] < b.size()) {
                raw.add(new Object[]{"same", a.get(p[0]), p[0] + 1, null});
                i = p[0] + 1;
                j = p[1] + 1;
            }
        }

        // counts (blank lines are not counted)
        int removed = 0, added = 0, misread = 0, same = 0;
        for (Object[] r : raw) {
            boolean blank = wordKeys((String) r[1]).isEmpty();
            if (blank) continue;
            switch ((String) r[0]) {
                case "removed": removed++; break;
                case "added": added++; break;
                case "misread": misread++; break;
                default: same++;
            }
        }

        // fold long unchanged runs and long removed runs (rows stay readable for long files)
        int n = raw.size();
        boolean[] keep = new boolean[n];
        for (int r = 0; r < n; r++) {
            if (!raw.get(r)[0].equals("same")) {
                for (int c = Math.max(0, r - CONTEXT_LINES); c <= Math.min(n - 1, r + CONTEXT_LINES); c++) keep[c] = true;
            }
        }
        List<Object> rows = new ArrayList<>();
        int r = 0;
        while (r < n && rows.size() < MAX_ROWS) {
            String type = (String) raw.get(r)[0];
            if (type.equals("same") && !keep[r]) {
                int s = r;
                while (r < n && raw.get(r)[0].equals("same") && !keep[r]) r++;
                rows.add(Http.map("type", "fold", "what", "unchanged", "count", r - s,
                        "line", raw.get(s)[2], "toLine", raw.get(r - 1)[2]));
                continue;
            }
            if (type.equals("removed")) {
                int s = r;
                while (r < n && raw.get(r)[0].equals("removed")) r++;
                if (r - s > MAX_REMOVED_SHOWN) {
                    for (int c = s; c < s + 2; c++) rows.add(row(raw.get(c)));
                    rows.add(Http.map("type", "fold", "what", "removed", "count", r - s - 4,
                            "line", raw.get(s + 2)[2], "toLine", raw.get(r - 3)[2]));
                    for (int c = r - 2; c < r; c++) rows.add(row(raw.get(c)));
                } else {
                    for (int c = s; c < r; c++) rows.add(row(raw.get(c)));
                }
                continue;
            }
            rows.add(row(raw.get(r)));
            r++;
        }

        int nonBlankOriginal = Math.max(1, nonBlankA);
        return Http.map(
                "compared", true,
                "rows", rows,
                "originalLines", a.size(),
                "linesSame", same,
                "linesRemoved", removed,
                "linesAdded", added,
                "linesMisread", misread,
                "samePercent", Math.round(1000.0 * same / nonBlankOriginal) / 10.0,
                "reflowed", reflowed,
                "truncated", r < n);
    }

    private static Map<String, Object> row(Object[] r) {
        Map<String, Object> m = Http.map("type", r[0], "text", r[1], "line", r[2]);
        if (r[3] != null) m.put("original", r[3]);
        return m;
    }
}
