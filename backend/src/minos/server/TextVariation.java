package minos.server;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Per-copy visible text variations (project extension, "canary trap").
 *
 * A change point is a place in a text document where two forms mean the
 * same thing:
 *
 *     numbers      2000        <->  2,000
 *     dates        01-06-2024  <->  01/06/2024
 *     word forms   cannot      <->  can't,   colour <-> color,  ...
 *
 * Each downloaded or viewed copy gets its own random choice (one bit) at
 * every change point. The choices are visible in the text, so they are
 * still there in screenshots, printouts and copied lines. Given a few
 * leaked lines, locate() finds which change points they contain and
 * which form each one has; comparing that with the recorded choices of
 * every issued copy identifies the copy.
 *
 * The stored original is never changed; only copies handed out vary.
 */
public final class TextVariation {

    private TextVariation() {
    }

    // ------------------------------------------------------------------
    // Word pairs: both forms have the same meaning.
    // ------------------------------------------------------------------

    static final String[][] PAIRS = {
            {"cannot", "can't"}, {"do not", "don't"}, {"does not", "doesn't"}, {"did not", "didn't"},
            {"is not", "isn't"}, {"are not", "aren't"}, {"was not", "wasn't"}, {"will not", "won't"},
            {"would not", "wouldn't"}, {"should not", "shouldn't"}, {"could not", "couldn't"},
            {"have not", "haven't"}, {"has not", "hasn't"}, {"it is", "it's"}, {"I am", "I'm"},
            {"we will", "we'll"}, {"I will", "I'll"}, {"you will", "you'll"}, {"we are", "we're"},
            {"they are", "they're"}, {"let us", "let's"},
            {"please", "kindly"}, {"e-mail", "email"}, {"okay", "OK"}, {"towards", "toward"},
            {"amongst", "among"}, {"whilst", "while"}, {"approximately", "approx."},
            {"colour", "color"}, {"organisation", "organization"}, {"centre", "center"},
            {"behaviour", "behavior"}, {"favour", "favor"}, {"analyse", "analyze"},
            {"realise", "realize"}, {"recognise", "recognize"}, {"finalise", "finalize"},
            {"authorise", "authorize"}, {"percent", "per cent"},
            {"Mr.", "Mr"}, {"Mrs.", "Mrs"}, {"Dr.", "Dr"}
    };

    static final Pattern DATE = Pattern.compile("(?<![\\w/-])(\\d{1,2})([-/])(\\d{1,2})\\2(\\d{2,4})(?![\\w/-])");
    static final Pattern NUMBER = Pattern.compile("(?<![\\w.,/-])(\\d{1,3}(?:,\\d{3})+|\\d{4,7})(?![\\w,/-]|\\.\\d)");
    static final Pattern WORD = Pattern.compile("[A-Za-z0-9]+");
    static final Pattern[] PAIR_PATTERNS = new Pattern[PAIRS.length * 2];

    static {
        for (int i = 0; i < PAIRS.length; i++) {
            for (int f = 0; f < 2; f++) {
                String form = PAIRS[i][f];
                StringBuilder rx = new StringBuilder("(?<![A-Za-z'])");
                String[] parts = form.split(" ");
                for (int k = 0; k < parts.length; k++) {
                    if (k > 0) rx.append("\\s+");
                    rx.append(Pattern.quote(parts[k]).replace("'", "\\E['\u2019]\\Q"));
                }
                char last = form.charAt(form.length() - 1);
                rx.append(Character.isLetter(last) ? "(?![A-Za-z'])" : "(?![A-Za-z])");
                PAIR_PATTERNS[i * 2 + f] = Pattern.compile(rx.toString(), Pattern.CASE_INSENSITIVE);
            }
        }
    }

    // ------------------------------------------------------------------
    // More change points, so that short texts such as e-mails also differ
    // ------------------------------------------------------------------

    /**
     * Exact-case pairs. E-mail header names and MIME values are case-insensitive
     * by the standards (RFC 5322, RFC 2045), so both forms mean the same.
     */
    static final String[][] CASE_PAIRS = {
            {"Message-ID", "Message-Id"}, {"Mime-Version", "MIME-Version"}, {"Content-Type", "Content-type"},
            {"Content-Transfer-Encoding", "Content-transfer-encoding"}, {"us-ascii", "US-ASCII"},
            {"7bit", "7BIT"}, {"8bit", "8BIT"}, {"quoted-printable", "Quoted-Printable"},
            {"X-cc", "X-CC"}, {"X-bcc", "X-BCC"}, {"X-FileName", "X-Filename"}, {"X-Folder", "X-folder"},
            {"Re:", "RE:"}, {"Fw:", "FW:"}, {"Fwd:", "FWD:"}, {"cc:", "Cc:"}
    };
    static final Pattern[] CASE_PATTERNS = new Pattern[CASE_PAIRS.length * 2];

    static final String[] MONTHS = {"Jan", "January", "Feb", "February", "Mar", "March", "Apr", "April",
            "Jun", "June", "Jul", "July", "Aug", "August", "Sep", "September", "Oct", "October",
            "Nov", "November", "Dec", "December"};
    static final String[] DAYS = {"Mon", "Monday", "Tue", "Tuesday", "Wed", "Wednesday", "Thu", "Thursday",
            "Fri", "Friday", "Sat", "Saturday", "Sun", "Sunday"};
    /** Month names next to a day number: "5 Oct", "Oct 5", "October 5th". */
    static final Pattern MONTH = Pattern.compile("(?<=\\b\\d{1,2}(?:st|nd|rd|th)? )(" + alternation(MONTHS) + ")\\b"
            + "|\\b(" + alternation(MONTHS) + ")(?= \\d{1,2}\\b)");
    /** Day names followed by a comma or a number: "Thu, 5 Oct", "Monday 12". */
    static final Pattern DAY = Pattern.compile("\\b(" + alternation(DAYS) + ")(?=,| \\d)");
    /** Middle initial with or without a full stop: "Phillip K Allen" / "Phillip K. Allen". */
    static final Pattern INITIAL = Pattern.compile("(?<=\\b[A-Z][a-z]{1,20} )([B-HJ-Z])(\\.?)(?= [A-Z][a-z]+\\b)");
    /** Comma after a word that starts a sentence: "However, we" / "However we". */
    static final Pattern INTRO = Pattern.compile("(?m)(?:^|(?<=[.!?] )|(?<=[.!?]  ))(However|Also|So|Thanks|Therefore|Finally|"
            + "Meanwhile|Unfortunately|Additionally|Otherwise|Besides|Anyway|Instead|Hopefully|Fortunately|Again|Then)(,?)(?= [a-zA-Z])");
    /** Serial (Oxford) comma: "A, B and C" / "A, B, and C". */
    static final Pattern OXFORD = Pattern.compile("(?<=, )([A-Za-z]+)(,?)(?= (?:and|or) [A-Za-z])");
    /** Capital after a colon for common words: "Note: the" / "Note: The". */
    static final Pattern AFTER_COLON = Pattern.compile("(?<=[a-z]: )(the|this|that|these|those|we|our|all|it|please|"
            + "there|you|your|no|yes|a|an|in|on|for|as|if|my)\\b", Pattern.CASE_INSENSITIVE);
    /** "and" / "&" between two capitalised words: "Research and Development". */
    static final Pattern AMPERSAND = Pattern.compile("(?<=\\b[A-Z][a-z]{1,20} )(and|&)(?= [A-Z][a-z]+\\b)");
    /** "10%" / "10 percent". */
    static final Pattern PERCENT = Pattern.compile("(?<![\\w.])(\\d{1,3}(?:\\.\\d+)?)(%| percent)(?![\\w])");
    /** Full stop at the end of a short sentence line: "35 million is fine" / "35 million is fine." */
    static final Pattern LINE_END = Pattern.compile("(?m)^([^\\r\\n.!?:;]*?[A-Za-z]+ [A-Za-z0-9]+ )([A-Za-z]{2,})(\\.?)[ \\t]*\\r?$");
    /** An e-mail header line ("Name: value" at the start of the text). */
    static final Pattern HEADER_LINE = Pattern.compile("^[A-Za-z][A-Za-z0-9-]*:( .*)?$");

    static String alternation(String[] words) {
        StringBuilder sb = new StringBuilder();
        for (String w : words) {
            if (sb.length() > 0) sb.append('|');
            sb.append(w);
        }
        return sb.toString();
    }

    static {
        for (int i = 0; i < CASE_PAIRS.length; i++) {
            for (int f = 0; f < 2; f++) {
                CASE_PATTERNS[i * 2 + f] = Pattern.compile("(?<![A-Za-z0-9-])" + Pattern.quote(CASE_PAIRS[i][f])
                        + (CASE_PAIRS[i][f].endsWith(":") ? "" : "(?![A-Za-z0-9-])"));
            }
        }
    }

    /**
     * End of an e-mail header block (offset of the blank line after it), or 0
     * when the text does not start with at least three "Name: value" lines.
     * Inside the header block only changes that keep the data the same are
     * made (header-name case, middle initials); values such as dates, numbers
     * and addresses are never changed there.
     */
    static int headerEnd(String text) {
        int pos = 0, headers = 0;
        while (pos < text.length()) {
            int nl = text.indexOf('\n', pos);
            int end = nl < 0 ? text.length() : nl;
            String line = text.substring(pos, end).replace("\r", "");
            String trimmed = line.replaceAll("[ \t]+$", "");
            if (trimmed.isEmpty()) break;
            if (HEADER_LINE.matcher(trimmed).matches()) headers++;
            else if (!(line.startsWith(" ") || line.startsWith("\t")) || headers == 0) return headers >= 3 ? pos : 0;
            pos = nl < 0 ? text.length() : nl + 1;
        }
        return headers >= 3 ? pos : 0;
    }

    private static Token other(int start, int end, String surface, String canonical, int form, String alt) {
        Token t = new Token();
        t.kind = Token.OTHER_TOKEN;
        t.start = start;
        t.end = end;
        t.surface = surface;
        t.canonical = canonical;
        t.form = form;
        t.alt = alt;
        return t;
    }

    private static String otherName(String[] names, String found) {
        for (int i = 0; i < names.length; i += 2) {
            if (names[i].equals(found)) return names[i + 1];
            if (names[i + 1].equals(found)) return names[i];
        }
        return found;
    }

    private static int nameIndex(String[] names, String found) {
        for (int i = 0; i < names.length; i++) if (names[i].equals(found)) return i / 2;
        return -1;
    }

    /** Change points added for short texts (see the patterns above). */
    static void extraPoints(String text, int bodyFrom, List<Token> special) {
        Matcher m;
        for (int i = 0; i < CASE_PAIRS.length; i++) {
            for (int f = 0; f < 2; f++) {
                m = CASE_PATTERNS[i * 2 + f].matcher(text);
                while (m.find()) special.add(other(m.start(), m.end(), m.group(), "#c:" + i, f, CASE_PAIRS[i][1 - f]));
            }
        }
        m = INITIAL.matcher(text);
        while (m.find()) {
            boolean dot = !m.group(2).isEmpty();
            special.add(other(m.start(), m.end(), m.group(), "#i:" + m.group(1), dot ? 1 : 0, m.group(1) + (dot ? "" : ".")));
        }
        // the rest only in the body
        m = MONTH.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            String g = m.group();
            special.add(other(m.start(), m.end(), g, MONTHS[nameIndex(MONTHS, g) * 2].toLowerCase(Locale.ROOT), g.length() > 3 ? 1 : 0, otherName(MONTHS, g)));
        }
        m = DAY.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            String g = m.group();
            special.add(other(m.start(), m.end(), g, DAYS[nameIndex(DAYS, g) * 2].toLowerCase(Locale.ROOT), g.length() > 3 ? 1 : 0, otherName(DAYS, g)));
        }
        m = INTRO.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            boolean comma = !m.group(2).isEmpty();
            special.add(other(m.start(), m.end(), m.group(), "#in:" + m.group(1).toLowerCase(Locale.ROOT), comma ? 1 : 0,
                    m.group(1) + (comma ? "" : ",")));
        }
        m = OXFORD.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            boolean comma = !m.group(2).isEmpty();
            special.add(other(m.start(), m.end(), m.group(), "#ox:" + m.group(1).toLowerCase(Locale.ROOT), comma ? 1 : 0,
                    m.group(1) + (comma ? "" : ",")));
        }
        m = AFTER_COLON.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            String g = m.group();
            boolean cap = Character.isUpperCase(g.charAt(0));
            String alt = (cap ? Character.toLowerCase(g.charAt(0)) : Character.toUpperCase(g.charAt(0))) + g.substring(1);
            special.add(other(m.start(), m.end(), g, "#k:" + g.toLowerCase(Locale.ROOT), cap ? 1 : 0, alt));
        }
        m = AMPERSAND.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            boolean amp = m.group().equals("&");
            special.add(other(m.start(), m.end(), m.group(), "#amp", amp ? 1 : 0, amp ? "and" : "&"));
        }
        m = PERCENT.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            boolean sign = m.group(2).equals("%");
            special.add(other(m.start(), m.end(), m.group(), "#pc:" + m.group(1), sign ? 0 : 1,
                    m.group(1) + (sign ? " percent" : "%")));
        }
        m = LINE_END.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            boolean dot = !m.group(3).isEmpty();
            special.add(other(m.start(2), m.end(3), m.group(2) + m.group(3), "#e:" + m.group(2).toLowerCase(Locale.ROOT),
                    dot ? 1 : 0, m.group(2) + (dot ? "" : ".")));
        }
    }

    // ------------------------------------------------------------------
    // Tokens
    // ------------------------------------------------------------------

    /** One token of a text; change points have kind != WORD. */
    static final class Token {
        static final int WORD_TOKEN = 0, NUMBER_TOKEN = 1, DATE_TOKEN = 2, PAIR_TOKEN = 3, OTHER_TOKEN = 4;
        int kind;
        int start, end;      // offsets in the text
        String surface;      // exact text
        String canonical;    // form-independent value, used for matching
        int form;            // which of the two forms appears (0 or 1)
        int pair = -1;       // index into PAIRS for PAIR_TOKEN
        String alt;          // the other form (OTHER_TOKEN)
    }

    static boolean isYear(String digits) {
        if (digits.length() != 4) return false;
        int v = Integer.parseInt(digits);
        return v >= 1900 && v <= 2099;
    }

    static final java.util.Set<String> AMOUNT_BEFORE = new java.util.HashSet<>(java.util.Arrays.asList(
            "rs", "inr", "usd", "eur", "limit", "total", "amount", "salary", "pay", "paid", "cost", "costs",
            "price", "fee", "fees", "budget", "bonus", "balance", "sum", "only", "rupees", "allowance"));
    static final java.util.Set<String> AMOUNT_AFTER = new java.util.HashSet<>(java.util.Arrays.asList(
            "per", "rupees", "rs", "inr", "usd", "dollars", "units", "km", "kg", "items", "employees",
            "people", "pieces", "hours", "only", "each", "a"));

    /** A 1900-2099 number counts as an amount (not a year) only when the nearby words say so. */
    static boolean looksLikeAmount(String text, int start, int end) {
        int i = start - 1;
        while (i >= 0 && (text.charAt(i) == ' ' || text.charAt(i) == ':' || text.charAt(i) == '.')) i--;
        if (i >= 0 && "$\u20b9\u20ac\u00a3".indexOf(text.charAt(i)) >= 0) return true;
        int e = i + 1;
        while (i >= 0 && Character.isLetter(text.charAt(i))) i--;
        String before = text.substring(i + 1, e).toLowerCase(Locale.ROOT);
        int j = end;
        while (j < text.length() && text.charAt(j) == ' ') j++;
        int s = j;
        while (j < text.length() && Character.isLetter(text.charAt(j))) j++;
        String after = text.substring(s, j).toLowerCase(Locale.ROOT);
        return AMOUNT_BEFORE.contains(before) || AMOUNT_AFTER.contains(after);
    }

    /** Splits a text into tokens; change points are recognised as such. */
    static List<Token> tokenize(String text) {
        List<Token> special = new ArrayList<>();
        int bodyFrom = headerEnd(text);
        Matcher m = DATE.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            Token t = new Token();
            t.kind = Token.DATE_TOKEN;
            t.start = m.start();
            t.end = m.end();
            t.surface = m.group();
            t.canonical = "#d:" + m.group(1) + "." + m.group(3) + "." + m.group(4);
            t.form = m.group(2).equals("-") ? 0 : 1;
            special.add(t);
        }
        m = NUMBER.matcher(text);
        while (m.find()) {
            if (m.start() < bodyFrom) continue;
            String digits = m.group().replace(",", "");
            if (!m.group().contains(",") && isYear(digits) && !looksLikeAmount(text, m.start(), m.end())) continue;
            Token t = new Token();
            t.kind = Token.NUMBER_TOKEN;
            t.start = m.start();
            t.end = m.end();
            t.surface = m.group();
            t.canonical = digits;   // same key as the plain word, so headers line up
            t.form = m.group().contains(",") ? 1 : 0;
            special.add(t);
        }
        for (int i = 0; i < PAIRS.length; i++) {
            for (int f = 0; f < 2; f++) {
                m = PAIR_PATTERNS[i * 2 + f].matcher(text);
                while (m.find()) {
                    if (m.start() < bodyFrom) continue;
                    Token t = new Token();
                    t.kind = Token.PAIR_TOKEN;
                    t.start = m.start();
                    t.end = m.end();
                    t.surface = m.group();
                    t.canonical = "#p:" + i;
                    t.form = f;
                    t.pair = i;
                    special.add(t);
                }
            }
        }
        extraPoints(text, bodyFrom, special);
        // keep the earliest, then longest, non-overlapping special tokens
        special.sort((a, b) -> a.start != b.start ? a.start - b.start : (b.end - b.start) - (a.end - a.start));
        List<Token> chosen = new ArrayList<>();
        int lastEnd = -1;
        for (Token t : special) {
            if (t.start >= lastEnd) {
                chosen.add(t);
                lastEnd = t.end;
            }
        }
        // plain words between the special tokens
        List<Token> out = new ArrayList<>();
        int pos = 0;
        for (Token t : chosen) {
            addWords(text, pos, t.start, out);
            out.add(t);
            pos = t.end;
        }
        addWords(text, pos, text.length(), out);
        return out;
    }

    private static void addWords(String text, int from, int to, List<Token> out) {
        Matcher w = WORD.matcher(text).region(from, to);
        while (w.find()) {
            Token t = new Token();
            t.kind = Token.WORD_TOKEN;
            t.start = w.start();
            t.end = w.end();
            t.surface = w.group();
            t.canonical = w.group().toLowerCase(Locale.ROOT);
            out.add(t);
        }
    }

    /** Number of change points in a text (how many bits a copy can carry). */
    public static int countPoints(String text) {
        int n = 0;
        for (Token t : tokenize(text)) if (t.kind != Token.WORD_TOKEN) n++;
        return n;
    }

    // ------------------------------------------------------------------
    // Making a copy
    // ------------------------------------------------------------------

    /** The other form of a change point. */
    static String alternate(Token t) {
        if (t.alt != null) return t.alt;
        switch (t.kind) {
            case Token.NUMBER_TOKEN: {
                String digits = t.surface.replace(",", "");
                if (t.surface.contains(",")) return digits;
                StringBuilder sb = new StringBuilder();
                int lead = digits.length() % 3;
                if (lead > 0) sb.append(digits, 0, lead);
                for (int i = lead; i < digits.length(); i += 3) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(digits, i, i + 3);
                }
                return sb.toString();
            }
            case Token.DATE_TOKEN:
                return t.surface.indexOf('-') >= 0 ? t.surface.replace('-', '/') : t.surface.replace('/', '-');
            default:
                return matchCase(t.surface, PAIRS[t.pair][1 - t.form]);
        }
    }

    /** Gives the replacement the capitalisation of the text it replaces. */
    static String matchCase(String original, String replacement) {
        boolean letters = false, allUpper = true;
        for (int i = 0; i < original.length(); i++) {
            char c = original.charAt(i);
            if (Character.isLetter(c)) {
                letters = true;
                if (!Character.isUpperCase(c)) allUpper = false;
            }
        }
        if (letters && allUpper && original.length() > 2) return replacement.toUpperCase(Locale.ROOT);
        if (!original.isEmpty() && Character.isUpperCase(original.charAt(0))) {
            return Character.toUpperCase(replacement.charAt(0)) + replacement.substring(1);
        }
        if (replacement.equals("OK") || replacement.startsWith("I") || replacement.startsWith("Mr")
                || replacement.startsWith("Dr")) {
            return replacement;
        }
        return replacement.substring(0, 1).toLowerCase(Locale.ROOT) + replacement.substring(1);
    }

    /** Builds the copy for a choice string: bit i = '1' uses the other form at change point i. */
    public static String apply(String original, String bits) {
        List<Token> tokens = tokenize(original);
        StringBuilder out = new StringBuilder(original.length() + 16);
        int pos = 0, point = 0;
        for (Token t : tokens) {
            if (t.kind == Token.WORD_TOKEN) continue;
            boolean flip = point < bits.length() && bits.charAt(point) == '1';
            out.append(original, pos, t.start);
            String form = flip ? alternate(t) : t.surface;
            // "approximately." -> "approx." (not "approx..")
            if (flip && form.endsWith(".") && t.end < original.length() && original.charAt(t.end) == '.') {
                form = form.substring(0, form.length() - 1);
            }
            out.append(form);
            pos = t.end;
            point++;
        }
        out.append(original, pos, original.length());
        return out.toString();
    }

    // ------------------------------------------------------------------
    // Reading the choices back from leaked text
    // ------------------------------------------------------------------

    /** What locate() found for one change point of the original. */
    public static final class Observation {
        public int point;        // index of the change point in the original
        public char bit;         // '0' = original form, '1' = other form
        public int start, end;   // where it was found in the leaked text
        public String original;  // the original surface form
    }

    static final int CONTEXT = 3;
    static final int SLACK = 2;

    /**
     * Finds the change points of `original` inside `leaked` (any fragment,
     * possibly edited) and reads which form each one has. A change point is
     * accepted only where enough of its surrounding words match.
     */
    public static List<Observation> locate(String original, String leaked) {
        List<Token> a = tokenize(original);
        List<Token> b = tokenize(normalizeOcr(leaked));
        List<Observation> out = new ArrayList<>();
        boolean[] used = new boolean[b.size()];
        int point = -1;
        for (int i = 0; i < a.size(); i++) {
            Token p = a.get(i);
            if (p.kind == Token.WORD_TOKEN) continue;
            point++;
            int best = -1, bestScore = 0, available = 0;
            for (int k = 1; k <= CONTEXT; k++) {
                if (i - k >= 0) available++;
                if (i + k < a.size()) available++;
            }
            for (int j = 0; j < b.size(); j++) {
                if (used[j] || !b.get(j).canonical.equals(p.canonical)) continue;
                // neighbouring words may be shifted by junk that text recognition
                // inserts (a stray "|" or "l"), so look a little further on each side
                java.util.Set<String> before = new java.util.HashSet<>(), after = new java.util.HashSet<>();
                for (int k = 1; k <= CONTEXT + SLACK; k++) {
                    if (j - k >= 0) before.add(b.get(j - k).canonical);
                    if (j + k < b.size()) after.add(b.get(j + k).canonical);
                }
                int score = 0;
                for (int k = 1; k <= CONTEXT; k++) {
                    if (i - k >= 0 && before.contains(a.get(i - k).canonical)) score++;
                    if (i + k < a.size() && after.contains(a.get(i + k).canonical)) score++;
                }
                if (score > bestScore) {
                    bestScore = score;
                    best = j;
                }
            }
            // two matching neighbouring words (plus the same value) are enough,
            // so a single leaked line can be traced
            int needed = Math.min(2, Math.max(1, available));
            if (best >= 0 && bestScore >= needed) {
                used[best] = true;
                Token q = b.get(best);
                Observation o = new Observation();
                o.point = point;
                o.bit = q.form == p.form ? '0' : '1';
                o.start = q.start;
                o.end = q.end;
                o.original = p.surface;
                out.add(o);
            }
        }
        return out;
    }

    /**
     * Undoes characters that text recognition (Google Lens, Snipping Tool,
     * phone OCR) or word processors often change: curly quotes, long dashes,
     * non-breaking and zero-width spaces. Every replacement is one character
     * for one character, so offsets stay valid.
     */
    static String normalizeOcr(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '\u2018': case '\u2019': case '\u201B': case '\u2032': case '`': case '\u00B4':
                    sb.append('\''); break;
                case '\u201C': case '\u201D': case '\u2033':
                    sb.append('"'); break;
                case '\u2010': case '\u2011': case '\u2012': case '\u2013': case '\u2014': case '\u2212':
                    sb.append('-'); break;
                case '\u2044': case '\u2215':
                    sb.append('/'); break;
                case '\u00A0': case '\u2007': case '\u202F':
                    sb.append(' '); break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Undoes the variations in an edited copy, so a suggested change stores
     * the owner's original wording wherever the editor did not change it.
     */
    public static String restoreOriginalForms(String original, String edited) {
        List<Observation> found = locate(original, edited);
        found.sort((x, y) -> y.start - x.start);
        StringBuilder sb = new StringBuilder(edited);
        for (Observation o : found) {
            if (o.bit == '1') sb.replace(o.start, o.end, o.original);
        }
        return sb.toString();
    }

    /** Canonical form used to compare two copies regardless of their variations. */
    public static String canonicalText(String text) {
        StringBuilder sb = new StringBuilder();
        for (Token t : tokenize(Watermark.strip(text))) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(t.canonical);
        }
        return sb.toString();
    }
}
