import it.unisa.dia.gas.jpbc.Element;
import minos.core.*;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Performance evaluation of Minos, following Section VII of the paper.
 *
 *   Fig. 2  Encrypt  (a) 1 keyword, attributes 1..100   (b) 10 keywords, attributes 1..100
 *                    (c) 1 attribute, keywords 1..100   (d) 10 attributes, keywords 1..100
 *   Fig. 3  TrapGen  same four settings
 *   Fig. 4  Search   same four settings
 *   Fig. 5  Detect and Trace with 100 keywords and 10 attributes, number of tests 1..100
 *           (y axis = total time of that many runs)
 *
 * As in the paper: symmetric type-A pairing on y^2 = x^3 + x, 160-bit group
 * order, AES for Enc, SHA-256 for the hashes, each point run 10 times and
 * the MEDIAN reported (after warm-up runs that are not measured).
 *
 * "Number of attributes" n: the access rule is A1 AND A2 AND ... AND An
 * (an n x n LSSS matrix) and the user holds all n attributes, so every
 * attribute takes part in Encrypt, TrapGen and Search (|I| = n1 = n).
 * "Number of keywords" m: Encrypt and Search use an index with m keywords;
 * TrapGen builds a trapdoor for m query keywords (the attribute part
 * tk1, tk2 once, then tk4 and tk7 for every keyword - the paper's setting:
 * "one additional power operation for each extra keyword").
 *
 * Usage:
 *   java -cp "minos-java/build;minos-java/lib/*;minos-java/test-build" Benchmark            (full, as in the paper)
 *   java ... Benchmark --quick                                                               (fewer points, 3 runs)
 *   options: --runs=10  --step=10  --max=100  --out=benchmark-results
 *
 * Output (folder benchmark-results):
 *   fig2a.csv ... fig5.csv, summary.csv, and report.html with all graphs.
 */
public class Benchmark {

    static int RUNS = 10;
    static int WARMUP = 2;
    static int STEP = 10;
    static int MAX = 100;
    static Path OUT = Paths.get("benchmark-results");

    static Setup.PublicParameters mpk;
    static Register.RegistrationResult owner;
    static Register.RegistrationResult client;
    static KeyGen.K baseK;
    static Set<String> R;
    static EnronDataset dataset;
    static String enronPath;
    static int enronEmails = 20000;
    static int idsPerKeyword = 5;

    public static void main(String[] args) throws Exception {
        for (String a : args) {
            if (a.equals("--quick")) { RUNS = 3; WARMUP = 1; STEP = 25; }
            else if (a.startsWith("--runs=")) RUNS = Integer.parseInt(a.substring(7));
            else if (a.startsWith("--step=")) STEP = Integer.parseInt(a.substring(7));
            else if (a.startsWith("--max=")) MAX = Integer.parseInt(a.substring(6));
            else if (a.startsWith("--out=")) OUT = Paths.get(a.substring(6));
            else if (a.startsWith("--enron=")) enronPath = a.substring(8);
            else if (a.startsWith("--emails=")) enronEmails = Integer.parseInt(a.substring(9));
            else if (a.startsWith("--ids=")) idsPerKeyword = Integer.parseInt(a.substring(6));
        }
        Files.createDirectories(OUT);
        long started = System.currentTimeMillis();

        System.out.println("== Minos performance evaluation (paper Section VII)");
        System.out.println("   runs per point: " + RUNS + " (median), warm-up: " + WARMUP
                + ", x values: " + xs() + "\n");

        if (enronPath != null) {
            dataset = EnronDataset.load(Paths.get(enronPath), enronEmails, MAX, idsPerKeyword);
            System.out.println("Dataset: Enron email dataset, " + dataset.emailsRead + " emails read, "
                    + dataset.distinctWords + " distinct words; the " + MAX + " most frequent keywords are used, each with "
                    + idsPerKeyword + " document identifiers.");
            System.out.println("   first keywords: " + dataset.keywords.subList(0, Math.min(15, dataset.keywords.size())) + "\n");
            StringBuilder kcsv = new StringBuilder("rank,keyword,documents_containing_it,document_identifiers\n");
            for (int i = 0; i < dataset.keywords.size(); i++) {
                String k = dataset.keywords.get(i);
                kcsv.append(i + 1).append(',').append(k).append(',').append(dataset.frequency.get(k)).append(",\"")
                        .append(String.join(" ", dataset.ids.get(k))).append("\"\n");
            }
            Files.writeString(OUT.resolve("enron-keywords.csv"), kcsv.toString());
        } else {
            System.out.println("Dataset: synthetic keywords keyword1..keyword" + MAX
                    + " (use --enron=PATH for the Enron email dataset)\n");
        }

        // Setup with an attribute universe of MAX attributes A1..A100.
        Set<String> universe = new LinkedHashSet<>();
        for (int i = 1; i <= MAX; i++) universe.add("A" + i);
        long t0 = System.nanoTime();
        mpk = Setup.setup(160, universe);
        double setupMs = (System.nanoTime() - t0) / 1e6;
        owner = Register.register(mpk, new HashSet<>());
        client = Register.register(mpk, owner.R);
        R = client.R;
        baseK = KeyGen.keyGen(mpk);
        System.out.printf("Setup with %d attributes: %.1f ms%n%n", MAX, setupMs);

        List<Chart> charts = new ArrayList<>();

        // ---------------- Fig. 2: Encrypt ----------------
        charts.add(series("fig2a", "Encryption performance with 1 keyword", "Number of attributes",
                n -> timeEncrypt(n, 1)));
        charts.add(series("fig2b", "Encryption performance with 10 keywords", "Number of attributes",
                n -> timeEncrypt(n, 10)));
        charts.add(series("fig2c", "Encryption performance with 1 attribute", "Number of keywords",
                m -> timeEncrypt(1, m)));
        charts.add(series("fig2d", "Encryption performance with 10 attributes", "Number of keywords",
                m -> timeEncrypt(10, m)));

        // ---------------- Fig. 3: TrapGen ----------------
        charts.add(series("fig3a", "Trapdoor generation performance with 1 keyword", "Number of attributes",
                n -> timeTrapGen(n, 1)));
        charts.add(series("fig3b", "Trapdoor generation performance with 10 keywords", "Number of attributes",
                n -> timeTrapGen(n, 10)));
        charts.add(series("fig3c", "Trapdoor generation performance with 1 attribute", "Number of keywords",
                m -> timeTrapGen(1, m)));
        charts.add(series("fig3d", "Trapdoor generation performance with 10 attributes", "Number of keywords",
                m -> timeTrapGen(10, m)));

        // ---------------- Fig. 4: Search ----------------
        charts.add(series("fig4a", "Search performance with 1 keyword", "Number of attributes",
                n -> timeSearch(n, 1)));
        charts.add(series("fig4b", "Search performance with 10 keywords", "Number of attributes",
                n -> timeSearch(n, 10)));
        charts.add(series("fig4c", "Search performance with 1 attribute", "Number of keywords",
                m -> timeSearch(1, m)));
        charts.add(series("fig4d", "Search performance with 10 attributes", "Number of keywords",
                m -> timeSearch(10, m)));

        // ---------------- Fig. 5: Detect and Trace ----------------
        charts.add(fig5());

        // ---------------- Table: every algorithm at 10 attributes / 10 keywords ----------------
        List<String[]> summary = summaryTable(setupMs);

        writeReport(charts, summary, (System.currentTimeMillis() - started) / 1000);
        System.out.println("\nDone in " + (System.currentTimeMillis() - started) / 1000 + " s. Open "
                + OUT.resolve("report.html").toAbsolutePath());
    }

    // ==================================================================
    // Measured operations
    // ==================================================================

    interface Measure { double run(int x) throws Exception; }

    /** AND of the first n attributes: an n x n LSSS matrix with |I| = n. */
    static KeyGen.K keysFor(int n) {
        StringBuilder rule = new StringBuilder();
        for (int i = 1; i <= n; i++) {
            if (i > 1) rule.append(" AND ");
            rule.append("A").append(i);
        }
        return baseK.withAccessStructure(AccessPolicy.parse(mpk, rule.toString()));
    }

    static Set<String> attributes(int n) {
        Set<String> s = new LinkedHashSet<>();
        for (int i = 1; i <= n; i++) s.add("A" + i);
        return s;
    }

    /** The j-th keyword (1-based): from the Enron dataset if loaded, otherwise synthetic. */
    static String kw(int j) {
        return dataset != null ? dataset.keywords.get(j - 1) : "keyword" + j;
    }

    /** Inverted index Phi with m keywords (each with the same number of document identifiers). */
    static Map<String, List<String>> index(int m) {
        Map<String, List<String>> phi = new LinkedHashMap<>();
        for (int j = 1; j <= m; j++) {
            phi.put(kw(j), dataset != null ? dataset.ids.get(kw(j)) : List.of("D1"));
        }
        return phi;
    }

    static Authorize.Token token(int n, KeyGen.K K) {
        return Authorize.ownerAuthorize(mpk, R, client.pk, Authorize.clientProof(mpk, client.pk, client.sk),
                attributes(n), K, owner.sk);
    }

    static double timeEncrypt(int n, int m) throws Exception {
        KeyGen.K K = keysFor(n);
        Map<String, List<String>> phi = index(m);
        return median(() -> Encrypt.encrypt(mpk, phi, owner.sk, owner.pk, K));
    }

    /** Trapdoor for m query keywords: attribute part once, keyword part m times. */
    static double timeTrapGen(int n, int m) throws Exception {
        KeyGen.K K = keysFor(n);
        Authorize.Token TK = token(n, K);
        return median(() -> {
            TrapGen.Trapdoor T = TrapGen.trapGen(mpk, kw(1), client.sk, TK);
            for (int j = 2; j <= m; j++) {
                Element inv = mpk.getHashFunctions().H2(kw(j)).duplicate().invert();
                TK.tk4.duplicate().powZn(inv);
                TK.tk7.duplicate().powZn(inv.duplicate().negate());
            }
            return T;
        });
    }

    /** CSP search over an index of m keywords with a trapdoor for one of them. */
    static double timeSearch(int n, int m) throws Exception {
        KeyGen.K K = keysFor(n);
        List<Map<String, Object>> L = Encrypt.toJson(Encrypt.encrypt(mpk, index(m), owner.sk, owner.pk, K));
        TrapGen.Trapdoor T = TrapGen.trapGen(mpk, kw(m), client.sk, token(n, K));
        double ms = median(() -> Search.search(mpk, L, T));
        if (Search.search(mpk, L, T).size() != 1) throw new IllegalStateException("search did not find the keyword");
        return ms;
    }

    interface Op { Object call() throws Exception; }

    static double median(Op op) throws Exception {
        for (int i = 0; i < WARMUP; i++) op.call();
        double[] t = new double[RUNS];
        for (int i = 0; i < RUNS; i++) {
            long s = System.nanoTime();
            op.call();
            t[i] = (System.nanoTime() - s) / 1e6;
        }
        Arrays.sort(t);
        return RUNS % 2 == 1 ? t[RUNS / 2] : (t[RUNS / 2 - 1] + t[RUNS / 2]) / 2;
    }

    static List<Integer> xs() {
        List<Integer> x = new ArrayList<>();
        x.add(1);
        for (int v = STEP; v <= MAX; v += STEP) if (v != 1) x.add(v);
        return x;
    }

    static Chart series(String id, String title, String xLabel, Measure m) throws Exception {
        Chart c = new Chart(id, title, xLabel, "Time (ms)");
        Line line = new Line("Minos", "#1f77b4");
        System.out.println(id + "  " + title);
        for (int x : xs()) {
            double ms = m.run(x);
            line.x.add((double) x);
            line.y.add(ms);
            System.out.printf("   %-4d %10.1f ms%n", x, ms);
        }
        c.lines.add(line);
        writeCsv(c);
        return c;
    }

    /** Fig. 5: total time of running Detect / Trace 1..100 times (100 keywords, 10 attributes). */
    static Chart fig5() throws Exception {
        System.out.println("fig5   Detect and trace performance (" + Math.min(100, MAX) + " keywords, " + Math.min(10, MAX) + " attributes)");
        int n = Math.min(10, MAX), m = Math.min(100, MAX);
        KeyGen.K K = keysFor(n);
        List<Map<String, Object>> L = Encrypt.toJson(Encrypt.encrypt(mpk, index(m), owner.sk, owner.pk, K));
        TrapGen.Trapdoor T = TrapGen.trapGen(mpk, kw(7), client.sk, token(n, K));
        Trace.HelpData hp = Trace.help(mpk, kw(1), owner.sk, owner.pk, K);
        List<String> W = new ArrayList<>(index(m).keySet());
        if (!Detect.detect(T.tk3, owner.sk).isEqual(client.pk)) throw new IllegalStateException("Detect failed");
        if (!Trace.trace(mpk, L, hp)) throw new IllegalStateException("Trace failed");
        for (int i = 0; i < WARMUP; i++) { Detect.detect(T.tk3, owner.sk); Trace.trace(mpk, L, hp); }

        Chart c = new Chart("fig5", "Detect and trace performance", "Number of tests", "Time (ms)");
        Line detect = new Line("Detect (Alg. 9)", "#9467bd");
        Line detect11 = new Line("Detect (Alg. 11 enhanced)", "#2ca02c");
        Line trace = new Line("Trace", "#8c564b");
        int tests = MAX;
        int every = Math.max(1, STEP);
        double sumD = 0, sumD11 = 0, sumT = 0;
        for (int i = 1; i <= tests; i++) {
            long s = System.nanoTime();
            Detect.detect(T.tk3, owner.sk);
            sumD += (System.nanoTime() - s) / 1e6;
            s = System.nanoTime();
            Detect.detectEnhanced(mpk, T, owner.sk, K, W);
            sumD11 += (System.nanoTime() - s) / 1e6;
            s = System.nanoTime();
            Trace.trace(mpk, L, hp);
            sumT += (System.nanoTime() - s) / 1e6;
            if (i == 1 || i % every == 0) {
                detect.x.add((double) i); detect.y.add(sumD);
                detect11.x.add((double) i); detect11.y.add(sumD11);
                trace.x.add((double) i); trace.y.add(sumT);
                System.out.printf("   %-4d detect %8.1f ms   detect-11 %9.1f ms   trace %9.1f ms%n", i, sumD, sumD11, sumT);
            }
        }
        c.lines.add(detect);
        c.lines.add(trace);
        c.lines.add(detect11);
        System.out.printf("   one Detect: %.2f ms, one enhanced Detect: %.1f ms, one Trace: %.1f ms%n",
                sumD / tests, sumD11 / tests, sumT / tests);
        writeCsv(c);
        return c;
    }

    static List<String[]> summaryTable(double setupMs) throws Exception {
        System.out.println("\nsummary (10 attributes, 10 keywords, median of " + RUNS + ")");
        int n = 10, m = 10;
        List<String[]> rows = new ArrayList<>();
        KeyGen.K K = keysFor(n);
        Authorize.Token TK = token(n, K);
        List<Map<String, Object>> L = Encrypt.toJson(Encrypt.encrypt(mpk, index(m), owner.sk, owner.pk, K));
        TrapGen.Trapdoor T = TrapGen.trapGen(mpk, kw(3), client.sk, TK);
        String ct4 = Search.search(mpk, L, T).get(0);
        Trace.HelpData hp = Trace.help(mpk, kw(1), owner.sk, owner.pk, K);
        List<String> W = new ArrayList<>(index(m).keySet());
        Set<String> empty = new HashSet<>();
        add(rows, "1. Setup (" + MAX + " attributes)", setupMs);
        add(rows, "2. Register", median(() -> Register.register(mpk, empty)));
        add(rows, "3. KeyGen (lines 3-7)", median(() -> KeyGen.keyGen(mpk)));
        add(rows, "3. KeyGen (lines 1-2, 10-attribute rule)", median(() -> keysFor(n)));
        add(rows, "4. Encrypt", median(() -> Encrypt.encrypt(mpk, index(m), owner.sk, owner.pk, K)));
        add(rows, "5. Authorize (client proof + owner)", median(() -> token(n, K)));
        add(rows, "6. TrapGen (1 keyword)", median(() -> TrapGen.trapGen(mpk, kw(3), client.sk, TK)));
        add(rows, "7. Search", median(() -> Search.search(mpk, L, T)));
        add(rows, "8. Decrypt", median(() -> Decrypt.decrypt(K.k, ct4)));
        add(rows, "9. Detect (Algorithm 9)", median(() -> Detect.detect(T.tk3, owner.sk)));
        add(rows, "11. Detect (Algorithm 11)", median(() -> Detect.detectEnhanced(mpk, T, owner.sk, K, W)));
        add(rows, "10. Trace - help data (claimant)", median(() -> Trace.help(mpk, kw(1), owner.sk, owner.pk, K)));
        add(rows, "10. Trace - check (CSP)", median(() -> Trace.trace(mpk, L, hp)));

        // sizes in bytes
        int indexBytes = 0;
        for (Map<String, Object> e : L) indexBytes += String.valueOf(e).length();
        rows.add(new String[]{"Encrypted index L size (10 attributes, 10 keywords)", indexBytes + " bytes (JSON)"});
        rows.add(new String[]{"Trapdoor size", T.toJson().toString().length() + " bytes (JSON)"});
        rows.add(new String[]{"Group element size (G)", mpk.getG().toBytes().length + " bytes"});

        StringBuilder csv = new StringBuilder("measurement,value\n");
        for (String[] r : rows) csv.append('"').append(r[0]).append("\",").append(r[1]).append('\n');
        Files.writeString(OUT.resolve("summary.csv"), csv.toString());
        return rows;
    }

    static void add(List<String[]> rows, String name, double ms) {
        rows.add(new String[]{name, String.format(Locale.ROOT, "%.2f ms", ms)});
        System.out.printf("   %-45s %10.2f ms%n", name, ms);
    }

    // ==================================================================
    // Output: CSV + HTML report with SVG line charts
    // ==================================================================

    static class Line {
        final String name, color;
        final List<Double> x = new ArrayList<>(), y = new ArrayList<>();
        Line(String name, String color) { this.name = name; this.color = color; }
    }

    static class Chart {
        final String id, title, xLabel, yLabel;
        final List<Line> lines = new ArrayList<>();
        Chart(String id, String title, String xLabel, String yLabel) {
            this.id = id; this.title = title; this.xLabel = xLabel; this.yLabel = yLabel;
        }
    }

    static void writeCsv(Chart c) throws IOException {
        StringBuilder sb = new StringBuilder(c.xLabel.replace(',', ' '));
        for (Line l : c.lines) sb.append(',').append(l.name.replace(',', ' ')).append(" (ms)");
        sb.append('\n');
        for (int i = 0; i < c.lines.get(0).x.size(); i++) {
            sb.append(c.lines.get(0).x.get(i).intValue());
            for (Line l : c.lines) sb.append(',').append(String.format(Locale.ROOT, "%.3f", l.y.get(i)));
            sb.append('\n');
        }
        Files.writeString(OUT.resolve(c.id + ".csv"), sb.toString());
    }

    static String svg(Chart c) {
        int W = 520, H = 330, left = 70, right = 20, top = 40, bottom = 55;
        double maxX = 0, maxY = 0;
        for (Line l : c.lines) {
            for (double v : l.x) maxX = Math.max(maxX, v);
            for (double v : l.y) maxY = Math.max(maxY, v);
        }
        maxX = Math.max(1, maxX);
        maxY = niceMax(maxY);
        double pw = W - left - right, ph = H - top - bottom;
        StringBuilder s = new StringBuilder();
        s.append("<svg viewBox=\"0 0 ").append(W).append(' ').append(H)
                .append("\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"Arial, sans-serif\" font-size=\"11\">");
        s.append("<text x=\"").append(W / 2).append("\" y=\"20\" text-anchor=\"middle\" font-size=\"13\" font-weight=\"bold\">")
                .append(esc(c.title)).append("</text>");
        for (int i = 0; i <= 5; i++) {
            double v = maxY * i / 5;
            double y = top + ph - ph * i / 5;
            s.append(String.format(Locale.ROOT,
                    "<line x1=\"%d\" x2=\"%.1f\" y1=\"%.1f\" y2=\"%.1f\" stroke=\"#ddd\"/><text x=\"%d\" y=\"%.1f\" text-anchor=\"end\">%s</text>",
                    left, left + pw, y, y, left - 6, y + 4, fmtTick(v)));
        }
        for (int i = 0; i <= 5; i++) {
            double v = maxX * i / 5;
            double x = left + pw * i / 5;
            s.append(String.format(Locale.ROOT,
                    "<line x1=\"%.1f\" x2=\"%.1f\" y1=\"%d\" y2=\"%.1f\" stroke=\"#999\"/><text x=\"%.1f\" y=\"%.1f\" text-anchor=\"middle\">%d</text>",
                    x, x, top + (int) ph, top + ph + 5, x, top + ph + 18, Math.round(v)));
        }
        s.append(String.format(Locale.ROOT, "<rect x=\"%d\" y=\"%d\" width=\"%.1f\" height=\"%.1f\" fill=\"none\" stroke=\"#333\"/>",
                left, top, pw, ph));
        s.append(String.format(Locale.ROOT, "<text x=\"%.1f\" y=\"%d\" text-anchor=\"middle\">%s</text>",
                left + pw / 2, H - 12, esc(c.xLabel)));
        s.append(String.format(Locale.ROOT,
                "<text transform=\"translate(16 %.1f) rotate(-90)\" text-anchor=\"middle\">%s</text>", top + ph / 2, esc(c.yLabel)));
        int legendY = top + 8;
        for (Line l : c.lines) {
            StringBuilder pts = new StringBuilder();
            for (int i = 0; i < l.x.size(); i++) {
                double x = left + pw * l.x.get(i) / maxX;
                double y = top + ph - ph * l.y.get(i) / maxY;
                pts.append(String.format(Locale.ROOT, "%.1f,%.1f ", x, y));
                s.append(String.format(Locale.ROOT, "<circle cx=\"%.1f\" cy=\"%.1f\" r=\"3\" fill=\"%s\"><title>%s: x=%d, %.1f ms</title></circle>",
                        x, y, l.color, esc(l.name), l.x.get(i).intValue(), l.y.get(i)));
            }
            s.append("<polyline fill=\"none\" stroke-dasharray=\"5 3\" stroke-width=\"1.6\" stroke=\"").append(l.color)
                    .append("\" points=\"").append(pts).append("\"/>");
            s.append(String.format(Locale.ROOT,
                    "<line x1=\"%d\" x2=\"%d\" y1=\"%d\" y2=\"%d\" stroke=\"%s\" stroke-width=\"2\"/><text x=\"%d\" y=\"%d\">%s</text>",
                    left + 10, left + 30, legendY, legendY, l.color, left + 35, legendY + 4, esc(l.name)));
            legendY += 15;
        }
        s.append("</svg>");
        return s.toString();
    }

    static double niceMax(double v) {
        if (v <= 0) return 1;
        double p = Math.pow(10, Math.floor(Math.log10(v)));
        for (double m : new double[]{1, 2, 2.5, 5, 10}) if (m * p >= v) return m * p;
        return 10 * p;
    }

    static String fmtTick(double v) {
        return v >= 100 || v == Math.rint(v) ? String.valueOf(Math.round(v)) : String.format(Locale.ROOT, "%.1f", v);
    }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static void writeReport(List<Chart> charts, List<String[]> summary, long seconds) throws IOException {
        Runtime rt = Runtime.getRuntime();
        String machine = System.getProperty("os.name") + " " + System.getProperty("os.version") + " (" + System.getProperty("os.arch")
                + "), " + rt.availableProcessors() + " logical CPUs, max heap " + rt.maxMemory() / (1024 * 1024) + " MB, Java "
                + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")";
        String cpu = System.getenv("PROCESSOR_IDENTIFIER");
        StringBuilder h = new StringBuilder();
        h.append("<!doctype html><html><head><meta charset=\"utf-8\"><title>Minos performance evaluation</title><style>")
                .append("body{font-family:Arial,sans-serif;margin:24px;color:#222}h1{margin-bottom:4px}")
                .append(".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(460px,1fr));gap:18px}")
                .append("figure{margin:0;border:1px solid #ddd;padding:8px;border-radius:6px}figcaption{font-size:13px;color:#444;margin-top:4px}")
                .append("table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:5px 9px;text-align:left}p.note{color:#555;max-width:900px}")
                .append("</style></head><body>");
        h.append("<h1>Minos performance evaluation</h1>");
        h.append("<p class=\"note\">Generated ").append(LocalDateTime.now().withNano(0)).append(" in ").append(seconds).append(" s. ")
                .append("Machine: ").append(esc(machine)).append(cpu != null ? ", CPU " + esc(cpu) : "").append(".<br>")
                .append("Settings as in the paper (Section VII-C): type-A symmetric pairing on y<sup>2</sup> = x<sup>3</sup> + x, 160-bit group order, ")
                .append("JPBC, AES, SHA-256. Each point is the median of ").append(RUNS).append(" runs after ").append(WARMUP).append(" warm-up runs. ")
                .append("The access rule for n attributes is A1 AND ... AND An and the user holds all of them. ")
                .append(dataset != null ? "Keywords: the " + MAX + " most frequent words of " + dataset.emailsRead
                        + " emails of the Enron email dataset (stop words removed), each with " + idsPerKeyword + " document identifiers."
                        : "Keywords: synthetic.").append("</p>");
        String[] groups = {"fig2", "fig3", "fig4", "fig5"};
        String[] names = {"Fig. 2. Encryption performance with various number of keywords and attributes.",
                "Fig. 3. Trapdoor generation performance with various number of keywords and attributes.",
                "Fig. 4. Search performance with various number of keywords and attributes.",
                "Fig. 5. Detect and trace performance (100 keywords, 10 attributes; y = total time of that many runs)."};
        for (int g = 0; g < groups.length; g++) {
            h.append("<h2>").append(esc(names[g])).append("</h2><div class=\"grid\">");
            char sub = 'a';
            for (Chart c : charts) {
                if (!c.id.startsWith(groups[g])) continue;
                h.append("<figure>").append(svg(c)).append("<figcaption>")
                        .append(groups[g].equals("fig5") ? "" : "(" + sub++ + ") ").append(esc(c.title))
                        .append(" - data: ").append(c.id).append(".csv</figcaption></figure>");
            }
            h.append("</div>");
        }
        h.append("<h2>All algorithms (10 attributes, 10 keywords)</h2><table><tr><th>Measurement</th><th>Median</th></tr>");
        for (String[] r : summary) h.append("<tr><td>").append(esc(r[0])).append("</td><td>").append(esc(r[1])).append("</td></tr>");
        h.append("</table></body></html>");
        Files.writeString(OUT.resolve("report.html"), h.toString(), StandardCharsets.UTF_8);
    }

    // ==================================================================
    // Enron email dataset (paper Section VII-C.4)
    //   Accepts either the CMU "maildir" folder (enron_mail_20150507.tar.gz,
    //   extracted) or the Kaggle "emails.csv" (columns file,message).
    //   Each email is one document; its identifier is its file name.
    //   Words of the subject and body are lower-cased, stop words are
    //   removed, and the most frequent words become the keywords. As in
    //   the paper, every keyword is linked to the same number of document
    //   identifiers.
    // ==================================================================

    static class EnronDataset {
        final List<String> keywords = new ArrayList<>();
        final Map<String, List<String>> ids = new HashMap<>();
        final Map<String, Integer> frequency = new HashMap<>();
        int emailsRead;
        int distinctWords;

        static final Set<String> STOP = new HashSet<>(Arrays.asList((
                "the and for that this with you are have will from not but your all can was our has any they been " +
                "would there their what about which when were them more also into than its out only other some " +
                "could should may other these those then such each just like here very over did does doing done " +
                "him his her she he who whom how why where while because about after before again against between " +
                "both during few most own same too off once under until upon above below down further now yes " +
                "get got let make made one two three use used using said says say know think need want see going " +
                "thanks thank please regards hello dear best sincerely let know also well good new day today time " +
                "subject sent original message forwarded forward fwd mail email emails cc bcc http https www com net " +
                "org html enron ect hou corp na pm am mon tue wed thu fri sat sun jan feb mar apr jun jul aug sep sept " +
                "oct nov dec monday tuesday wednesday thursday friday saturday sunday re fw to of in on at by an or " +
                "is it be as if so no do we me my us up go").split(" ")));

        static EnronDataset load(Path path, int maxEmails, int keywordCount, int idsPerKeyword) throws IOException {
            if (!Files.exists(path)) throw new IOException("Enron dataset not found: " + path.toAbsolutePath());
            EnronDataset d = new EnronDataset();
            Map<String, Integer> df = new HashMap<>();
            Map<String, List<String>> postings = new HashMap<>();
            System.out.println("Reading the Enron email dataset from " + path.toAbsolutePath() + " ...");
            if (Files.isDirectory(path)) {
                try (java.util.stream.Stream<Path> files = Files.walk(path)) {
                    Iterator<Path> it = files.filter(Files::isRegularFile).iterator();
                    while (it.hasNext() && d.emailsRead < maxEmails) {
                        Path f = it.next();
                        String text = new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1);
                        String id = path.relativize(f).toString().replace('\\', '/');
                        d.add(id, text, df, postings, idsPerKeyword);
                    }
                }
            } else {
                try (java.io.BufferedReader in = Files.newBufferedReader(path, StandardCharsets.ISO_8859_1)) {
                    readCsvRecord(in); // header: file,message
                    List<String> rec;
                    while (d.emailsRead < maxEmails && (rec = readCsvRecord(in)) != null) {
                        if (rec.size() >= 2) d.add(rec.get(0), rec.get(1), df, postings, idsPerKeyword);
                    }
                }
            }
            d.distinctWords = df.size();
            // keywords: highest document frequency first (ties: alphabetical, for repeatable runs)
            List<Map.Entry<String, Integer>> ranked = new ArrayList<>(df.entrySet());
            ranked.sort((a, b) -> b.getValue().equals(a.getValue()) ? a.getKey().compareTo(b.getKey()) : b.getValue() - a.getValue());
            for (Map.Entry<String, Integer> e : ranked) {
                if (d.keywords.size() == keywordCount) break;
                if (e.getValue() < idsPerKeyword) break;
                d.keywords.add(e.getKey());
                d.ids.put(e.getKey(), postings.get(e.getKey()));
                d.frequency.put(e.getKey(), e.getValue());
            }
            if (d.keywords.size() < keywordCount) {
                throw new IOException("Only " + d.keywords.size() + " keywords found; read more emails (--emails=...)");
            }
            return d;
        }

        void add(String id, String email, Map<String, Integer> df, Map<String, List<String>> postings, int idsPerKeyword) {
            emailsRead++;
            // headers end at the first empty line; keep the Subject header
            int split = email.indexOf("\n\n");
            if (split < 0) split = email.indexOf("\r\n\r\n");
            String headers = split < 0 ? "" : email.substring(0, split);
            String body = split < 0 ? email : email.substring(split);
            String subject = "";
            for (String line : headers.split("\r?\n")) {
                if (line.regionMatches(true, 0, "Subject:", 0, 8)) subject = line.substring(8);
            }
            Set<String> words = new LinkedHashSet<>();
            tokenize(subject + "\n" + body, words);
            for (String w : words) {
                df.merge(w, 1, Integer::sum);
                List<String> list = postings.computeIfAbsent(w, k -> new ArrayList<>(idsPerKeyword));
                if (list.size() < idsPerKeyword) list.add(id);
            }
        }

        static void tokenize(String text, Set<String> out) {
            StringBuilder word = new StringBuilder();
            for (int i = 0; i <= text.length(); i++) {
                char c = i < text.length() ? Character.toLowerCase(text.charAt(i)) : ' ';
                if (c >= 'a' && c <= 'z') {
                    word.append(c);
                } else {
                    if (word.length() >= 3 && word.length() <= 15 && !STOP.contains(word.toString())) out.add(word.toString());
                    word.setLength(0);
                }
            }
        }

        /** One record of a CSV file with quoted fields that may contain new lines. */
        static List<String> readCsvRecord(java.io.BufferedReader in) throws IOException {
            List<String> fields = new ArrayList<>();
            StringBuilder field = new StringBuilder();
            boolean quoted = false, any = false;
            int c;
            while ((c = in.read()) != -1) {
                any = true;
                char ch = (char) c;
                if (quoted) {
                    if (ch == '"') {
                        in.mark(1);
                        int next = in.read();
                        if (next == '"') field.append('"');
                        else { quoted = false; if (next != -1) in.reset(); }
                    } else field.append(ch);
                } else if (ch == '"') quoted = true;
                else if (ch == ',') { fields.add(field.toString()); field.setLength(0); }
                else if (ch == '\n') { fields.add(field.toString()); return fields; }
                else if (ch != '\r') field.append(ch);
            }
            if (!any) return null;
            fields.add(field.toString());
            return fields;
        }
    }
}
