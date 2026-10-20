import minos.common.Json;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * End-to-end test through the HTTP APIs (the same calls the web UI makes).
 *
 *   java -cp build:lib/* EndToEndTest phase1 http://localhost:8080
 *   (restart both servers)
 *   java -cp build:lib/* EndToEndTest phase2 http://localhost:8080
 */
public class EndToEndTest {

    static String base;
    static int failures = 0;

    static final class Client {
        final HttpClient http = HttpClient.newBuilder().cookieHandler(new CookieManager()).build();
        final String name;

        Client(String name) {
            this.name = name;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> call(String method, String path, Object body) throws Exception {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
            if (body == null) b.method(method, HttpRequest.BodyPublishers.noBody());
            else b.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(Json.write(body)));
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, Object> m = (Map<String, Object>) Json.parse(r.body());
            m.put("_status", r.statusCode());
            return m;
        }

        byte[] raw(String path) throws Exception {
            HttpResponse<byte[]> r = http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode() + " " + new String(r.body()));
            return r.body();
        }

        Map<String, Object> post(String path, Object body) throws Exception {
            return call("POST", path, body);
        }

        Map<String, Object> get(String path) throws Exception {
            return call("GET", path, null);
        }

        void login(String password, String role) throws Exception {
            Map<String, Object> r = post("/api/login", map("userId", name, "password", password, "actingAs", role));
            check(name + " logs in as " + role, Boolean.TRUE.equals(r.get("success")), r);
        }
    }

    static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    static void check(String what, boolean ok, Object detail) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + what + (ok ? "" : "   -> " + detail));
        if (!ok) failures++;
    }

    static void step(String s) {
        System.out.println("\n== " + s);
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object o) {
        return (List<Object>) o;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) {
        return (Map<String, Object>) o;
    }

    public static void main(String[] args) throws Exception {
        base = args[1];
        if (args[0].equals("phase1")) phase1();
        else phase2();
        System.out.println(failures == 0 ? "\nALL CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    static void phase1() throws Exception {
        Client anon = new Client("anon");

        step("FIRST RUN: Setup (Algorithm 1)");
        Map<String, Object> st = anon.get("/api/status");
        check("system reports not initialized", Boolean.FALSE.equals(st.get("initialized")), st);
        check("CSP server online", Boolean.TRUE.equals(st.get("cspOnline")), st);
        Map<String, Object> setup = anon.post("/api/setup",
                map("attributes", List.of("HR", "Manager", "Employee", "Finance", "Admin")));
        check("setup succeeds", Boolean.TRUE.equals(setup.get("initialized")), setup);
        check("mpk pushed to CSP", String.valueOf(setup.get("cspSync")).startsWith("CSP holds"), setup.get("cspSync"));
        Map<String, Object> again = anon.post("/api/setup", map("attributes", List.of("HR")));
        check("second setup refused (mpk never regenerated)", (int) again.get("_status") == 409, again);

        step("REGISTER owner + users (Algorithm 2 + automatic KeyGen, Algorithm 3)");
        for (Object[] u : new Object[][]{
                {"alice", List.of("Admin", "Manager")},
                {"bob", List.of("HR", "Employee")},
                {"carol", List.of("Employee")},
                {"mallory", List.of("Finance")}}) {
            Map<String, Object> r = anon.post("/api/register", map("userId", u[0], "displayName", u[0],
                    "password", "password-" + u[0], "attributes", u[1]));
            check("register " + u[0] + " " + u[1], Boolean.TRUE.equals(r.get("success"))
                    && String.valueOf(r.get("keyGen")).contains("sk2"), r);
        }
        Map<String, Object> dup = anon.post("/api/register", map("userId", "bob", "password", "xxxxxxxx",
                "attributes", List.of("HR")));
        check("duplicate registration refused", (int) dup.get("_status") == 409, dup);
        Map<String, Object> csp = m(anon.get("/api/status").get("csp"));
        check("CSP registration list R has 4 public keys", ((Number) csp.get("registeredUsers")).intValue() == 4, csp);

        step("OWNER: upload + Encrypt (Algorithm 4) + AES-GCM document encryption");
        Client alice = new Client("alice");
        alice.login("password-alice", "owner");
        String salaryText = "CONFIDENTIAL salary sheet 2026\nbob: 100\n";
        Map<String, Object> up1 = alice.post("/api/owner/documents", map(
                "fileName", "salary.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString(salaryText.getBytes(StandardCharsets.UTF_8)),
                "keywords", "Salary, payroll, confidentialsalaryreportA",
                "allowedRoles", List.of("HR", "Manager")));
        check("salary.txt uploaded with policy HR OR Manager", "HR OR Manager".equals(up1.get("policy")), up1);
        String salaryId = (String) up1.get("documentId");
        Map<String, Object> up2 = alice.post("/api/owner/documents", map(
                "fileName", "board.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString("board minutes".getBytes(StandardCharsets.UTF_8)),
                "keywords", "salary, board",
                "policy", "(Finance AND Manager) OR Admin"));
        check("board.txt uploaded with AND/OR policy", Boolean.TRUE.equals(up2.get("success"))
                && m(up2.get("accessStructure")).get("n2").toString().equals("2"), up2);
        Map<String, Object> csp2 = m(anon.get("/api/status").get("csp"));
        check("CSP stores 2 encrypted documents + 2 indexes",
                ((Number) csp2.get("encryptedDocuments")).intValue() == 2
                        && ((Number) csp2.get("encryptedIndexes")).intValue() == 2, csp2);
        Map<String, Object> userAsOwner = alice.post("/api/user/search", map("keyword", "salary"));
        check("owner role cannot call the user search endpoint", (int) userAsOwner.get("_status") == 403, userAsOwner);

        step("USER bob (HR): Authorize -> TrapGen -> CSP Search -> Decrypt");
        Client bob = new Client("bob");
        bob.login("password-bob", "user");
        Map<String, Object> s1 = bob.post("/api/user/search", map("keyword", "SALARY"));
        List<Object> matches = list(s1.get("matches"));
        check("bob finds exactly salary.txt", matches.size() == 1
                && salaryId.equals(m(matches.get(0)).get("documentId")), s1);
        check("board.txt denied by Authorize (policy not satisfied)", list(s1.get("denied")).size() == 1, s1.get("denied"));
        check("one trapdoor generated (only for authorized document)", list(s1.get("trapdoors")).size() == 1, s1.get("trapdoors"));
        String searchId = (String) s1.get("searchId");
        byte[] plain = bob.raw("/api/user/documents/" + salaryId + "/download?searchId=" + searchId);
        check("bob decrypts the document body (AES-GCM)", same(new String(plain, StandardCharsets.UTF_8), salaryText), new String(plain));

        Map<String, Object> s2 = bob.post("/api/user/search", map("keyword", "salary"));
        check("same keyword again -> NEW trapdoor (different hash), accepted",
                !m(list(s2.get("trapdoors")).get(0)).get("trapdoorHash").equals(m(list(s1.get("trapdoors")).get(0)).get("trapdoorHash"))
                        && "ACCEPTED".equals(m(list(s2.get("trapdoors")).get(0)).get("status")), s2.get("trapdoors"));
        Map<String, Object> s3 = bob.post("/api/user/search", map("keyword", "nothing-here"));
        check("unknown keyword -> no match", list(s3.get("matches")).isEmpty(), s3);
        Map<String, Object> s4 = bob.post("/api/user/search", map("keyword", "confidentialsalaryreportB"));
        check("keyword sharing a 24-char prefix does NOT match (H2 fix)", list(s4.get("matches")).isEmpty(), s4);

        step("USER carol (Employee): Authorize fails -> no trapdoor");
        Client carol = new Client("carol");
        carol.login("password-carol", "user");
        Map<String, Object> a1 = carol.post("/api/user/search", map("keyword", "salary"));
        check("carol denied, zero trapdoors sent", Boolean.TRUE.equals(a1.get("accessDenied"))
                && list(a1.get("trapdoors")).isEmpty(), a1);
        try {
            carol.raw("/api/user/documents/" + salaryId + "/download?searchId=" + searchId);
            check("carol cannot use bob's search to download", false, "download succeeded");
        } catch (IllegalStateException e) {
            check("carol cannot use bob's search to download", e.getMessage().startsWith("HTTP 403"), e.getMessage());
        }

        step("REPLAY: resubmit bob's used trapdoor");
        String tdId = (String) m(list(s1.get("trapdoors")).get(0)).get("trapdoorId");
        Map<String, Object> envelope = m(m(s1.get("envelopes")).get(tdId));
        Client attacker = new Client("mallory");
        attacker.login("password-mallory", "user");
        Map<String, Object> rp = attacker.post("/api/security/submit-trapdoor", map("envelope", envelope));
        check("CSP rejects reused trapdoor", "REJECTED_REPLAY".equals(rp.get("status")) && rp.get("alertId") != null, rp);
        Map<String, Object> tampered = new LinkedHashMap<>(envelope);
        tampered.put("nonce", "AAAAAAAAAAAAAAAAAAAAAA==");
        Map<String, Object> rt = attacker.post("/api/security/submit-trapdoor", map("envelope", tampered));
        check("modified-nonce copy rejected (signature) + alert", "REJECTED_INVALID_ENVELOPE".equals(rt.get("status"))
                && rt.get("alertId") != null, rt);

        step("OWNER sees alert; Detect (Algorithm 11) identifies the registered user");
        Thread.sleep(1500);
        Map<String, Object> al = alice.get("/api/owner/alerts");
        List<Object> alerts = list(al.get("alerts"));
        check("2 alerts for alice", alerts.size() == 2, al);
        boolean allBob = true;
        for (Object o : alerts) {
            Map<String, Object> a = m(o);
            allBob &= "bob".equals(a.get("identifiedUserId")) && "11".equals(String.valueOf(a.get("detectAlgorithm")))
                    && "mallory".equals(a.get("reusedBy")) && a.get("firstUsedAt") != null;
        }
        check("each alert: trapdoor bound to bob (Alg. 11), reused by mallory, first-use time", allBob, alerts);

        step("OWNER revokes bob");
        Map<String, Object> rv = alice.post("/api/owner/revocations", map("userId", "bob",
                "alertId", m(alerts.get(0)).get("alertId")));
        check("revocation recorded", "bob".equals(rv.get("revoked")), rv);
        Map<String, Object> s5 = bob.post("/api/user/search", map("keyword", "salary"));
        check("bob's search is now denied", Boolean.TRUE.equals(s5.get("accessDenied")), s5);

        step("TRACE (Algorithm 10): ownership claims");
        Map<String, Object> t1 = alice.post("/api/ownership/claim", map("documentId", salaryId));
        check("alice's claim verified", Boolean.TRUE.equals(t1.get("valid")), t1);
        Map<String, Object> t2 = attacker.post("/api/ownership/claim", map("documentId", salaryId, "keyword", "salary"));
        check("mallory's false claim rejected", Boolean.FALSE.equals(t2.get("valid")), t2);

        step("OWNER APPROVAL: access request -> approve -> deny (project extension)");
        String handbook = "Employee handbook v3";
        Map<String, Object> up3 = alice.post("/api/owner/documents", map(
                "fileName", "handbook.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString(handbook.getBytes(StandardCharsets.UTF_8)),
                "keywords", "handbook", "allowedRoles", List.of("Employee"), "requireApproval", true));
        String hbId = (String) up3.get("documentId");
        check("handbook.txt uploaded with approval required", hbId != null, up3);
        Client carol2 = new Client("carol");
        carol2.login("password-carol", "user");
        Map<String, Object> h1 = carol2.post("/api/user/search", map("keyword", "handbook"));
        boolean pendingListed = false;
        for (Object o : list(h1.get("denied"))) {
            if (hbId.equals(m(o).get("documentId")) && "PENDING".equals(m(o).get("approval"))) pendingListed = true;
        }
        check("carol's first search: no match, request PENDING, no trapdoor sent",
                list(h1.get("matches")).isEmpty() && list(h1.get("trapdoors")).isEmpty() && pendingListed, h1);
        List<Object> reqs = list(alice.get("/api/owner/access-requests").get("requests"));
        check("alice sees exactly one pending request from carol", reqs.size() == 1
                && "carol".equals(m(reqs.get(0)).get("userId")) && "PENDING".equals(m(reqs.get(0)).get("status"))
                && !String.valueOf(reqs.get(0)).contains("handbook\""), reqs);
        String reqId = (String) m(reqs.get(0)).get("requestId");
        Map<String, Object> other = attacker.post("/api/owner/access-requests/" + reqId + "/approve", map());
        check("another owner cannot decide alice's request", (int) other.get("_status") == 403, other);
        alice.post("/api/owner/access-requests/" + reqId + "/approve", map());
        Map<String, Object> h2 = carol2.post("/api/user/search", map("keyword", "handbook"));
        check("after approval carol finds handbook.txt", list(h2.get("matches")).size() == 1, h2);
        byte[] hb = carol2.raw("/api/user/documents/" + hbId + "/download?searchId=" + h2.get("searchId"));
        check("carol decrypts handbook.txt", same(new String(hb, StandardCharsets.UTF_8), handbook), new String(hb));
        alice.post("/api/owner/access-requests/" + reqId + "/deny", map());
        Map<String, Object> h3 = carol2.post("/api/user/search", map("keyword", "handbook"));
        check("after deny carol is refused again, no trapdoor", list(h3.get("matches")).isEmpty()
                && list(h3.get("trapdoors")).isEmpty(), h3);
        List<Object> mine = list(carol2.get("/api/user/access-requests").get("requests"));
        check("carol sees her request as DENIED", mine.size() == 1 && "DENIED".equals(m(mine.get(0)).get("status")), mine);

        step("OWNERSHIP DISPUTE: false claims are recorded, owner alerted, repeat offender blocked (extension)");
        check("mallory's first false claim (above) was recorded as FALSE_CLAIM 1/3",
                "FALSE_CLAIM".equals(t2.get("status")) && ((Number) t2.get("falseClaims")).intValue() == 1, t2);
        List<Object> aliceAlerts = list(alice.get("/api/owner/alerts").get("alerts"));
        Map<String, Object> claimAlert = null;
        for (Object o : aliceAlerts) if ("FALSE_OWNERSHIP_CLAIM".equals(m(o).get("type"))) claimAlert = m(o);
        check("alice got a FALSE_OWNERSHIP_CLAIM alert naming mallory", claimAlert != null
                && "mallory".equals(claimAlert.get("identifiedUserId")), aliceAlerts);
        Map<String, Object> f2 = attacker.post("/api/ownership/claim", map("documentId", hbId, "reason", "I wrote it"));
        check("second false claim: 2/3, not blocked", "FALSE_CLAIM".equals(f2.get("status"))
                && ((Number) f2.get("falseClaims")).intValue() == 2 && Boolean.FALSE.equals(f2.get("blocked")), f2);
        Map<String, Object> f3 = attacker.post("/api/ownership/claim", map("documentId", hbId));
        check("third false claim: 3/3, claimant now blocked", "FALSE_CLAIM".equals(f3.get("status"))
                && Boolean.TRUE.equals(f3.get("blocked")), f3);
        Map<String, Object> f4 = attacker.post("/api/ownership/claim", map("documentId", salaryId));
        check("fourth claim refused before Trace (BLOCKED)", "BLOCKED".equals(f4.get("status"))
                && Boolean.FALSE.equals(f4.get("valid")), f4);
        Map<String, Object> cl = alice.get("/api/ownership/claims");
        int againstAlice = list(cl.get("claimsOnMyDocuments")).size();
        check("alice sees all 5 claims on her documents (1 own + 3 false + 1 blocked)", againstAlice == 5, cl);
        boolean reasonShown = false;
        for (Object o : list(cl.get("claimsOnMyDocuments"))) if ("I wrote it".equals(m(o).get("reason"))) reasonShown = true;
        check("the claimant's stated reason is shown to the owner", reasonShown, cl);
        int claimAlerts = 0;
        for (Object o : list(alice.get("/api/owner/alerts").get("alerts")))
            if ("FALSE_OWNERSHIP_CLAIM".equals(m(o).get("type"))) claimAlerts++;
        check("3 false-claim alerts (blocked attempt raises none)", claimAlerts == 3, claimAlerts);
        Map<String, Object> ok2 = alice.post("/api/ownership/claim", map("documentId", hbId));
        check("the real owner is never blocked", "VERIFIED".equals(ok2.get("status")), ok2);

        step("PERMISSIONS + MAKER-CHECKER: view / download / modify, owner approves changes (extension)");
        String original = "Travel rules\nDaily limit: 2000\nApproval: manager\n";
        Map<String, Object> up4 = alice.post("/api/owner/documents", map(
                "fileName", "rules.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString(original.getBytes(StandardCharsets.UTF_8)),
                "keywords", "rules", "allowedRoles", List.of("Employee"), "requireApproval", true));
        String rulesId = (String) up4.get("documentId");
        Map<String, Object> q1 = carol2.post("/api/user/search", map("keyword", "rules"));
        check("carol's search creates an access request", list(q1.get("matches")).isEmpty(), q1);
        String rulesReq = null;
        for (Object o : list(alice.get("/api/owner/access-requests").get("requests"))) {
            if (rulesId.equals(m(o).get("documentId"))) rulesReq = (String) m(o).get("requestId");
        }
        Map<String, Object> g1 = alice.post("/api/owner/access-requests/" + rulesReq + "/approve",
                map("permissions", List.of("VIEW")));
        check("alice grants VIEW only", list(g1.get("permissions")).equals(List.of("VIEW")), g1);
        Map<String, Object> q2 = carol2.post("/api/user/search", map("keyword", "rules"));
        String sid2 = (String) q2.get("searchId");
        check("search result carries carol's permissions", list(q2.get("matches")).size() == 1
                && list(m(list(q2.get("matches")).get(0)).get("permissions")).equals(List.of("VIEW")), q2);
        Map<String, Object> v1 = carol2.get("/api/user/documents/" + rulesId + "/view?searchId=" + sid2);
        check("VIEW: carol reads the text in the browser", "text".equals(v1.get("kind"))
                && same(original, (String) v1.get("text")), v1);
        Map<String, Object> v1b = carol2.get("/api/user/documents/" + rulesId + "/view?searchId=" + sid2);
        check("VIEW works twice within the same search", same(original, (String) v1b.get("text")), v1b);
        Map<String, Object> dl = carol2.get("/api/user/documents/" + rulesId + "/download?searchId=" + sid2);
        check("DOWNLOAD refused without permission", (int) dl.get("_status") == 403, dl);
        Map<String, Object> pr0 = carol2.post("/api/user/documents/" + rulesId + "/changes",
                map("searchId", sid2, "text", "x", "note", "try"));
        check("MODIFY refused without permission", (int) pr0.get("_status") == 403, pr0);

        Map<String, Object> g2 = alice.post("/api/owner/access-requests/" + rulesReq + "/approve",
                map("permissions", List.of("DOWNLOAD", "MODIFY")));
        check("alice changes permissions to download + modify (view implied)",
                list(g2.get("permissions")).equals(List.of("VIEW", "DOWNLOAD", "MODIFY")), g2);
        Map<String, Object> q3 = carol2.post("/api/user/search", map("keyword", "rules"));
        String sid3 = (String) q3.get("searchId");
        String edited = "Travel rules\nDaily limit: 20000\nApproval: manager\n";
        Map<String, Object> pr1 = carol2.post("/api/user/documents/" + rulesId + "/changes",
                map("searchId", sid3, "text", edited, "note", "Raised the daily limit"));
        check("MAKER: carol proposes a change -> version 2 PENDING", "PENDING".equals(pr1.get("status"))
                && ((Number) pr1.get("version")).intValue() == 2, pr1);
        byte[] stillOld = carol2.raw("/api/user/documents/" + rulesId + "/download?searchId=" + sid3);
        check("before approval everyone still gets the original", same(new String(stillOld, StandardCharsets.UTF_8), original),
                new String(stillOld));
        List<Object> ch = list(alice.get("/api/owner/changes").get("changes"));
        check("CHECKER: alice sees the pending change", ch.size() == 1 && "PENDING".equals(m(ch.get(0)).get("status"))
                && "carol".equals(m(ch.get(0)).get("proposedBy")), ch);
        Map<String, Object> det = alice.get("/api/owner/changes/" + rulesId + "/2");
        boolean removedOld = false, addedNew = false;
        for (Object o : list(det.get("lines"))) {
            if ("removed".equals(m(o).get("type")) && "Daily limit: 2000".equals(m(o).get("text"))) removedOld = true;
            if ("added".equals(m(o).get("type")) && "Daily limit: 20000".equals(m(o).get("text"))) addedNew = true;
        }
        check("alice sees exactly what changed (line diff)", removedOld && addedNew, det);
        Map<String, Object> ap = alice.post("/api/owner/changes/" + rulesId + "/2/approve", map("comment", "ok"));
        check("alice approves -> version 2 is current", ((Number) ap.get("currentVersion")).intValue() == 2, ap);
        Map<String, Object> twice = alice.post("/api/owner/changes/" + rulesId + "/2/approve", map());
        check("a decided change cannot be decided twice", (int) twice.get("_status") == 409, twice);
        Map<String, Object> q4 = carol2.post("/api/user/search", map("keyword", "rules"));
        Map<String, Object> v2 = carol2.get("/api/user/documents/" + rulesId + "/view?searchId=" + q4.get("searchId"));
        check("after approval users get version 2", same(edited, (String) v2.get("text"))
                && ((Number) v2.get("version")).intValue() == 2, v2);
        Map<String, Object> pr2 = carol2.post("/api/user/documents/" + rulesId + "/changes",
                map("searchId", q4.get("searchId"), "text", "deleted everything", "note", "cleanup"));
        Map<String, Object> rj = alice.post("/api/owner/changes/" + rulesId + "/" + pr2.get("version") + "/reject",
                map("comment", "important information removed"));
        check("alice rejects a harmful change; version 2 stays current", "REJECTED".equals(rj.get("status"))
                && ((Number) rj.get("currentVersion")).intValue() == 2, rj);
        byte[] orig = alice.raw("/api/owner/documents/" + rulesId + "/download?version=1");
        check("owner can always download the ORIGINAL version", new String(orig, StandardCharsets.UTF_8).equals(original),
                new String(orig));
        Map<String, Object> hist = alice.get("/api/owner/documents/" + rulesId + "/history");
        Set<String> actions = new HashSet<>();
        for (Object o : list(hist.get("log"))) actions.add((String) m(o).get("action"));
        check("history keeps 3 versions", list(hist.get("versions")).size() == 3, hist);
        check("access log records who viewed / proposed / approved / rejected",
                actions.containsAll(List.of("ACCESS_GRANTED", "VIEWED", "CHANGE_PROPOSED", "CHANGE_APPROVED",
                        "CHANGE_REJECTED", "OWNER_DOWNLOADED")), actions);
        List<Object> mineCh = list(carol2.get("/api/user/changes").get("changes"));
        check("carol sees her 2 proposals and their outcome", mineCh.size() == 2, mineCh);

        step("LEAK TRACING: unique copy per download, hidden code + wording variations (extension)");
        String memo = "Subject: Q3 travel budget\n"
                + "Daily limit: 2000 per day for all staff.\n"
                + "Please don't book flights after 15-09-2026.\n"
                + "The hotel allowance is 4500 per night, approximately.\n"
                + "We cannot reimburse more than 12000 per trip.\n"
                + "It is the colour of the form that matters: blue for domestic.\n"
                + "I am available on 20-09-2026 for questions.\n"
                + "Kindly check the centre notice board; the total budget is 250000.\n";
        Map<String, Object> um = alice.post("/api/owner/documents", map(
                "fileName", "memo.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString(memo.getBytes(StandardCharsets.UTF_8)),
                "keywords", "memo", "policy", "Employee OR Finance"));
        String memoId = (String) um.get("documentId");
        check("memo.txt uploaded with leak tracing and enough change points", Boolean.TRUE.equals(um.get("leakTracing"))
                && ((Number) um.get("changePoints")).intValue() >= 12 && um.get("leakTracingWarning") == null, um);
        Client mal = new Client("mallory");
        mal.login("password-mallory", "user");
        Map<String, Object> ms1 = carol2.post("/api/user/search", map("keyword", "memo"));
        String c1 = new String(carol2.raw("/api/user/documents/" + memoId + "/download?searchId=" + ms1.get("searchId")), StandardCharsets.UTF_8);
        Map<String, Object> ms2 = carol2.post("/api/user/search", map("keyword", "memo"));
        String c2 = new String(carol2.raw("/api/user/documents/" + memoId + "/download?searchId=" + ms2.get("searchId")), StandardCharsets.UTF_8);
        Map<String, Object> ms3 = mal.post("/api/user/search", map("keyword", "memo"));
        String m1 = new String(mal.raw("/api/user/documents/" + memoId + "/download?searchId=" + ms3.get("searchId")), StandardCharsets.UTF_8);
        check("every download is a different copy with the same meaning", !c1.equals(c2) && !c1.equals(m1)
                && same(c1, memo) && same(c2, memo) && same(m1, memo), c1 + "\n---\n" + c2);
        check("visible wording differs between copies", !minos.server.Watermark.strip(c1).equals(minos.server.Watermark.strip(c2)), c1);
        check("each copy carries the hidden code", minos.server.Watermark.containsMarks(c1)
                && minos.server.Watermark.containsMarks(m1), "");
        byte[] ownCopy = alice.raw("/api/owner/documents/" + memoId + "/download");
        check("the owner's own download is the exact original", new String(ownCopy, StandardCharsets.UTF_8).equals(memo), "");

        Map<String, Object> lk1 = alice.post("/api/owner/leak-check", map("text", c1));
        check("forwarded file: hidden code names carol exactly", "EXACT".equals(lk1.get("verdict"))
                && "carol".equals(m(list(lk1.get("exactMatches")).get(0)).get("userId")), lk1);
        String[] mallLines = m1.split("\n");
        String copied = mallLines[3] + "\n" + mallLines[4];
        Map<String, Object> lk2 = alice.post("/api/owner/leak-check", map("text", copied));
        check("two copied lines (hidden code kept): names mallory exactly", "EXACT".equals(lk2.get("verdict"))
                && "mallory".equals(m(list(lk2.get("exactMatches")).get(0)).get("userId")), lk2);
        String[] c2Lines = minos.server.Watermark.strip(c2).split("\n");
        String typed = c2Lines[1] + "\n" + c2Lines[2] + "\n" + c2Lines[4] + "\n" + c2Lines[7];
        Map<String, Object> lk3 = alice.post("/api/owner/leak-check", map("text", typed));
        String c2Id = null;
        for (Object o : list(alice.get("/api/owner/documents/" + memoId + "/copies").get("copies"))) {
            if ("carol".equals(m(o).get("userId")) && c2Id == null) c2Id = (String) m(o).get("copyId");
        }
        check("screenshot / printout (lines typed in, no hidden code): wording names carol's 2nd download",
                "WORDING_UNIQUE".equals(lk3.get("verdict"))
                        && c2Id.equals(m(list(lk3.get("wordingMatches")).get(0)).get("copyId")), lk3);
        List<Object> rank3 = list(lk3.get("ranking"));
        check("ranking: carol's 2nd copy first at 100%, every other copy lower", rank3.size() >= 3
                && c2Id.equals(m(rank3.get(0)).get("copyId")) && ((Number) m(rank3.get(0)).get("percent")).doubleValue() == 100.0
                && ((Number) m(rank3.get(1)).get("percent")).doubleValue() < 100.0, rank3);
        Map<String, Object> md1 = m(lk1.get("modifications"));
        check("unchanged leak: no lines added or removed (per-copy differences ignored)", Boolean.TRUE.equals(md1.get("compared"))
                && ((Number) md1.get("linesRemoved")).intValue() == 0 && ((Number) md1.get("linesAdded")).intValue() == 0, md1);
        String editedLeak = minos.server.Watermark.strip(c2).replace("4,500", "9500").replace("4500", "9500")
                .replace(" for all staff", "");
        String[] editedLines = editedLeak.split("\n");
        String withoutFirstLines = String.join("\n", java.util.Arrays.copyOfRange(editedLines, 2, editedLines.length));
        Map<String, Object> lk7 = alice.post("/api/owner/leak-check", map("text", withoutFirstLines));
        Map<String, Object> md7 = m(lk7.get("modifications"));
        boolean removedAmount = false, addedAmount = false, removedFirst = false;
        for (Object o : list(md7.get("rows"))) {
            String type = String.valueOf(m(o).get("type")), text = String.valueOf(m(o).get("text"));
            if (type.equals("removed") && text.contains("4500")) removedAmount = true;
            if (type.equals("added") && text.contains("9500")) addedAmount = true;
            if (type.equals("removed") && text.startsWith("Subject: Q3 travel budget")) removedFirst = true;
        }
        check("edited leak (first 2 lines deleted, an amount and words changed): still carol; red/green lines shown",
                "carol".equals(m(list(lk7.get("wordingMatches")).get(0)).get("userId")) && removedAmount && addedAmount && removedFirst
                        && ((Number) md7.get("linesRemoved")).intValue() == 3 && ((Number) md7.get("linesAdded")).intValue() == 1, md7);
        // flip one space/tab inside the hidden code of the first line
        int flipAt = c1.indexOf('\n') - 5;
        String tamperedCopy = c1.substring(0, flipAt) + (c1.charAt(flipAt) == ' ' ? '\t' : ' ') + c1.substring(flipAt + 1);
        Map<String, Object> lk4 = alice.post("/api/owner/leak-check", map("text", tamperedCopy));
        check("an altered hidden code is reported, never blamed on another user", ((Number) lk4.get("alteredMarks")).intValue() >= 1
                && "carol".equals(m(list(lk4.get("exactMatches")).get(0)).get("userId")), lk4);
        Map<String, Object> lk5 = alice.post("/api/owner/leak-check", map("text", "Completely unrelated text 777 here."));
        check("unrelated text: nothing found", "NOT_FOUND".equals(lk5.get("verdict")), lk5);
        Map<String, Object> lk6 = mal.post("/api/owner/leak-check", map("text", c1));
        check("only owners can run the leak check", (int) lk6.get("_status") == 403, lk6);

        Map<String, Object> plainUp = alice.post("/api/owner/documents", map(
                "fileName", "contract.txt", "contentType", "text/plain",
                "dataBase64", Base64.getEncoder().encodeToString("Fee: 5000 per month.\n".getBytes(StandardCharsets.UTF_8)),
                "keywords", "contract", "policy", "Employee", "leakTracing", false));
        Map<String, Object> cs = carol2.post("/api/user/search", map("keyword", "contract"));
        String contract = new String(carol2.raw("/api/user/documents/" + plainUp.get("documentId") + "/download?searchId="
                + cs.get("searchId")), StandardCharsets.UTF_8);
        check("owner switched tracing off: download is the exact original", contract.equals("Fee: 5000 per month.\n"), contract);

        Map<String, Object> ev1 = carol2.post("/api/user/documents/" + memoId + "/view-event", map("event", "COPY_ATTEMPT"));
        carol2.post("/api/user/documents/" + memoId + "/view-event", map("event", "COPY_ATTEMPT"));
        Map<String, Object> ev2 = carol2.post("/api/user/documents/" + memoId + "/view-event", map("event", "WINDOW_LEFT"));
        carol2.post("/api/user/documents/" + memoId + "/view-event", map("event", "PRINT_SCREEN"));
        int viewAlerts = 0, copyCount = 0;
        for (Object o : list(alice.get("/api/owner/alerts").get("alerts"))) {
            if ("VIEW_PROTECTION".equals(m(o).get("type")) && "carol".equals(m(o).get("userId"))) {
                viewAlerts++;
                if ("COPY_ATTEMPT".equals(m(o).get("event"))) copyCount = ((Number) m(o).get("count")).intValue();
            }
        }
        check("copy and Print Screen attempts alert the owner (repeats grouped); leaving the window only logs",
                Boolean.TRUE.equals(ev1.get("alert")) && Boolean.FALSE.equals(ev2.get("alert"))
                        && viewAlerts == 2 && copyCount == 2, viewAlerts + " " + copyCount);
        int unseenBefore = ((Number) alice.get("/api/owner/alerts").get("unseen")).intValue();
        alice.post("/api/owner/alerts/seen", map());
        int unseenAfter = ((Number) alice.get("/api/owner/alerts").get("unseen")).intValue();
        carol2.post("/api/user/documents/" + memoId + "/view-event", map("event", "COPY_ATTEMPT"));
        int unseenRepeat = ((Number) alice.get("/api/owner/alerts").get("unseen")).intValue();
        check("alert number: cleared after the owner opens the alerts, back to 1 when an alert repeats",
                unseenBefore > 0 && unseenAfter == 0 && unseenRepeat == 1, unseenBefore + " " + unseenAfter + " " + unseenRepeat);
        boolean viewInRanking = false;
        for (Object o : list(alice.post("/api/owner/leak-check", map("text", typed)).get("ranking"))) {
            if ("VIEW".equals(m(o).get("channel"))) viewInRanking = true;
        }
        check("Find the leaker table lists downloaded copies only", !viewInRanking, "");

        Map<String, Object> rs = carol2.post("/api/user/search", map("keyword", "rules"));
        Map<String, Object> rview = carol2.get("/api/user/documents/" + rulesId + "/view?searchId=" + rs.get("searchId"));
        String viewed = (String) rview.get("text");
        Map<String, Object> pr3 = carol2.post("/api/user/documents/" + rulesId + "/changes", map("searchId", rs.get("searchId"),
                "text", viewed.replace("Approval: manager", "Approval: director"), "note", "New approver"));
        Map<String, Object> det3 = alice.get("/api/owner/changes/" + rulesId + "/" + pr3.get("version"));
        int removed = 0, added = 0;
        for (Object o : list(det3.get("lines"))) {
            if ("removed".equals(m(o).get("type"))) removed++;
            if ("added".equals(m(o).get("type"))) added++;
        }
        check("editing a traceable copy: only the real change reaches the owner (variations and hidden code removed)",
                removed == 1 && added == 1, det3.get("lines"));
    }

    /** Same content, ignoring the per-copy variations and hidden leak-tracing code. */
    static boolean same(String a, String b) {
        return minos.server.TextVariation.canonicalText(a).equals(minos.server.TextVariation.canonicalText(b));
    }

    static void phase2() throws Exception {
        Client anon = new Client("anon");
        step("AFTER RESTART of both servers");
        Map<String, Object> st = anon.get("/api/status");
        check("still initialized (mpk loaded, not regenerated)", Boolean.TRUE.equals(st.get("initialized")), st);
        check("4 users and 6 documents persisted", ((Number) st.get("users")).intValue() == 4
                && ((Number) st.get("documents")).intValue() == 6, st);
        Map<String, Object> csp = m(st.get("csp"));
        check("CSP storage persisted (6 documents + 3 proposed versions)", ((Number) csp.get("encryptedIndexes")).intValue() == 6
                && ((Number) csp.get("encryptedDocuments")).intValue() == 9
                && ((Number) csp.get("alerts")).intValue() == 5, csp);

        Client alice = new Client("alice");
        alice.login("password-alice", "owner");
        Map<String, Object> al = alice.get("/api/owner/alerts");
        int reuse = 0, claimAl = 0, viewAl = 0;
        boolean idsOk = true;
        for (Object o : list(al.get("alerts"))) {
            Map<String, Object> a = m(o);
            if ("VIEW_PROTECTION".equals(a.get("type"))) { viewAl++; continue; }
            if ("FALSE_OWNERSHIP_CLAIM".equals(a.get("type"))) { claimAl++; idsOk &= "mallory".equals(a.get("identifiedUserId")); }
            else { reuse++; idsOk &= "bob".equals(a.get("identifiedUserId")); }
        }
        check("alerts persisted: 2 trapdoor-reuse (bob) + 3 false-claim (mallory)", reuse == 2 && claimAl == 3 && viewAl == 2 && idsOk, al);
        List<Object> reqs = list(alice.get("/api/owner/access-requests").get("requests"));
        boolean handbookDenied = false, rulesApproved = false;
        for (Object o : reqs) {
            if ("handbook.txt".equals(m(o).get("fileName"))) handbookDenied = "DENIED".equals(m(o).get("status"));
            if ("rules.txt".equals(m(o).get("fileName"))) rulesApproved = "APPROVED".equals(m(o).get("status"))
                    && list(m(o).get("permissions")).contains("MODIFY");
        }
        check("access decisions and permissions persisted", reqs.size() == 2 && handbookDenied && rulesApproved, reqs);
        Map<String, Object> rev = alice.get("/api/owner/revocations");
        check("revocation persisted", list(rev.get("revocations")).size() == 1, rev);

        Client bob = new Client("bob");
        bob.login("password-bob", "user");
        check("bob still denied after restart", Boolean.TRUE.equals(bob.post("/api/user/search", map("keyword", "salary")).get("accessDenied")), "");

        Client mallory = new Client("mallory");
        mallory.login("password-mallory", "owner");
        Map<String, Object> claim = mallory.post("/api/ownership/claim", map(
                "documentId", m(list(alice.get("/api/owner/documents").get("documents")).get(0)).get("documentId"),
                "keyword", "salary"));
        check("after restart mallory is still blocked from claims", Boolean.FALSE.equals(claim.get("valid"))
                && "BLOCKED".equals(claim.get("status")), claim);

        String rulesDoc = null;
        for (Object o : list(alice.get("/api/owner/documents").get("documents"))) {
            if ("rules.txt".equals(m(o).get("fileName"))) rulesDoc = (String) m(o).get("documentId");
        }
        Map<String, Object> hist = alice.get("/api/owner/documents/" + rulesDoc + "/history");
        byte[] orig = alice.raw("/api/owner/documents/" + rulesDoc + "/download?version=1");
        check("versions, decisions and original survive restart", ((Number) hist.get("currentVersion")).intValue() == 2
                && list(hist.get("versions")).size() == 4
                && new String(orig, StandardCharsets.UTF_8).startsWith("Travel rules\nDaily limit: 2000\n"), hist);
        String memoDoc = null;
        for (Object o : list(alice.get("/api/owner/documents").get("documents"))) {
            if ("memo.txt".equals(m(o).get("fileName"))) memoDoc = (String) m(o).get("documentId");
        }
        Client mal2 = new Client("mallory");
        mal2.login("password-mallory", "user");
        Map<String, Object> msr = mal2.post("/api/user/search", map("keyword", "memo"));
        String mcopy = new String(mal2.raw("/api/user/documents/" + memoDoc + "/download?searchId=" + msr.get("searchId")),
                StandardCharsets.UTF_8);
        String screenshotText = minos.server.Watermark.strip(mcopy).split("\n")[4] + "\n"
                + minos.server.Watermark.strip(mcopy).split("\n")[7];
        Map<String, Object> lkr = alice.post("/api/owner/leak-check", map("text", screenshotText));
        boolean malFound = false;
        for (Object o : list(lkr.get("wordingMatches"))) if ("mallory".equals(m(o).get("userId"))) malFound = true;
        Map<String, Object> lkr2 = alice.post("/api/owner/leak-check", map("text", mcopy));
        check("after restart: copies, hidden-code key and records persist; leaks still traced",
                malFound && "EXACT".equals(lkr2.get("verdict"))
                        && "mallory".equals(m(list(lkr2.get("exactMatches")).get(0)).get("userId")), lkr + " " + lkr2);
        Map<String, Object> rs = alice.post("/api/owner/revocations/remove", map("userId", "bob"));
        check("owner restores bob", "bob".equals(rs.get("restored")), rs);
        Map<String, Object> s = bob.post("/api/user/search", map("keyword", "payroll"));
        check("bob can search twice after restore (new trapdoor, persisted mpk/keys)",
                list(s.get("matches")).size() == 1, s);
        String id = (String) m(list(s.get("matches")).get(0)).get("documentId");
        byte[] body = bob.raw("/api/user/documents/" + id + "/download?searchId=" + s.get("searchId"));
        check("document decrypts after restart", new String(body, StandardCharsets.UTF_8).startsWith("CONFIDENTIAL"), new String(body));
    }
}
