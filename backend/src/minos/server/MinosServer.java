package minos.server;

import minos.common.CryptoUtil;
import minos.common.Http;
import minos.common.Http.ApiException;
import minos.common.Http.Request;
import minos.common.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * MINOS SERVER (default http://localhost:8080)
 *
 * Browser JavaScript  --HTTP/JSON-->  this server  --HTTP/JSON-->  CSP server
 *
 * Serves the web application (frontend/) and the /api endpoints. Every
 * important button in the UI calls one of these endpoints, which run the
 * Java Minos algorithms in MinosService.
 */
public final class MinosServer {

    private static final String COOKIE = "MINOS_SESSION";
    private static final long SESSION_TTL = 8 * 3600 * 1000L;

    private final MinosService service;
    private final Map<String, Map<String, Object>> sessions = new ConcurrentHashMap<>();
    private volatile String linkKeyCache;
    private final Path dataDir;

    public MinosServer(MinosService service, Path dataDir) {
        this.service = service;
        this.dataDir = dataDir;
    }

    // ---------------------------------------------------------------
    // Session handling
    // ---------------------------------------------------------------

    private Map<String, Object> session(Request r) {
        String token = r.cookie(COOKIE);
        Map<String, Object> s = token == null ? null : sessions.get(token);
        if (s == null || ((Number) s.get("expires")).longValue() < System.currentTimeMillis()) {
            if (token != null) sessions.remove(token);
            throw new ApiException(401, "Please log in");
        }
        r.attachment = s;
        return s;
    }

    private String uid(Request r) {
        return (String) session(r).get("userId");
    }

    private void requireOwnerRole(Request r) {
        if (!"owner".equals(session(r).get("actingAs"))) {
            throw new ApiException(403, "Switch to the Data Owner role for this action");
        }
    }

    private void requireUserRole(Request r) {
        if (!"user".equals(session(r).get("actingAs"))) {
            throw new ApiException(403, "Switch to the Data User role for this action");
        }
    }

    private void requireLink(Request r) throws Exception {
        if (linkKeyCache == null) {
            Path f = dataDir.resolve("config").resolve("server.json");
            if (Files.exists(f)) {
                Object k = ((Map<?, ?>) Json.parse(Files.readString(f))).get("linkKey");
                linkKeyCache = k == null ? null : k.toString();
            }
        }
        String given = r.header("X-Minos-Link");
        if (linkKeyCache == null || given == null || !CryptoUtil.constantTimeEquals(
                given.getBytes(StandardCharsets.UTF_8), linkKeyCache.getBytes(StandardCharsets.UTF_8))) {
            throw new ApiException(401, "Invalid server link key");
        }
    }

    private Map<String, Object> me(Request r) {
        Map<String, Object> s = session(r);
        Map<String, Object> u = service.publicUser(service.user((String) s.get("userId")));
        u.put("actingAs", s.get("actingAs"));
        return u;
    }

    // ---------------------------------------------------------------
    // Routes
    // ---------------------------------------------------------------

    public Http.Router router(Path webRoot) {
        Http.Filter owner = this::requireOwnerRole;
        Http.Filter user = this::requireUserRole;
        Http.Filter link = this::requireLink;

        return new Http.Router("MINOS")
                // ---------- system ----------
                .get("/api/status", r -> service.status())
                .post("/api/setup", r -> {
                    List<String> attrs = new ArrayList<>();
                    for (Object o : r.list("attributes")) attrs.add(String.valueOf(o));
                    return service.setup(attrs);
                })
                .post("/api/register", r -> {
                    List<String> attrs = new ArrayList<>();
                    for (Object o : r.list("attributes")) attrs.add(String.valueOf(o));
                    return service.register(r.str("userId").trim(), r.optStr("displayName", ""),
                            r.str("password"), attrs);
                })
                .post("/api/login", this::login)
                .post("/api/logout", r -> {
                    String t = r.cookie(COOKIE);
                    if (t != null) sessions.remove(t);
                    return Http.Response.json(200, Http.map("success", true))
                            .header("Set-Cookie", COOKIE + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                })
                .get("/api/me", r -> Http.map("user", me(r)))
                .post("/api/me/role", r -> {
                    String role = r.str("actingAs");
                    if (!role.equals("owner") && !role.equals("user")) throw new ApiException(400, "owner or user");
                    session(r).put("actingAs", role);
                    return Http.map("user", me(r));
                })
                .get("/api/access-info", r -> service.accessInfo(uid(r)))
                .get("/api/users", r -> {
                    session(r);
                    return Http.map("users", service.usersList());
                })
                .get("/api/documents", r -> {
                    session(r);
                    return Http.map("documents", service.documentsOf(null));
                })
                .post("/api/ownership/claim", r -> service.claimOwnership(uid(r), r.str("documentId"),
                        r.optStr("keyword", ""), r.optStr("reason", "")))
                .get("/api/ownership/claims", r -> service.ownershipClaims(uid(r)))
                .get("/api/logs", r -> {
                    session(r);
                    Map<String, Object> out = service.cspLogs();
                    out.put("audit", service.auditLog(60));
                    return out;
                })

                // ---------- data owner ----------
                .post("/api/owner/documents", r -> {
                    List<String> roles = new ArrayList<>();
                    for (Object o : r.list("allowedRoles")) roles.add(String.valueOf(o));
                    return service.upload(uid(r), r.str("fileName"), r.optStr("contentType", ""),
                            CryptoUtil.unb64(r.str("dataBase64")), r.optStr("keywords", ""),
                            roles, r.optStr("policy", ""),
                            Boolean.TRUE.equals(r.json().get("requireApproval")),
                            !Boolean.FALSE.equals(r.json().get("leakTracing")));
                }, owner)
                .get("/api/owner/documents", r -> Http.map("documents", service.documentsOf(uid(r))), owner)
                .get("/api/owner/documents/{id}/download", r -> download(service.ownerDownload(uid(r), r.params.get("id"),
                        intQuery(r, "version", 0))), owner)
                .get("/api/owner/documents/{id}/history", r -> service.documentHistory(uid(r), r.params.get("id")), owner)
                .get("/api/owner/changes", r -> service.ownerChanges(uid(r)), owner)
                .post("/api/owner/leak-check", r -> service.traceLeak(uid(r), r.optStr("text", "")), owner)
                .get("/api/owner/documents/{id}/copies", r -> service.issuedCopies(uid(r), r.params.get("id")), owner)
                .get("/api/owner/document-log", r -> service.ownerDocumentLog(uid(r)), owner)
                .get("/api/owner/changes/{id}/{version}", r -> service.changeDetails(uid(r), r.params.get("id"),
                        Integer.parseInt(r.params.get("version"))), owner)
                .post("/api/owner/changes/{id}/{version}/approve", r -> service.decideChange(uid(r), r.params.get("id"),
                        Integer.parseInt(r.params.get("version")), true, r.optStr("comment", "")), owner)
                .post("/api/owner/changes/{id}/{version}/reject", r -> service.decideChange(uid(r), r.params.get("id"),
                        Integer.parseInt(r.params.get("version")), false, r.optStr("comment", "")), owner)
                .get("/api/owner/alerts", r -> service.ownerAlerts(uid(r)), owner)
                .post("/api/owner/alerts/seen", r -> service.markAlertsSeen(uid(r)), owner)
                .post("/api/owner/alerts/{id}/detect", r -> service.runDetect(r.params.get("id")), owner)
                .get("/api/owner/revocations", r -> Http.map("revocations", service.revocationsOf(uid(r))), owner)
                .post("/api/owner/revocations", r -> service.revoke(uid(r), r.str("userId"), r.optStr("alertId", null)), owner)
                .post("/api/owner/revocations/remove", r -> service.restore(uid(r), r.str("userId")), owner)
                .get("/api/owner/activity", r -> service.ownerActivity(uid(r)), owner)
                .get("/api/owner/access-requests", r -> Http.map("requests", service.accessRequestsForOwner(uid(r))), owner)
                .post("/api/owner/access-requests/{id}/approve", r -> service.decideAccessRequest(uid(r), r.params.get("id"), true,
                        r.json().get("permissions") instanceof List ? r.list("permissions") : null), owner)
                .post("/api/owner/access-requests/{id}/deny", r -> service.decideAccessRequest(uid(r), r.params.get("id"), false), owner)

                // ---------- data user ----------
                .post("/api/user/search", r -> service.search(uid(r), r.optStr("keyword", "")), user)
                .get("/api/user/documents/{id}/download", r -> download(
                        service.retrieve(uid(r), r.query.getOrDefault("searchId", ""), r.params.get("id"))), user)
                .get("/api/user/documents/{id}/view", r -> service.view(
                        uid(r), r.query.getOrDefault("searchId", ""), r.params.get("id")), user)
                .post("/api/user/documents/{id}/changes", r -> service.proposeChange(uid(r), r.params.get("id"),
                        r.str("searchId"),
                        r.json().get("text") instanceof String ? (String) r.json().get("text") : null,
                        r.json().get("dataBase64") instanceof String ? CryptoUtil.unb64((String) r.json().get("dataBase64")) : null,
                        r.optStr("note", "")), user)
                .get("/api/user/changes", r -> service.userChanges(uid(r)), user)
                .post("/api/user/documents/{id}/view-event", r -> service.viewEvent(uid(r), r.params.get("id"),
                        r.optStr("event", "")), user)
                .get("/api/user/activity", r -> service.userActivity(uid(r)), user)
                .get("/api/user/access-requests", r -> Http.map("requests", service.accessRequestsForUser(uid(r))))
                .post("/api/security/submit-trapdoor", r -> service.submitTrapdoor(uid(r), r.map("envelope")))

                // ---------- CSP -> Minos callback ----------
                .post("/internal/csp/alert", r -> service.runDetect(r.str("alertId")), link)

                .staticFiles(webRoot);
    }

    private Object login(Request r) {
        Map<String, Object> u = service.login(r.str("userId").trim(), r.str("password"));
        String role = r.optStr("actingAs", "user");
        if (!role.equals("owner") && !role.equals("user")) role = "user";
        String token = CryptoUtil.randomId(32);
        sessions.put(token, Http.map("userId", u.get("userId"), "actingAs", role,
                "expires", System.currentTimeMillis() + SESSION_TTL));
        u.put("actingAs", role);
        return Http.Response.json(200, Http.map("success", true, "user", u))
                .header("Set-Cookie", COOKIE + "=" + token + "; Path=/; HttpOnly; SameSite=Strict");
    }

    private static int intQuery(Request r, String name, int fallback) {
        String v = r.query.get(name);
        if (v == null || v.isEmpty()) return fallback;
        try {
            return Integer.parseInt(v);
        } catch (NumberFormatException e) {
            throw new Http.ApiException(400, "Invalid " + name);
        }
    }

    private static Http.Response download(Map<String, Object> file) {
        String name = String.valueOf(file.get("fileName")).replaceAll("[^A-Za-z0-9._ -]", "_");
        return Http.Response.bytes((byte[]) file.get("bytes"), String.valueOf(file.get("contentType")))
                .header("Content-Disposition", "attachment; filename=\"" + name + "\"");
    }

    // ---------------------------------------------------------------
    // main
    // ---------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        int port = 8080;
        String cspUrl = "http://localhost:9090";
        Path data = Paths.get("backend/minos-data");
        Path web = Paths.get("frontend");
        for (String a : args) {
            if (a.startsWith("--port=")) port = Integer.parseInt(a.substring(7));
            if (a.startsWith("--csp=")) cspUrl = a.substring(6);
            if (a.startsWith("--data=")) data = Paths.get(a.substring(7));
            if (a.startsWith("--web=")) web = Paths.get(a.substring(6));
        }
        MinosService service = new MinosService(data, cspUrl, "http://localhost:" + port);
        MinosServer server = new MinosServer(service, data.toAbsolutePath());
        Http.start(port, server.router(web), 8);
        System.out.println("[MINOS] Minos server running at http://localhost:" + port);
        System.out.println("[MINOS] Data directory: " + data.toAbsolutePath());
        if (service.initialized()) {
            System.out.println("[MINOS] Existing public parameters (mpk) loaded - Setup is skipped.");
            System.out.println("[MINOS] " + service.syncCsp());
        } else {
            System.out.println("[MINOS] First run: open the web app and complete Setup.");
        }
    }
}
