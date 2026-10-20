package minos.csp;

import minos.common.BlobStore;
import minos.common.CryptoUtil;
import minos.common.Http;
import minos.common.Http.ApiException;
import minos.common.Http.Request;
import minos.common.Json;
import minos.common.JsonHttpClient;
import minos.common.JsonStore;
import minos.common.LocalBlobStore;
import minos.core.Codec;
import minos.core.MinosStorage;
import minos.core.Search;
import minos.core.Setup;
import minos.core.Trace;
import minos.core.TrapGen;
import minos.ext.SchnorrSignature;
import minos.ext.TrapdoorEnvelope;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CSP SERVER - the cloud service provider of the Minos system model
 * (paper Fig. 1). Honest-but-curious: it stores only ciphertexts, the
 * encrypted index L, public keys and metadata; it never receives a secret
 * key, a plaintext document, a raw AES key or a plaintext keyword.
 *
 * Minos algorithms executed here:
 *   Register, CSP side (Alg. 2 lines 5-6)      R.add(pk)        public-keys/
 *   Search (Alg. 7)                            /csp/api/search
 *   Detect, CSP side (Alg. 9 lines 3-4)        R[pk_c] <- tk3   /alerts/{id}/detect-result
 *   Trace (Alg. 10)                            /csp/api/trace
 *   Suspension of identities linked to tk3 (paper Section VI-A.4)
 *
 * Project extensions executed here: local storage (BlobStore, replaceable
 * by a cloud object store), trapdoor-use records, one-time trapdoors and
 * replay detection, security alerts, retrieval tickets, security logs.
 *
 * Storage layout (csp-storage/):
 *   encrypted-documents/<id>.bin   AES-GCM document ciphertext
 *   encrypted-index/<id>.json      Minos ciphertext L
 *   public-keys/<user>.json        registration list R
 *   metadata/                      params, documents, trapdoor records, alerts, suspensions
 *   logs/                          security.log, activity.log (JSON lines)
 */
public final class CspServer {

    private final BlobStore blobs;
    private final JsonStore store;
    private final Object lock = new Object();          // records / alerts / R
    private final Object crypto = new Object();        // JPBC operations
    private volatile Setup.PublicParameters mpk;
    private volatile Map<String, Object> link;
    private final Map<String, Map<String, Object>> tickets = new ConcurrentHashMap<>();

    private static final String PARAMS = "metadata/public-params.bin";
    private static final String LINK = "metadata/link.json";
    private static final String RECORDS = "metadata/trapdoor-records.json";
    private static final String ALERTS = "metadata/alerts.json";
    private static final String SUSPENSIONS = "metadata/suspensions.json";
    private static final String CLAIMS = "metadata/ownership-claims.json";
    /** Ownership disputes: this many false claims within CLAIM_WINDOW_MS blocks further claims. */
    static final int MAX_FALSE_CLAIMS = 3;
    static final long CLAIM_WINDOW_MS = 24L * 60 * 60 * 1000;
    private static final String SECURITY_LOG = "logs/security.log";
    private static final String ACTIVITY_LOG = "logs/activity.log";

    public CspServer(BlobStore blobs) throws Exception {
        this.blobs = blobs;
        this.store = new JsonStore(blobs);
        for (String dir : new String[]{"encrypted-documents", "encrypted-index", "public-keys", "metadata", "logs"}) {
            if (blobs instanceof LocalBlobStore) {
                Files.createDirectories(((LocalBlobStore) blobs).root().resolve(dir));
            }
        }
        if (blobs.exists(LINK)) link = store.readMap(LINK);
        if (blobs.exists(PARAMS)) {
            mpk = loadParams(blobs.get(PARAMS));
            System.out.println("[CSP] Loaded existing Minos public parameters (mpk).");
        }
    }

    // ================================================================
    // Routes
    // ================================================================

    public Http.Router router() {
        Http.Filter link = this::requireLink;
        Http.Filter ready = r -> requireParams();
        return new Http.Router("CSP")
                .get("/csp/api/health", r -> health())
                .post("/csp/api/admin/init", this::init)
                .post("/csp/api/registry/users", this::registerUser, link, ready)
                .get("/csp/api/registry/users", r -> Http.map("users", registry()))
                .post("/csp/api/documents", this::storeDocument, link, ready)
                .get("/csp/api/documents", r -> Http.map("documents", documentSummaries()))
                .post("/csp/api/search", this::search, ready)
                .post("/csp/api/documents/{id}/retrieve", this::retrieve)
                .post("/csp/api/documents/{id}/owner-retrieve", this::ownerRetrieve, link)
                .post("/csp/api/documents/{id}/versions", this::proposeVersion, link)
                .post("/csp/api/documents/{id}/versions/{version}/decision", this::decideVersion, link)
                .get("/csp/api/alerts", this::alerts, link)
                .get("/csp/api/alerts/{id}", this::alert, link)
                .post("/csp/api/alerts/{id}/detect-result", this::detectResult, link)
                .get("/csp/api/suspensions", this::suspensions, link)
                .post("/csp/api/suspensions", this::suspend, link)
                .post("/csp/api/suspensions/remove", this::unsuspend, link)
                .post("/csp/api/trace", this::trace, ready)
                .get("/csp/api/ownership-claims", this::claims, link)
                .get("/csp/api/trapdoor-records", this::records, link)
                .get("/csp/api/logs", r -> Http.map("events",
                        store.tailLog(SECURITY_LOG, intParam(r, "limit", 100))), link);
    }

    private void requireLink(Request r) {
        Map<String, Object> l = link;
        String given = r.header("X-Minos-Link");
        if (l == null || given == null || !CryptoUtil.constantTimeEquals(
                given.getBytes(StandardCharsets.UTF_8),
                String.valueOf(l.get("linkKey")).getBytes(StandardCharsets.UTF_8))) {
            throw new ApiException(401, "Missing or invalid server link key");
        }
    }

    private void requireParams() {
        if (mpk == null) throw new ApiException(409, "CSP has not received the Minos public parameters yet");
    }

    // ================================================================
    // Health / initialisation
    // ================================================================

    private Map<String, Object> health() {
        int docs = blobs.list("encrypted-documents/").size();
        return Http.map(
                "service", "Minos CSP",
                "initialized", mpk != null,
                "linked", link != null,
                "storage", blobs.describe(),
                "registeredUsers", blobs.list("public-keys/").size(),
                "encryptedDocuments", docs,
                "encryptedIndexes", blobs.list("encrypted-index/").size(),
                "trapdoorRecords", store.readList(RECORDS).size(),
                "alerts", store.readList(ALERTS).size());
    }

    /**
     * Receives mpk (the public output of Setup) and the server link key from
     * the Minos server. Accepted once; afterwards only the same mpk.
     */
    private Map<String, Object> init(Request r) throws Exception {
        byte[] params = CryptoUtil.unb64(r.str("publicParamsBase64"));
        synchronized (lock) {
            if (link != null) {
                requireLink(r);
                byte[] existing = blobs.get(PARAMS);
                if (existing != null && !java.util.Arrays.equals(existing, params)) {
                    throw new ApiException(409, "CSP already holds different public parameters");
                }
                return Http.map("alreadyInitialized", true);
            }
            Setup.PublicParameters loaded = loadParams(params);
            blobs.put(PARAMS, params);
            Map<String, Object> l = Http.map(
                    "linkKey", r.str("linkKey"),
                    "minosCallbackUrl", r.str("minosCallbackUrl"),
                    "linkedAt", now());
            store.write(LINK, l);
            link = l;
            mpk = loaded;
        }
        store.log(ACTIVITY_LOG, Http.map("event", "INIT", "detail", "Public parameters received"));
        return Http.map("initialized", true);
    }

    private static Setup.PublicParameters loadParams(byte[] bytes) throws Exception {
        Path tmp = Files.createTempFile("minos-mpk", ".bin");
        try {
            Files.write(tmp, bytes);
            return MinosStorage.load(tmp);
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    // ================================================================
    // Register (Algorithm 2, CSP side): R.add(pk)
    // ================================================================

    private Map<String, Object> registerUser(Request r) {
        String userId = r.str("userId");
        String pk = r.str("publicKey");
        if (!userId.matches("[A-Za-z0-9_.-]{3,32}")) throw new ApiException(400, "Invalid user id");
        synchronized (crypto) {
            try {
                Codec.g1(mpk, pk);
            } catch (RuntimeException e) {
                throw new ApiException(400, "Public key is not an element of G");
            }
        }
        synchronized (lock) {
            String key = "public-keys/" + userId + ".json";
            if (blobs.exists(key)) throw new ApiException(409, "User already registered at the CSP");
            for (Map<String, Object> u : registry()) {
                if (pk.equals(u.get("publicKey"))) throw new ApiException(409, "Public key already registered");
            }
            store.write(key, Http.map(
                    "userId", userId,
                    "publicKey", pk,
                    "displayName", r.optStr("displayName", userId),
                    "registeredAt", now(),
                    "status", "active",
                    "linkedTrapdoorTags", new ArrayList<>()));
        }
        store.log(ACTIVITY_LOG, Http.map("event", "REGISTER", "userId", userId,
                "publicKeyFingerprint", fingerprint(pk)));
        return Http.map("userId", userId, "registrationListSize", blobs.list("public-keys/").size());
    }

    private List<Map<String, Object>> registry() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String key : blobs.list("public-keys/")) out.add(store.readMap(key));
        return out;
    }

    // ================================================================
    // Encrypted document + encrypted index upload (output of Encrypt)
    // ================================================================

    private Map<String, Object> storeDocument(Request r) {
        String id = r.str("documentId");
        if (!id.matches("D-[a-f0-9]{16,40}")) throw new ApiException(400, "Invalid document id");
        List<Object> entries = r.list("indexEntries");
        if (entries.isEmpty()) throw new ApiException(400, "Encrypted index L is empty");
        for (Object e : entries) {
            Map<String, Object> m = Codec.map(e);
            if (!"attribute".equals(m.get("type")) && !"keyword".equals(m.get("type"))) {
                throw new ApiException(400, "Invalid index entry");
            }
            if (m.containsKey("keyword") || m.containsKey("w")) {
                throw new ApiException(400, "Plaintext keywords are not accepted by the CSP");
            }
        }
        byte[] sealed = CryptoUtil.unb64(r.str("encryptedDocumentBase64"));
        synchronized (lock) {
            if (blobs.exists("metadata/documents/" + id + ".json")) throw new ApiException(409, "Document exists");
            blobs.put("encrypted-documents/" + id + ".bin", sealed);
            store.write("encrypted-index/" + id + ".json", Http.map(
                    "documentId", id, "entries", entries));
            // metadata last: a document becomes visible only when complete
            store.write("metadata/documents/" + id + ".json", Http.map(
                    "documentId", id,
                    "ownerUserId", r.str("ownerUserId"),
                    "ownerPublicKey", r.str("ownerPublicKey"),
                    "wrappedFileKeyBase64", r.str("wrappedFileKeyBase64"),
                    "encryption", "AES-256-GCM (document), AES-256-GCM key wrap under HKDF(k)",
                    "sizeBytes", sealed.length,
                    "sha256", CryptoUtil.sha256Hex(sealed),
                    "indexEntries", entries.size(),
                    "uploadedAt", now()));
        }
        store.log(ACTIVITY_LOG, Http.map("event", "UPLOAD", "documentId", id,
                "ownerUserId", r.str("ownerUserId"), "bytes", sealed.length, "indexEntries", entries.size()));
        return Http.map("documentId", id, "storedBytes", sealed.length, "indexEntries", entries.size());
    }

    private List<Map<String, Object>> documentSummaries() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String key : blobs.list("metadata/documents/")) {
            Map<String, Object> m = store.readMap(key);
            m.remove("wrappedFileKeyBase64");
            m.remove("versions");
            out.add(m);
        }
        return out;
    }

    private Map<String, Object> documentMeta(String id) {
        if (!id.matches("D-[a-f0-9]{16,40}")) throw new ApiException(400, "Invalid document id");
        String key = "metadata/documents/" + id + ".json";
        if (!blobs.exists(key)) throw new ApiException(404, "Unknown document " + id);
        return store.readMap(key);
    }

    // ================================================================
    // Search (Algorithm 7) wrapped by one-time trapdoor processing
    // ================================================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> search(Request r) {
        Map<String, Object> env = r.map("envelope");
        String submittedBy = r.optStr("submittedBy", "anonymous");
        String documentId = String.valueOf(env.get("documentId"));
        Map<String, Object> meta = documentMeta(documentId);
        String ownerUserId = (String) meta.get("ownerUserId");

        TrapGen.Trapdoor T;
        String hash;
        String coreHash;
        synchronized (crypto) {
            try {
                T = TrapGen.Trapdoor.fromJson(mpk, Codec.map(env.get("trapdoor")));
            } catch (RuntimeException e) {
                logSecurity("TRAPDOOR_MALFORMED", documentId, ownerUserId, submittedBy, null, "Could not decode trapdoor");
                throw new ApiException(400, "Malformed trapdoor");
            }
            hash = TrapdoorEnvelope.trapdoorHash(T, env);
            coreHash = CryptoUtil.sha256Hex(T.canonicalBytes());
        }
        String nonce = String.valueOf(env.get("nonce"));
        String trapdoorId = String.valueOf(env.get("trapdoorId"));
        long now = System.currentTimeMillis();

        synchronized (lock) {
            List<Object> records = store.readList(RECORDS);

            // ---------- 1. one-time use: exact reuse ----------
            Map<String, Object> first = null;
            for (Object o : records) {
                Map<String, Object> rec = (Map<String, Object>) o;
                if (!"ACCEPTED".equals(rec.get("status"))) continue;
                if (hash.equals(rec.get("trapdoorHash"))
                        || (nonce.equals(rec.get("nonce")) && documentId.equals(rec.get("documentId")))) {
                    first = rec;
                    break;
                }
            }
            if (first != null) {
                Map<String, Object> alert = raiseAlert("TRAPDOOR_REUSE", "Trapdoor reuse detected",
                        first, env, hash, submittedBy, ownerUserId, documentId, now);
                records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now,
                        "REJECTED_REPLAY", T, alert.get("alertId")));
                store.write(RECORDS, records);
                logSecurity("TRAPDOOR_REPLAY_REJECTED", documentId, ownerUserId, submittedBy, hash,
                        "Trapdoor " + trapdoorId + " was already used at " + first.get("usedAt") + "; alert " + alert.get("alertId"));
                notifyMinos(String.valueOf(alert.get("alertId")));
                return rejection("REJECTED_REPLAY",
                        "Trapdoor reuse detected: this trapdoor was already used. Search refused and a security alert was raised.",
                        hash, trapdoorId, alert.get("alertId"));
            }

            // ---------- 2. envelope authenticity (owner signature) ----------
            boolean signatureOk;
            synchronized (crypto) {
                signatureOk = coreHash.equals(env.get("coreHash"))
                        && SchnorrSignature.verify(mpk, Codec.g1(mpk, (String) meta.get("ownerPublicKey")),
                        TrapdoorEnvelope.signedMessage(env),
                        String.valueOf(env.get("ownerSigR")), String.valueOf(env.get("ownerSigS")));
            }
            if (!signatureOk) {
                Map<String, Object> usedCore = null;
                for (Object o : records) {
                    Map<String, Object> rec = (Map<String, Object>) o;
                    if ("ACCEPTED".equals(rec.get("status")) && coreHash.equals(rec.get("coreHash"))) {
                        usedCore = rec;
                        break;
                    }
                }
                Object alertId = null;
                if (usedCore != null) {
                    // A used trapdoor re-submitted with a forged envelope (e.g. new nonce).
                    Map<String, Object> alert = raiseAlert("TRAPDOOR_REUSE",
                            "Trapdoor reuse detected (one-time envelope was modified to evade detection)",
                            usedCore, env, hash, submittedBy, ownerUserId, documentId, now);
                    alertId = alert.get("alertId");
                    notifyMinos(String.valueOf(alertId));
                }
                records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now,
                        "REJECTED_INVALID_ENVELOPE", T, alertId));
                store.write(RECORDS, records);
                logSecurity("TRAPDOOR_ENVELOPE_INVALID", documentId, ownerUserId, submittedBy, hash,
                        "Owner signature / core hash check failed" + (alertId != null ? "; matches a used trapdoor, alert " + alertId : ""));
                return rejection("REJECTED_INVALID_ENVELOPE",
                        "Trapdoor envelope is not authentic (owner signature check failed)" +
                                (alertId != null ? ". It is a modified copy of a used trapdoor: security alert raised." : "."),
                        hash, trapdoorId, alertId);
            }

            // ---------- 3. freshness ----------
            long expires = TrapdoorEnvelope.num(env.get("expiresAt"));
            if (now > expires) {
                records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now, "REJECTED_EXPIRED", T, null));
                store.write(RECORDS, records);
                logSecurity("TRAPDOOR_EXPIRED", documentId, ownerUserId, submittedBy, hash, "Envelope expired");
                return rejection("REJECTED_EXPIRED", "Trapdoor expired; generate a new one", hash, trapdoorId, null);
            }

            // ---------- 4. suspended identity (paper VI-A.4: R links tk3 to a suspended pk) ----------
            String tk3 = Codec.enc(T.tk3);
            for (Object o : store.readList(SUSPENSIONS)) {
                Map<String, Object> s = (Map<String, Object>) o;
                if (ownerUserId.equals(s.get("ownerUserId")) && tk3.equals(s.get("tk3"))) {
                    records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now, "REJECTED_SUSPENDED", T, null));
                    store.write(RECORDS, records);
                    logSecurity("TRAPDOOR_SUSPENDED_IDENTITY", documentId, ownerUserId, submittedBy, hash,
                            "tk3 is linked to suspended user " + s.get("userId"));
                    return rejection("REJECTED_SUSPENDED",
                            "The identity bound to this trapdoor has been suspended by the data owner", hash, trapdoorId, null);
                }
            }

            // ---------- 5. Minos trapdoor consistency (tk5, Section VI-D) ----------
            boolean consistent;
            synchronized (crypto) {
                consistent = Search.verifyTk5(mpk, T);
            }
            if (!consistent) {
                records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now, "REJECTED_INVALID_TRAPDOOR", T, null));
                store.write(RECORDS, records);
                logSecurity("TRAPDOOR_INCONSISTENT", documentId, ownerUserId, submittedBy, hash, "tk5 check failed");
                return rejection("REJECTED_INVALID_TRAPDOOR", "Trapdoor components are inconsistent (tk5 check)", hash, trapdoorId, null);
            }

            // ---------- 6. accept once ----------
            records.add(record(hash, coreHash, env, documentId, ownerUserId, submittedBy, now, "ACCEPTED", T, null));
            store.write(RECORDS, records);
        }

        // ---------- 7. Minos Search, Algorithm 7 ----------
        List<String> C;
        Map<String, Object> index = store.readMap("encrypted-index/" + documentId + ".json");
        List<Map<String, Object>> L = new ArrayList<>();
        for (Object e : Codec.list(index.get("entries"))) L.add(Codec.map(e));
        synchronized (crypto) {
            try {
                C = Search.search(mpk, L, T);
            } catch (IllegalArgumentException e) {
                C = new ArrayList<>();   // trapdoor rows do not belong to this index
            }
        }

        Map<String, Object> out = Http.map(
                "accepted", true,
                "status", "ACCEPTED",
                "trapdoorId", trapdoorId,
                "trapdoorHash", hash,
                "documentId", documentId,
                "matches", C);
        if (!C.isEmpty()) {
            String ticket = CryptoUtil.randomId(24);
            tickets.put(ticket, Http.map("documentId", documentId, "expires", now + 15 * 60 * 1000L, "trapdoorHash", hash));
            out.put("retrievalTicket", ticket);
        }
        logActivity("SEARCH", documentId, ownerUserId, submittedBy, hash,
                C.isEmpty() ? "no match" : "match (" + C.size() + " ct4)");
        return out;
    }

    private Map<String, Object> record(String hash, String coreHash, Map<String, Object> env, String documentId,
                                       String ownerUserId, String submittedBy, long now, String status,
                                       TrapGen.Trapdoor T, Object alertId) {
        Map<String, Object> rec = Http.map(
                "trapdoorHash", hash,
                "trapdoorId", String.valueOf(env.get("trapdoorId")),
                "coreHash", coreHash,
                "nonce", String.valueOf(env.get("nonce")),
                "documentId", documentId,
                "ownerUserId", ownerUserId,
                "submittedBy", submittedBy,
                // pseudonymous identity tag: SHA-256(tk3). The CSP cannot invert it;
                // only the owner's Detect maps tk3 to pk_c.
                "identityTag", CryptoUtil.sha256Hex(T.tk3.toBytes()).substring(0, 16),
                "operation", "SEARCH",
                "usedAt", now,
                "status", status);
        if (alertId != null) rec.put("alertId", alertId);
        return rec;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> raiseAlert(String type, String reason, Map<String, Object> first,
                                           Map<String, Object> env, String hash, String submittedBy,
                                           String ownerUserId, String documentId, long now) {
        List<Object> alerts = store.readList(ALERTS);
        Map<String, Object> alert = Http.map(
                "alertId", "A-" + CryptoUtil.randomId(6),
                "type", type,
                "reason", reason,
                "documentId", documentId,
                "ownerUserId", ownerUserId,
                "trapdoorId", String.valueOf(env.get("trapdoorId")),
                "trapdoorHash", hash,
                "firstTrapdoorHash", first.get("trapdoorHash"),
                "firstUsedAt", first.get("usedAt"),
                "firstSubmittedBy", first.get("submittedBy"),
                "reusedAt", now,
                "reusedBy", submittedBy,
                "identityTag", first.get("identityTag"),
                "identifiedUserId", null,
                "detectStatus", "PENDING",
                "status", "OPEN",
                // the replayed trapdoor is kept so the owner can run Detect on it
                // (paper V-A: "the CSP forwards the trapdoor to the data owner")
                "trapdoorEnvelope", env);
        alerts.add(alert);
        store.write(ALERTS, alerts);
        return alert;
    }

    private Map<String, Object> rejection(String status, String message, String hash, String trapdoorId, Object alertId) {
        Map<String, Object> m = Http.map("accepted", false, "status", status, "message", message,
                "trapdoorHash", hash, "trapdoorId", trapdoorId, "matches", new ArrayList<>());
        if (alertId != null) m.put("alertId", alertId);
        return m;
    }

    /** CSP -> Minos server: "anomalous trapdoor observed, please run Detect". Asynchronous. */
    private void notifyMinos(String alertId) {
        Map<String, Object> l = link;
        if (l == null) return;
        Thread t = new Thread(() -> {
            try {
                Thread.sleep(200);
                String url = String.valueOf(l.get("minosCallbackUrl"));
                JsonHttpClient client = new JsonHttpClient(url.substring(0, url.indexOf("/", 8)));
                client.setLinkKey(String.valueOf(l.get("linkKey")));
                client.post(url.substring(url.indexOf("/", 8)), Http.map("alertId", alertId));
            } catch (Exception e) {
                System.out.println("[CSP] Minos server not reachable for alert " + alertId
                        + "; Detect will run when the owner opens the alerts page.");
            }
        }, "csp-notify");
        t.setDaemon(true);
        t.start();
    }

    // ================================================================
    // Retrieval of encrypted matching documents
    // ================================================================

    private Http.Response retrieve(Request r) {
        String id = r.params.get("id");
        Map<String, Object> t = tickets.remove(r.str("ticket"));
        if (t == null || !id.equals(t.get("documentId"))
                || ((Number) t.get("expires")).longValue() < System.currentTimeMillis()) {
            logSecurity("RETRIEVE_DENIED", id, null, r.optStr("submittedBy", "anonymous"), null, "Invalid or expired retrieval ticket");
            throw new ApiException(403, "No valid retrieval ticket for this document (search first)");
        }
        logActivity("RETRIEVE", id, null, r.optStr("submittedBy", "anonymous"), (String) t.get("trapdoorHash"), "ciphertext released");
        return ciphertextResponse(id, 0);
    }

    private Http.Response ownerRetrieve(Request r) {
        String id = r.params.get("id");
        int version = 0;
        Object v = r.json().get("version");
        if (v instanceof Number) version = ((Number) v).intValue();
        logActivity("OWNER_RETRIEVE", id, null, r.optStr("submittedBy", "owner"), null,
                "ciphertext released to owner" + (version > 0 ? " (version " + version + ")" : ""));
        return ciphertextResponse(id, version);
    }

    /**
     * Returns one stored version of the encrypted document.
     * version 0 means "the current (approved) version".
     * Version 1 is the owner's original upload; later versions are
     * changes proposed by editors (maker) and approved by the owner (checker).
     */
    @SuppressWarnings("unchecked")
    private Http.Response ciphertextResponse(String id, int version) {
        Map<String, Object> meta = documentMeta(id);
        int current = 1;
        if (meta.get("currentVersion") instanceof Number) current = ((Number) meta.get("currentVersion")).intValue();
        int wanted = version <= 0 ? current : version;
        String blobKey;
        Object wrappedKey;
        if (wanted == 1) {
            blobKey = "encrypted-documents/" + id + ".bin";
            wrappedKey = meta.get("wrappedFileKeyBase64");
        } else {
            Map<String, Object> found = null;
            Object list = meta.get("versions");
            if (list instanceof List) {
                for (Object o : (List<Object>) list) {
                    Map<String, Object> item = (Map<String, Object>) o;
                    if (((Number) item.get("version")).intValue() == wanted) found = item;
                }
            }
            if (found == null) throw new ApiException(404, "Unknown version " + wanted);
            blobKey = (String) found.get("blob");
            wrappedKey = found.get("wrappedFileKeyBase64");
        }
        byte[] sealed = blobs.get(blobKey);
        Map<String, Object> out = Http.map(
                "success", true,
                "documentId", id,
                "version", wanted,
                "encryptedDocumentBase64", CryptoUtil.b64(sealed),
                "wrappedFileKeyBase64", wrappedKey);
        return Http.Response.json(200, out);
    }

    // ================================================================
    // Maker-checker versions (project extension)
    //   maker  : an editor proposes a new encrypted version, signed with
    //            the editor's registered key  -> status PENDING
    //   checker: the owner approves (it becomes the current version)
    //            or rejects it. Nothing is ever overwritten or deleted.
    // ================================================================

    /** Text the editor signs: binds the editor to exactly this encrypted version. */
    public static String versionMessage(String documentId, int baseVersion, String ciphertextHash, String note) {
        return "minos-document-version/v1\n" + documentId + "\n" + baseVersion + "\n" + ciphertextHash + "\n"
                + CryptoUtil.sha256Hex(note.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> proposeVersion(Request r) {
        String id = r.params.get("id");
        byte[] sealed = CryptoUtil.unb64(r.str("encryptedDocumentBase64"));
        String editorPk = r.str("editorPublicKey");
        String note = r.optStr("note", "");
        int baseVersion = ((Number) r.json().get("baseVersion")).intValue();

        // The editor must be a registered user (list R) ...
        String editorId = null;
        for (String key : blobs.list("public-keys/")) {
            Map<String, Object> u = store.readMap(key);
            if (editorPk.equals(u.get("publicKey"))) editorId = (String) u.get("userId");
        }
        if (editorId == null) throw new ApiException(403, "Only registered users can propose changes");
        // ... and must have signed exactly this encrypted version.
        String hash = CryptoUtil.sha256Hex(sealed);
        boolean signed;
        synchronized (crypto) {
            signed = SchnorrSignature.verify(mpk, Codec.g1(mpk, editorPk),
                    versionMessage(id, baseVersion, hash, note), r.str("sigR"), r.str("sigS"));
        }
        if (!signed) throw new ApiException(403, "The change is not signed by the editor");

        synchronized (lock) {
            Map<String, Object> meta = documentMeta(id);
            List<Object> versions = meta.get("versions") instanceof List
                    ? (List<Object>) meta.get("versions") : new ArrayList<>();
            int next = 2;
            for (Object o : versions) {
                int v = ((Number) ((Map<String, Object>) o).get("version")).intValue();
                if (v >= next) next = v + 1;
            }
            String blobKey = "encrypted-documents/" + id + ".v" + next + ".bin";
            blobs.put(blobKey, sealed);
            Map<String, Object> entry = Http.map(
                    "version", next,
                    "baseVersion", baseVersion,
                    "status", "PENDING",
                    "proposedBy", editorId,
                    "editorFingerprint", fingerprint(editorPk),
                    "sigR", r.str("sigR"),
                    "sigS", r.str("sigS"),
                    "sha256", hash,
                    "sizeBytes", sealed.length,
                    "blob", blobKey,
                    "wrappedFileKeyBase64", r.str("wrappedFileKeyBase64"),
                    "proposedAt", now());
            versions.add(entry);
            meta.put("versions", versions);
            store.write("metadata/documents/" + id + ".json", meta);
            logActivity("VERSION_PROPOSED", id, (String) meta.get("ownerUserId"), editorId, hash,
                    "version " + next + " proposed (pending owner approval)");
            return Http.map("documentId", id, "version", next, "status", "PENDING", "proposedBy", editorId);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> decideVersion(Request r) {
        String id = r.params.get("id");
        int version = Integer.parseInt(r.params.get("version"));
        boolean approve = Boolean.TRUE.equals(r.json().get("approve"));
        synchronized (lock) {
            Map<String, Object> meta = documentMeta(id);
            Map<String, Object> found = null;
            if (meta.get("versions") instanceof List) {
                for (Object o : (List<Object>) meta.get("versions")) {
                    Map<String, Object> item = (Map<String, Object>) o;
                    if (((Number) item.get("version")).intValue() == version) found = item;
                }
            }
            if (found == null) throw new ApiException(404, "Unknown version");
            if (!"PENDING".equals(found.get("status"))) throw new ApiException(409, "This change was already decided");
            found.put("status", approve ? "APPROVED" : "REJECTED");
            found.put("decidedAt", now());
            if (approve) meta.put("currentVersion", version);
            store.write("metadata/documents/" + id + ".json", meta);
            logActivity(approve ? "VERSION_APPROVED" : "VERSION_REJECTED", id, (String) meta.get("ownerUserId"),
                    (String) found.get("proposedBy"), (String) found.get("sha256"), "version " + version);
            return Http.map("documentId", id, "version", version, "status", found.get("status"),
                    "currentVersion", meta.get("currentVersion") == null ? 1 : meta.get("currentVersion"));
        }
    }

    // ================================================================
    // Alerts + Detect result (Algorithm 9, CSP side)
    // ================================================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> alerts(Request r) {
        String owner = r.query.get("ownerUserId");
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : store.readList(ALERTS)) {
            Map<String, Object> a = (Map<String, Object>) o;
            if (owner == null || owner.equals(a.get("ownerUserId"))) {
                Map<String, Object> copy = new LinkedHashMap<>(a);
                copy.remove("trapdoorEnvelope");
                out.add(copy);
            }
        }
        return Http.map("alerts", out);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> alert(Request r) {
        for (Object o : store.readList(ALERTS)) {
            Map<String, Object> a = (Map<String, Object>) o;
            if (r.params.get("id").equals(a.get("alertId"))) return Http.map("alert", a);
        }
        throw new ApiException(404, "Unknown alert");
    }

    /**
     * Algorithm 9 lines 2-4: the owner sends pk_c and tk3; the CSP executes
     * R[pk_c] <- tk3 and resolves pk_c to a registered user id from R.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> detectResult(Request r) {
        String id = r.params.get("id");
        String pk = r.str("publicKey");
        String tk3 = r.str("tk3");
        synchronized (lock) {
            String userId = null;
            for (String key : blobs.list("public-keys/")) {
                Map<String, Object> u = store.readMap(key);
                if (pk.equals(u.get("publicKey"))) {
                    userId = (String) u.get("userId");
                    List<Object> tags = (List<Object>) u.computeIfAbsent("linkedTrapdoorTags", k -> new ArrayList<>());
                    boolean present = false;
                    for (Object t : tags) if (tk3.equals(((Map<String, Object>) t).get("tk3"))) present = true;
                    if (!present) {
                        tags.add(Http.map("tk3", tk3, "linkedAt", now(), "alertId", id));   // R[pk_c] <- tk3
                    }
                    store.write(key, u);
                }
            }
            List<Object> alerts = store.readList(ALERTS);
            Map<String, Object> found = null;
            for (Object o : alerts) {
                Map<String, Object> a = (Map<String, Object>) o;
                if (id.equals(a.get("alertId"))) found = a;
            }
            if (found == null) throw new ApiException(404, "Unknown alert");
            found.put("identifiedUserId", userId);
            found.put("identifiedPublicKeyFingerprint", fingerprint(pk));
            found.put("detectStatus", userId == null ? "UNREGISTERED_KEY" : "IDENTIFIED");
            found.put("detectAlgorithm", r.optStr("algorithm", "9"));
            found.put("trapdoorIntegrity", r.optStr("integrity", "unknown"));
            found.put("detectedAt", System.currentTimeMillis());
            store.write(ALERTS, alerts);
            logSecurity("DETECT_RESULT", (String) found.get("documentId"), (String) found.get("ownerUserId"),
                    "owner", (String) found.get("trapdoorHash"),
                    "Alert " + id + ": trapdoor bound to registered user " + userId + " (R[pk_c] <- tk3 recorded)");
            return Http.map("identifiedUserId", userId);
        }
    }

    // ================================================================
    // Suspension (paper VI-A.4) - project revocation hooks into it
    // ================================================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> suspensions(Request r) {
        String owner = r.query.get("ownerUserId");
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(SUSPENSIONS)) {
            Map<String, Object> s = (Map<String, Object>) o;
            if (owner == null || owner.equals(s.get("ownerUserId"))) out.add(s);
        }
        return Http.map("suspensions", out);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> suspend(Request r) {
        String owner = r.str("ownerUserId");
        String user = r.str("userId");
        String tk3 = r.str("tk3");
        synchronized (lock) {
            List<Object> list = store.readList(SUSPENSIONS);
            for (Object o : list) {
                Map<String, Object> s = (Map<String, Object>) o;
                if (owner.equals(s.get("ownerUserId")) && user.equals(s.get("userId"))) return Http.map("alreadySuspended", true);
            }
            list.add(Http.map("ownerUserId", owner, "userId", user, "tk3", tk3, "suspendedAt", now()));
            store.write(SUSPENSIONS, list);
            List<Object> alerts = store.readList(ALERTS);
            for (Object o : alerts) {
                Map<String, Object> a = (Map<String, Object>) o;
                if (owner.equals(a.get("ownerUserId")) && user.equals(a.get("identifiedUserId"))) a.put("status", "USER_REVOKED");
            }
            store.write(ALERTS, alerts);
        }
        logSecurity("IDENTITY_SUSPENDED", null, owner, owner, null, "Owner " + owner + " suspended trapdoors of " + user);
        return Http.map("suspended", true);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> unsuspend(Request r) {
        String owner = r.str("ownerUserId");
        String user = r.str("userId");
        synchronized (lock) {
            List<Object> list = store.readList(SUSPENSIONS);
            list.removeIf(o -> owner.equals(((Map<String, Object>) o).get("ownerUserId"))
                    && user.equals(((Map<String, Object>) o).get("userId")));
            store.write(SUSPENSIONS, list);
        }
        logSecurity("IDENTITY_RESTORED", null, owner, owner, null, "Owner " + owner + " restored " + user);
        return Http.map("suspended", false);
    }

    // ================================================================
    // Trace (Algorithm 10)
    // ================================================================

    /**
     * Ownership claim (dispute) handling around Trace (Algorithm 10).
     *
     * Paper part: Trace(L, hp) -> true/false.
     * Project extension: every claim is signed by the claimant's registered key
     * (so nobody can file a claim in someone else's name), recorded, and a false
     * claim raises an alert for the real owner. A claimant with MAX_FALSE_CLAIMS
     * false claims within 24 hours is blocked from filing more claims until the
     * window passes.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> trace(Request r) {
        String id = r.str("documentId");
        Map<String, Object> meta = documentMeta(id);
        String ownerUserId = (String) meta.get("ownerUserId");
        String helpJson = r.str("helpDataJson");
        String claimantPk = r.str("claimantPublicKey");
        String claimedAt = r.str("claimedAt");
        String reason = r.optStr("reason", "");
        if (reason.length() > 500) reason = reason.substring(0, 500);

        // 1. The claim must come from a registered key (list R) ...
        String claimantUserId = null;
        for (String key : blobs.list("public-keys/")) {
            Map<String, Object> u = store.readMap(key);
            if (claimantPk.equals(u.get("publicKey"))) claimantUserId = (String) u.get("userId");
        }
        if (claimantUserId == null) throw new ApiException(403, "Ownership claims must come from a registered user");
        // ... and be signed with the matching secret key.
        String message = claimMessage(id, claimedAt, CryptoUtil.sha256Hex(helpJson.getBytes(StandardCharsets.UTF_8)), reason);
        boolean signed;
        synchronized (crypto) {
            signed = SchnorrSignature.verify(mpk, Codec.g1(mpk, claimantPk), message, r.str("sigR"), r.str("sigS"));
        }
        if (!signed) throw new ApiException(403, "The ownership claim signature is not valid");

        long now = System.currentTimeMillis();
        synchronized (lock) {
            List<Object> claims = store.readList(CLAIMS);
            int recentFalse = 0;
            long oldestRecentFalse = Long.MAX_VALUE;
            for (Object o : claims) {
                Map<String, Object> c = (Map<String, Object>) o;
                long at = ((Number) c.get("claimedAt")).longValue();
                if (claimantUserId.equals(c.get("claimantUserId")) && "FALSE_CLAIM".equals(c.get("result"))
                        && now - at < CLAIM_WINDOW_MS) {
                    recentFalse++;
                    oldestRecentFalse = Math.min(oldestRecentFalse, at);
                }
            }
            Map<String, Object> claim = Http.map(
                    "claimId", "C-" + CryptoUtil.randomId(6),
                    "documentId", id,
                    "ownerUserId", ownerUserId,
                    "claimantUserId", claimantUserId,
                    "claimantFingerprint", fingerprint(claimantPk),
                    "reason", reason,
                    "claimedAt", now);

            // 2. Repeated false claims: refuse without running Trace.
            if (recentFalse >= MAX_FALSE_CLAIMS) {
                long until = oldestRecentFalse + CLAIM_WINDOW_MS;
                claim.put("result", "BLOCKED");
                claim.put("blockedUntil", until);
                claims.add(claim);
                store.write(CLAIMS, claims);
                logSecurity("OWNERSHIP_CLAIM_BLOCKED", id, ownerUserId, claimantUserId, null,
                        claimantUserId + " has " + recentFalse + " false claims in 24 h; claim refused");
                return Http.map("valid", false, "status", "BLOCKED", "claimId", claim.get("claimId"),
                        "claimant", claimantUserId, "falseClaims", recentFalse, "blockedUntil", until,
                        "maxFalseClaims", MAX_FALSE_CLAIMS);
            }

            // 3. Trace (Algorithm 10).
            Map<String, Object> index = store.readMap("encrypted-index/" + id + ".json");
            List<Map<String, Object>> L = new ArrayList<>();
            for (Object e : Codec.list(index.get("entries"))) L.add(Codec.map(e));
            boolean valid;
            synchronized (crypto) {
                try {
                    valid = Trace.trace(mpk, L, Trace.HelpData.fromJson(mpk, Codec.map(Json.parse(helpJson))));
                } catch (RuntimeException e) {
                    valid = false;
                }
            }
            claim.put("result", valid ? "VERIFIED" : "FALSE_CLAIM");
            int falseClaims = recentFalse + (valid ? 0 : 1);
            boolean nowBlocked = !valid && falseClaims >= MAX_FALSE_CLAIMS;
            claim.put("falseClaimsIn24h", falseClaims);
            Object alertId = null;

            // 4. A false claim raises an alert for the real owner.
            if (!valid) {
                List<Object> alerts = store.readList(ALERTS);
                Map<String, Object> alert = Http.map(
                        "alertId", "A-" + CryptoUtil.randomId(6),
                        "type", "FALSE_OWNERSHIP_CLAIM",
                        "reason", "False ownership claim: Trace (Algorithm 10) returned false",
                        "documentId", id,
                        "ownerUserId", ownerUserId,
                        "claimId", claim.get("claimId"),
                        "claimantReason", reason,
                        "claimedAt", now,
                        "falseClaimsIn24h", falseClaims,
                        "maxFalseClaims", MAX_FALSE_CLAIMS,
                        "claimantBlocked", nowBlocked,
                        // the claimant is known from the registered key that signed the claim
                        "identifiedUserId", claimantUserId,
                        "identifiedPublicKeyFingerprint", fingerprint(claimantPk),
                        "detectStatus", "NOT_APPLICABLE",
                        "status", "OPEN");
                alerts.add(alert);
                store.write(ALERTS, alerts);
                alertId = alert.get("alertId");
                claim.put("alertId", alertId);
            }
            claims.add(claim);
            store.write(CLAIMS, claims);
            logSecurity(valid ? "OWNERSHIP_CLAIM_VERIFIED" : "OWNERSHIP_CLAIM_REJECTED", id, ownerUserId, claimantUserId, null,
                    "Trace (Algorithm 10) result: " + valid + (valid ? "" : " - false claim " + falseClaims + "/"
                            + MAX_FALSE_CLAIMS + " in 24 h" + (nowBlocked ? ", claimant now blocked" : "")
                            + ", alert " + alertId));
            Map<String, Object> out = Http.map("valid", valid, "status", valid ? "VERIFIED" : "FALSE_CLAIM",
                    "documentId", id, "claimant", claimantUserId, "claimId", claim.get("claimId"),
                    "falseClaims", falseClaims, "maxFalseClaims", MAX_FALSE_CLAIMS, "blocked", nowBlocked);
            if (alertId != null) out.put("alertId", alertId);
            return out;
        }
    }

    /** The exact text a claimant signs. Shared with the Minos Server. */
    public static String claimMessage(String documentId, String claimedAt, String helpDataHash, String reason) {
        return "minos-ownership-claim/v1\n" + documentId + "\n" + claimedAt + "\n" + helpDataHash + "\n"
                + CryptoUtil.sha256Hex(reason.getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(Request r) {
        String owner = r.query.get("ownerUserId");
        String claimant = r.query.get("claimantUserId");
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(CLAIMS)) {
            Map<String, Object> c = (Map<String, Object>) o;
            if ((owner == null || owner.equals(c.get("ownerUserId")))
                    && (claimant == null || claimant.equals(c.get("claimantUserId")))) out.add(c);
        }
        Collections.reverse(out);
        return Http.map("claims", out);
    }

    // ================================================================
    // Trapdoor records
    // ================================================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> records(Request r) {
        String owner = r.query.get("ownerUserId");
        String by = r.query.get("submittedBy");
        int limit = intParam(r, "limit", 200);
        List<Object> all = store.readList(RECORDS);
        List<Object> out = new ArrayList<>();
        for (int i = all.size() - 1; i >= 0 && out.size() < limit; i--) {
            Map<String, Object> rec = new LinkedHashMap<>((Map<String, Object>) all.get(i));
            if (owner != null && !owner.equals(rec.get("ownerUserId"))) continue;
            if (by != null && !by.equals(rec.get("submittedBy"))) continue;
            rec.remove("nonce");
            rec.remove("coreHash");
            out.add(rec);
        }
        return Http.map("records", out);
    }

    // ================================================================
    // Helpers
    // ================================================================

    private void logSecurity(String event, String doc, String owner, String by, String hash, String detail) {
        store.log(SECURITY_LOG, Http.map("event", event, "documentId", doc, "ownerUserId", owner,
                "submittedBy", by, "trapdoorHash", hash, "detail", detail));
    }

    private void logActivity(String event, String doc, String owner, String by, String hash, String detail) {
        store.log(ACTIVITY_LOG, Http.map("event", event, "documentId", doc, "ownerUserId", owner,
                "submittedBy", by, "trapdoorHash", hash, "detail", detail));
    }

    private static String fingerprint(String b64) {
        return CryptoUtil.sha256Hex(b64.getBytes(StandardCharsets.UTF_8)).substring(0, 16);
    }

    private static String now() {
        return java.time.Instant.now().toString();
    }

    private static int intParam(Request r, String name, int def) {
        try {
            return Integer.parseInt(r.query.getOrDefault(name, String.valueOf(def)));
        } catch (NumberFormatException e) {
            return def;
        }
    }

    // ================================================================
    // main
    // ================================================================

    public static void main(String[] args) throws Exception {
        int port = 9090;
        Path dir = Paths.get("backend/csp-storage");
        for (String a : args) {
            if (a.startsWith("--port=")) port = Integer.parseInt(a.substring(7));
            if (a.startsWith("--storage=")) dir = Paths.get(a.substring(10));
        }
        CspServer csp = new CspServer(new LocalBlobStore(dir));
        Http.start(port, csp.router(), 8);
        System.out.println("[CSP] Minos CSP server running at http://localhost:" + port);
        System.out.println("[CSP] Storage: " + dir.toAbsolutePath());
        System.out.println("[CSP] Public parameters " + (csp.mpk == null ? "not received yet (run Setup in the web app)" : "loaded"));
    }
}
