package minos.server;

import it.unisa.dia.gas.jpbc.Element;
import minos.common.CryptoUtil;
import minos.common.Http;
import minos.common.Http.ApiException;
import minos.common.Json;
import minos.common.JsonHttpClient;
import minos.common.JsonStore;
import minos.common.LocalBlobStore;
import minos.core.AccessPolicy;
import minos.core.Authorize;
import minos.core.Codec;
import minos.core.Decrypt;
import minos.core.Detect;
import minos.core.Encrypt;
import minos.core.KeyGen;
import minos.core.MinosStorage;
import minos.core.Register;
import minos.core.Setup;
import minos.core.Trace;
import minos.core.TrapGen;
import minos.ext.DocumentCrypto;
import minos.ext.KeyVault;
import minos.ext.SchnorrSignature;
import minos.ext.TrapdoorEnvelope;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Business logic of the MINOS SERVER.
 *
 * Roles played by this process (paper Fig. 1):
 *   - client software of data owners and data users (Register, KeyGen,
 *     Encrypt, Authorize client side, TrapGen, Decrypt);
 *   - trusted proxy of the data owner (paper Section VIII-A) that executes
 *     the owner side of Authorize and Detect while the owner is offline,
 *     strictly following the owner's access policy and revocation list.
 *
 * Secret keys live only in the encrypted KeyVault of this process; the CSP
 * receives public keys, ciphertexts, trapdoors and help data only.
 */
public final class MinosService {

    public static final int LAMBDA = 160;
    public static final List<String> DEFAULT_ATTRIBUTES =
            List.of("HR", "Manager", "Employee", "Finance", "Admin");

    private final Path dataDir;
    private final JsonStore store;
    private final KeyVault vault;
    private final JsonHttpClient csp;
    private final String publicUrl;
    private volatile Setup.PublicParameters mpk;
    private final Map<String, Map<String, Object>> searchSessions = new ConcurrentHashMap<>();

    private static final String SERVER = "config/server.json";
    private static final String USERS = "users.json";
    private static final String DOCUMENTS = "documents.json";
    private static final String REVOCATIONS = "revocations.json";
    private static final String ACCESS_REQUESTS = "access-requests.json";
    /** Every traceable copy handed out: copy id -> user, document, version, time, variation bits. */
    private static final String LEAK_COPIES = "leak-copies.json";
    /** View-page protection events reported to owners (copy, print, Print Screen attempts). */
    private static final String VIEW_ALERTS = "view-alerts.json";
    private static final String ALERTS_SEEN = "alerts-seen.json";
    /** Who viewed / downloaded / changed which document, and what was decided. */
    private static final String DOCUMENT_LOG = "logs/document-access.log";
    public static final String VIEW = "VIEW";
    public static final String DOWNLOAD = "DOWNLOAD";
    public static final String MODIFY = "MODIFY";
    private static final String AUDIT = "logs/audit.log";

    public MinosService(Path dataDir, String cspUrl, String publicUrl) throws Exception {
        this.dataDir = dataDir.toAbsolutePath();
        this.store = new JsonStore(new LocalBlobStore(this.dataDir));
        this.vault = new KeyVault(this.dataDir);
        this.csp = new JsonHttpClient(cspUrl);
        this.publicUrl = publicUrl;
        Path params = paramsFile();
        if (Files.exists(params)) {
            mpk = MinosStorage.load(params);         // NEXT RUN: load existing mpk
            csp.setLinkKey(String.valueOf(server().get("linkKey")));
        }
    }

    private Path paramsFile() {
        return dataDir.resolve("config").resolve("public-params.bin");
    }

    public boolean initialized() {
        return mpk != null;
    }

    private Map<String, Object> server() {
        return store.readMap(SERVER);
    }

    private void requireSetup() {
        if (mpk == null) throw new ApiException(409, "System not initialized: run Setup first");
    }

    // ================================================================
    // STATUS
    // ================================================================

    public Map<String, Object> status() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("initialized", mpk != null);
        out.put("defaultAttributes", DEFAULT_ATTRIBUTES);
        out.put("cspUrl", csp.baseUrl());
        out.put("vault", vault.mode());
        Map<String, Object> cspHealth;
        try {
            cspHealth = csp.get("/csp/api/health");
            out.put("cspOnline", true);
            out.put("csp", cspHealth);
        } catch (ApiException e) {
            out.put("cspOnline", false);
        }
        if (mpk != null) {
            Map<String, Object> s = server();
            out.put("lambda", mpk.getLambda());
            out.put("attributes", new ArrayList<>(mpk.getAttributes()));
            out.put("setupAt", s.get("setupAt"));
            out.put("groupOrderBits", mpk.getP().bitLength());
            out.put("generatorFingerprint", CryptoUtil.sha256Hex(mpk.getG().toBytes()).substring(0, 16));
            out.put("users", store.readMap(USERS).size());
            out.put("documents", store.readMap(DOCUMENTS).size());
        }
        return out;
    }

    // ================================================================
    // 1. SETUP (Algorithm 1) - first run only, then persisted
    // ================================================================

    public synchronized Map<String, Object> setup(List<String> attributes) throws Exception {
        if (mpk != null || Files.exists(paramsFile())) {
            throw new ApiException(409, "Setup already completed; the existing mpk is reused and never regenerated");
        }
        Set<String> A = new LinkedHashSet<>();
        for (String a : attributes) {
            String t = a.trim();
            if (!t.matches("[A-Za-z][A-Za-z0-9_-]{0,31}")) throw new ApiException(400, "Invalid attribute name: " + a);
            if (t.equalsIgnoreCase("AND") || t.equalsIgnoreCase("OR")) throw new ApiException(400, "Reserved word: " + t);
            A.add(t);
        }
        if (A.isEmpty()) throw new ApiException(400, "The attribute universe A is empty");

        long t0 = System.currentTimeMillis();
        Setup.PublicParameters params = Setup.setup(LAMBDA, A);          // Algorithm 1
        long ms = System.currentTimeMillis() - t0;
        MinosStorage.save(paramsFile(), params);                         // persist mpk

        String linkKey = CryptoUtil.randomId(32);
        store.write(SERVER, Http.map(
                "setupAt", java.time.Instant.now().toString(),
                "linkKey", linkKey,
                "attributes", new ArrayList<>(A)));
        csp.setLinkKey(linkKey);
        mpk = params;
        audit("SETUP", null, "Algorithm 1 executed; |U| = " + A.size() + ", " + ms + " ms");
        String cspState = syncCsp();
        Map<String, Object> out = status();
        out.put("setupMillis", ms);
        out.put("cspSync", cspState);
        return out;
    }

    /** Sends mpk (public) to the CSP; repeated on every start until accepted. */
    public synchronized String syncCsp() {
        if (mpk == null) return "not initialized";
        try {
            byte[] params = Files.readAllBytes(paramsFile());
            csp.post("/csp/api/admin/init", Http.map(
                    "publicParamsBase64", CryptoUtil.b64(params),
                    "linkKey", server().get("linkKey"),
                    "minosCallbackUrl", publicUrl + "/internal/csp/alert"));
            return "CSP holds the public parameters";
        } catch (ApiException e) {
            return "CSP not reachable yet (" + e.getMessage() + "); will retry";
        } catch (Exception e) {
            return "CSP sync failed: " + e.getMessage();
        }
    }

    // ================================================================
    // 2-3. REGISTER (Algorithm 2) -> KEYGEN (Algorithm 3) automatically
    // ================================================================

    public synchronized Map<String, Object> register(String userId, String displayName,
                                                     String password, List<String> attributes) throws Exception {
        requireSetup();
        if (!userId.matches("[A-Za-z0-9_.-]{3,32}")) {
            throw new ApiException(400, "User ID: 3-32 letters, digits, '.', '_' or '-'");
        }
        if (password == null || password.length() < 8) throw new ApiException(400, "Password must have at least 8 characters");
        Map<String, Object> users = store.readMap(USERS);
        for (String existing : users.keySet()) {
            if (existing.equalsIgnoreCase(userId)) throw new ApiException(409, "User ID already registered");
        }
        Set<String> Sc = new LinkedHashSet<>();
        for (String a : attributes) {
            if (!mpk.getAttributes().contains(a)) throw new ApiException(400, "Attribute not in universe U: " + a);
            Sc.add(a);
        }
        if (Sc.isEmpty()) throw new ApiException(400, "Select at least one attribute/role");

        // Algorithm 2 (user side): beta <- Zp, pk = g^beta, sk = beta
        Register.RegistrationResult reg = Register.register(mpk, new HashSet<>());
        String pk = Codec.enc(reg.pk);

        // Algorithm 2 lines 4-5: send pk to the CSP, which runs R.add(pk).
        csp.post("/csp/api/registry/users", Http.map(
                "userId", userId, "publicKey", pk,
                "displayName", displayName == null || displayName.isBlank() ? userId : displayName));

        // Algorithm 3 (lines 3-7) automatically after registration.
        long t0 = System.currentTimeMillis();
        KeyGen.K K = KeyGen.keyGen(mpk);
        long keyGenMs = System.currentTimeMillis() - t0;

        // Secret material -> encrypted vault only.
        Map<String, Object> secret = new LinkedHashMap<>();
        secret.put("sk", Codec.enc(reg.sk));
        secret.put("K", Codec.kToJson(K));
        vault.put(vaultUser(userId), secret);

        byte[] salt = CryptoUtil.random(16);
        byte[] hash = CryptoUtil.pbkdf2(password.toCharArray(), salt, CryptoUtil.PBKDF2_ITERATIONS);
        users.put(userId, Http.map(
                "userId", userId,
                "displayName", displayName == null || displayName.isBlank() ? userId : displayName.trim(),
                "attributes", new ArrayList<>(Sc),
                "publicKey", pk,
                "passwordSalt", CryptoUtil.b64(salt),
                "passwordHash", CryptoUtil.b64(hash),
                "passwordIterations", CryptoUtil.PBKDF2_ITERATIONS,
                "registeredAt", java.time.Instant.now().toString(),
                "keyGenAt", java.time.Instant.now().toString()));
        store.write(USERS, users);
        audit("REGISTER", userId, "Algorithm 2 (pk sent to CSP, R.add) + Algorithm 3 KeyGen (" + keyGenMs + " ms)");

        return Http.map(
                "userId", userId,
                "attributes", new ArrayList<>(Sc),
                "publicKeyFingerprint", fingerprint(pk),
                "register", "pk = g^beta generated; pk stored in the CSP registration list R",
                "keyGen", "K = ({sk1,v} for |U| = " + K.sk1.size() + " attributes, sk2, k) generated and stored encrypted",
                "keyGenMillis", keyGenMs);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> login(String userId, String password) {
        requireSetup();
        Map<String, Object> u = (Map<String, Object>) store.readMap(USERS).get(userId);
        if (u == null) {
            CryptoUtil.pbkdf2(password.toCharArray(), new byte[16], CryptoUtil.PBKDF2_ITERATIONS); // equal timing
            throw new ApiException(401, "Invalid user ID or password");
        }
        byte[] expected = CryptoUtil.unb64((String) u.get("passwordHash"));
        byte[] actual = CryptoUtil.pbkdf2(password.toCharArray(), CryptoUtil.unb64((String) u.get("passwordSalt")),
                ((Number) u.get("passwordIterations")).intValue());
        if (!CryptoUtil.constantTimeEquals(expected, actual)) throw new ApiException(401, "Invalid user ID or password");
        audit("LOGIN", userId, "password verified (PBKDF2)");
        return publicUser(u);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> user(String userId) {
        Map<String, Object> u = (Map<String, Object>) store.readMap(USERS).get(userId);
        if (u == null) throw new ApiException(404, "Unknown user " + userId);
        return u;
    }

    public Map<String, Object> publicUser(Map<String, Object> u) {
        return Http.map(
                "userId", u.get("userId"),
                "displayName", u.get("displayName"),
                "attributes", u.get("attributes"),
                "publicKeyFingerprint", fingerprint((String) u.get("publicKey")),
                "registeredAt", u.get("registeredAt"));
    }

    @SuppressWarnings("unchecked")
    private Set<String> attributesOf(String userId) {
        return new LinkedHashSet<>((List<String>) (List<?>) user(userId).get("attributes"));
    }

    // ---- secrets ----

    private static final class Secrets {
        Element sk;
        Element pk;
        KeyGen.K K;
    }

    @SuppressWarnings("unchecked")
    private Secrets secrets(String userId) {
        Map<String, Object> v = vault.get(vaultUser(userId));
        Secrets s = new Secrets();
        s.sk = Codec.zr(mpk, (String) v.get("sk"));
        s.pk = Codec.g1(mpk, (String) user(userId).get("publicKey"));
        s.K = Codec.kFromJson(mpk, (Map<String, Object>) v.get("K"));
        return s;
    }

    private static String vaultUser(String userId) {
        return "user-" + userId;
    }

    // ================================================================
    // 4. OWNER UPLOAD: KeyGen lines 1-2 + Encrypt (Algorithm 4)
    //    + AES-GCM document encryption (project extension)
    // ================================================================

    public synchronized Map<String, Object> upload(String ownerId, String fileName, String contentType,
                                                   byte[] document, String keywordText,
                                                   List<String> roles, String policyText,
                                                   boolean requireApproval) throws Exception {
        return upload(ownerId, fileName, contentType, document, keywordText, roles, policyText, requireApproval, true);
    }

    public synchronized Map<String, Object> upload(String ownerId, String fileName, String contentType,
                                                   byte[] document, String keywordText,
                                                   List<String> roles, String policyText,
                                                   boolean requireApproval, boolean leakTracing) throws Exception {
        requireSetup();
        if (document.length == 0) throw new ApiException(400, "The document is empty");
        if (document.length > 20 * 1024 * 1024) throw new ApiException(413, "Maximum document size is 20 MB");
        String name = fileName.replaceAll("[\\\\/:*?\"<>|\\r\\n]", "_");
        // A text upload never keeps leak-tracing marks (e.g. an owner re-uploading a copy).
        boolean isText = TextDiff.isText(contentType, name, document);
        if (isText) {
            String asText = new String(document, java.nio.charset.StandardCharsets.UTF_8);
            if (Watermark.containsMarks(asText)) {
                document = Watermark.strip(asText).getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        int changePoints = isText ? TextVariation.countPoints(new String(document, java.nio.charset.StandardCharsets.UTF_8)) : 0;

        List<String> keywords = normalizeKeywords(keywordText);
        if (keywords.isEmpty()) throw new ApiException(400, "Enter at least one keyword");

        // Algorithm 3, lines 1-2: access structure (M, pi) for this document.
        AccessPolicy policy;
        try {
            policy = policyText != null && !policyText.isBlank()
                    ? AccessPolicy.parse(mpk, policyText)
                    : AccessPolicy.anyOf(mpk, roles);
        } catch (IllegalArgumentException e) {
            throw new ApiException(400, e.getMessage());
        }

        Secrets owner = secrets(ownerId);
        KeyGen.K K = owner.K.withAccessStructure(policy);
        String documentId = "D-" + CryptoUtil.randomId(10);

        // Inverted index Phi: keyword -> [documentId] (same size per keyword).
        Map<String, List<String>> Phi = new LinkedHashMap<>();
        for (String w : keywords) Phi.put(w, List.of(documentId));

        // Algorithm 4: Encrypt -> L
        long t0 = System.currentTimeMillis();
        List<Encrypt.Entry> L = Encrypt.encrypt(mpk, Phi, owner.sk, owner.pk, K);
        long encMs = System.currentTimeMillis() - t0;

        // Extension: AES-256-GCM document body + file key wrapped under HKDF(k).
        DocumentCrypto.Encrypted enc = DocumentCrypto.encrypt(document, documentId, K.k);
        Arrays.fill(enc.fileKey, (byte) 0);

        csp.post("/csp/api/documents", Http.map(
                "documentId", documentId,
                "ownerUserId", ownerId,
                "ownerPublicKey", Codec.enc(owner.pk),
                "indexEntries", Encrypt.toJson(L),
                "encryptedDocumentBase64", CryptoUtil.b64(enc.sealedDocument),
                "wrappedFileKeyBase64", CryptoUtil.b64(enc.wrappedFileKey)));

        // Owner-side dictionary W (for Detect / Trace) - encrypted in the vault.
        vault.put("doc-" + documentId, Http.map("keywords", keywords));

        Map<String, Object> docs = store.readMap(DOCUMENTS);
        docs.put(documentId, Http.map(
                "documentId", documentId,
                "ownerUserId", ownerId,
                "fileName", name,
                "contentType", contentType == null || contentType.isBlank() ? "application/octet-stream" : contentType,
                "sizeBytes", document.length,
                "policy", policy.expression,
                "policyAttributes", policy.attributes(),
                "matrixRows", policy.M.length,
                "matrixColumns", policy.M[0].length,
                "keywordCount", keywords.size(),
                "requireApproval", requireApproval,
                "leakTracing", isText && leakTracing,
                "changePoints", changePoints,
                "uploadedAt", java.time.Instant.now().toString()));
        store.write(DOCUMENTS, docs);
        audit("UPLOAD", ownerId, "document " + documentId + ": Encrypt (Algorithm 4, " + encMs
                + " ms, |L| = " + L.size() + ") + AES-GCM body; policy " + policy.expression);

        return Http.map(
                "documentId", documentId,
                "fileName", name,
                "policy", policy.expression,
                "accessStructure", Http.map("n1", policy.M.length, "n2", policy.M[0].length, "pi", policy.attributes()),
                "indexEntries", L.size(),
                "keywordEntries", keywords.size(),
                "encryptMillis", encMs,
                "leakTracing", isText && leakTracing,
                "changePoints", changePoints,
                "leakTracingWarning", isText && leakTracing && changePoints < MIN_CHANGE_POINTS
                        ? "This document has only " + changePoints + " places where copies can differ, so a leaked"
                        + " screenshot or printout may match several downloads. Copied or forwarded text is still"
                        + " traced exactly by the hidden code." : null,
                "documentCiphertextBytes", enc.sealedDocument.length);
    }

    private static List<String> normalizeKeywords(String text) {
        Set<String> out = new LinkedHashSet<>();
        if (text == null) return new ArrayList<>();
        for (String part : text.split("[,;\\n]")) {
            String w = normalizeKeyword(part);
            if (!w.isEmpty()) out.add(w);
        }
        return new ArrayList<>(out);
    }

    private static String normalizeKeyword(String w) {
        String k = w.trim().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ");
        if (k.length() > 64) throw new ApiException(400, "Keyword too long (max 64 characters)");
        return k;
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> documentsOf(String ownerId) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : store.readMap(DOCUMENTS).values()) {
            Map<String, Object> d = (Map<String, Object>) o;
            if (ownerId == null || ownerId.equals(d.get("ownerUserId"))) out.add(d);
        }
        out.sort((a, b) -> String.valueOf(a.get("uploadedAt")).compareTo(String.valueOf(b.get("uploadedAt"))));
        return out;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> document(String id) {
        Map<String, Object> d = (Map<String, Object>) store.readMap(DOCUMENTS).get(id);
        if (d == null) throw new ApiException(404, "Unknown document");
        return d;
    }

    // ================================================================
    // 5-8. SEARCH: Authorize (Alg. 5) -> TrapGen (Alg. 6) -> CSP Search
    //      (Alg. 7) -> Decrypt (Alg. 8)
    // ================================================================

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> search(String userId, String keyword) {
        requireSetup();
        String w = normalizeKeyword(keyword == null ? "" : keyword);
        if (w.isEmpty()) throw new ApiException(400, "Enter a keyword");

        Secrets client = secrets(userId);
        Set<String> Sc = attributesOf(userId);

        // Registration list R, maintained by the CSP.
        Set<String> R = new HashSet<>();
        for (Object o : Codec.list(csp.get("/csp/api/registry/users").get("users"))) {
            R.add((String) Codec.map(o).get("publicKey"));
        }

        String searchId = "S-" + CryptoUtil.randomId(8);
        List<Map<String, Object>> matches = new ArrayList<>();
        List<Map<String, Object>> denied = new ArrayList<>();
        List<Map<String, Object>> trapdoors = new ArrayList<>();
        Map<String, Object> envelopes = new LinkedHashMap<>();
        Map<String, Object> retrieval = new LinkedHashMap<>();
        long t0 = System.currentTimeMillis();

        for (Map<String, Object> doc : documentsOf(null)) {
            String docId = (String) doc.get("documentId");
            String ownerId = (String) doc.get("ownerUserId");

            // Application-level revocation (checked by the owner side of Authorize).
            if (isRevoked(ownerId, userId)) {
                denied.add(Http.map("documentId", docId, "owner", ownerId,
                        "reason", "Access revoked by the data owner"));
                continue;
            }

            Secrets owner = secrets(ownerId);
            KeyGen.K K = owner.K.withAccessStructure(AccessPolicy.fromExpression(mpk, (String) doc.get("policy")));

            // ---- Algorithm 5: Authorize ----
            Authorize.Proof rho = Authorize.clientProof(mpk, client.pk, client.sk);  // lines 1-8 (client)
            Authorize.Token TK;
            try {
                TK = Authorize.ownerAuthorize(mpk, R, client.pk, rho, Sc, K, owner.sk); // lines 9-19 (owner)
            } catch (IllegalArgumentException e) {
                denied.add(Http.map("documentId", docId, "owner", ownerId, "reason", e.getMessage()));
                continue;   // no trapdoor is generated
            }
            byte[] k = K.k;                                                          // lines 20-21

            // ---- Extension: owner approval (checked after Authorize, before TrapGen) ----
            // The request names only the user and the document; the keyword is never
            // shown to the owner, as in the paper's Authorize (TK is keyword-independent).
            String approval = approvalGate(doc, userId);
            if (approval != null) {
                denied.add(Http.map("documentId", docId, "owner", ownerId, "fileName", doc.get("fileName"),
                        "approval", approval,
                        "reason", "PENDING".equals(approval)
                                ? "Waiting for the owner to approve your access request"
                                : "The owner denied your access request"));
                continue;   // no trapdoor is generated
            }

            // ---- Algorithm 6: TrapGen (new trapdoor for every search) ----
            TrapGen.Trapdoor T = TrapGen.trapGen(mpk, w, client.sk, TK);

            // ---- Extension: one-time envelope signed by the owner (proxy) ----
            Map<String, Object> env = TrapdoorEnvelope.issue(mpk, docId, T, owner.sk, owner.pk);
            String trapdoorId = (String) env.get("trapdoorId");

            // ---- Algorithm 7 at the CSP ----
            Map<String, Object> res = csp.post("/csp/api/search", Http.map("envelope", env, "submittedBy", userId));
            boolean accepted = Boolean.TRUE.equals(res.get("accepted"));
            List<Object> C = Codec.list(res.get("matches"));

            Map<String, Object> td = Http.map(
                    "trapdoorId", trapdoorId,
                    "trapdoorHash", res.get("trapdoorHash"),
                    "documentId", docId,
                    "status", res.get("status"),
                    "matched", !C.isEmpty());
            trapdoors.add(td);
            envelopes.put(trapdoorId, env);
            if (!accepted) {
                td.put("message", res.get("message"));
                continue;
            }

            // ---- Algorithm 8: Decrypt the matching ct4 -> document ids ----
            List<String> ids = new ArrayList<>();
            for (Object ct4 : C) {
                try {
                    ids.addAll(Decrypt.decrypt(k, (String) ct4));
                } catch (Exception e) {
                    td.put("message", "Decrypt failed");
                }
            }
            if (ids.contains(docId)) {
                matches.add(Http.map(
                        "documentId", docId,
                        "fileName", doc.get("fileName"),
                        "owner", ownerId,
                        "sizeBytes", doc.get("sizeBytes"),
                        "contentType", doc.get("contentType"),
                        "policy", doc.get("policy"),
                        "decryptedIds", ids,
                        "trapdoorId", trapdoorId,
                        "permissions", permissionsFor(doc, userId),
                        "currentVersion", currentVersionOf(doc)));
                retrieval.put(docId, res.get("retrievalTicket"));
            }
        }

        long ms = System.currentTimeMillis() - t0;
        searchSessions.put(searchId, Http.map("userId", userId, "created", System.currentTimeMillis(),
                "tickets", retrieval));
        pruneSearchSessions();
        // NOTE: the plaintext keyword is deliberately not logged.
        audit("SEARCH", userId, "Authorize+TrapGen for " + trapdoors.size() + " document(s), "
                + denied.size() + " denied, " + matches.size() + " match(es), " + ms + " ms");

        return Http.map(
                "searchId", searchId,
                "documentsConsidered", trapdoors.size() + denied.size(),
                "authorizedDocuments", trapdoors.size(),
                "denied", denied,
                "matches", matches,
                "trapdoors", trapdoors,
                "envelopes", envelopes,
                "millis", ms,
                "accessDenied", trapdoors.isEmpty());
    }

    private void pruneSearchSessions() {
        long cutoff = System.currentTimeMillis() - 30 * 60 * 1000L;
        searchSessions.values().removeIf(s -> ((Number) s.get("created")).longValue() < cutoff);
    }

    /**
     * Fetches the encrypted current version for a document returned by the
     * user's search. The CSP releases the ciphertext once per search (single-use
     * ticket); the ciphertext - never the plaintext - is kept in the search
     * session so the user can view, download and edit within that session.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchForSearch(String userId, String searchId, String docId) {
        requireSetup();
        Map<String, Object> session = searchSessions.get(searchId);
        if (session == null || !userId.equals(session.get("userId"))) {
            throw new ApiException(403, "Search session expired - search again");
        }
        Map<String, Object> doc = document(docId);
        String ownerId = (String) doc.get("ownerUserId");
        if (isRevoked(ownerId, userId)) throw new ApiException(403, "Access revoked by the data owner");
        if (approvalGate(doc, userId) != null) throw new ApiException(403, "The owner has not approved your access to this document");
        AccessPolicy policy = AccessPolicy.fromExpression(mpk, (String) doc.get("policy"));
        if (!policy.isSatisfiedBy(mpk.getPairing(), attributesOf(userId))) {
            throw new ApiException(403, "Attributes do not satisfy the access policy");
        }
        Map<String, Object> fetched = (Map<String, Object>) session.computeIfAbsent("fetched", k -> new ConcurrentHashMap<String, Object>());
        Map<String, Object> c = (Map<String, Object>) fetched.get(docId);
        if (c == null) {
            Map<String, Object> tickets = (Map<String, Object>) session.get("tickets");
            Object ticket = tickets.remove(docId);
            if (ticket == null) throw new ApiException(403, "This document was not returned by your search - search again");
            c = csp.post("/csp/api/documents/" + docId + "/retrieve", Http.map("ticket", ticket, "submittedBy", userId));
            fetched.put(docId, c);
        }
        return c;
    }

    private void requirePermission(Map<String, Object> doc, String userId, String permission, String action) {
        if (!permissionsFor(doc, userId).contains(permission)) {
            throw new ApiException(403, "The owner has not given you permission to " + action + " this document");
        }
    }

    /** Download (needs the DOWNLOAD permission). */
    public synchronized Map<String, Object> retrieve(String userId, String searchId, String docId) {
        Map<String, Object> doc = document(docId);
        requirePermission(doc, userId, DOWNLOAD, "download");
        Map<String, Object> c = fetchForSearch(userId, searchId, docId);
        byte[] plain = openDocument((String) doc.get("ownerUserId"), docId, c);
        int version = ((Number) c.getOrDefault("version", 1)).intValue();
        audit("DOWNLOAD", userId, "document " + docId + " version " + version + " decrypted after authorized search");
        Map<String, Object> copy = traceableCopy(doc, userId, version, plain, "DOWNLOAD");
        if (copy != null) plain = (byte[]) copy.get("bytes");
        documentLog(docId, (String) doc.get("ownerUserId"), userId, "DOWNLOADED", version,
                copy == null ? "Downloaded the document" : "Downloaded a traceable copy (ref " + copy.get("copyId") + ")");
        return Http.map("bytes", plain, "fileName", doc.get("fileName"), "contentType", doc.get("contentType"));
    }

    /** View in the browser (needs the VIEW permission). */
    public synchronized Map<String, Object> view(String userId, String searchId, String docId) {
        Map<String, Object> doc = document(docId);
        requirePermission(doc, userId, VIEW, "view");
        Map<String, Object> c = fetchForSearch(userId, searchId, docId);
        byte[] plain = openDocument((String) doc.get("ownerUserId"), docId, c);
        int version = ((Number) c.getOrDefault("version", 1)).intValue();
        documentLog(docId, (String) doc.get("ownerUserId"), userId, "VIEWED", version, "Viewed the document in the browser");
        Map<String, Object> out = Http.map(
                "documentId", docId,
                "fileName", doc.get("fileName"),
                "contentType", doc.get("contentType"),
                "version", version,
                "sizeBytes", plain.length,
                "permissions", permissionsFor(doc, userId),
                "viewer", Http.map("userId", userId, "displayName", user(userId).get("displayName"),
                        "at", java.time.ZonedDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm"))));
        String type = String.valueOf(doc.get("contentType"));
        if (TextDiff.isText(type, String.valueOf(doc.get("fileName")), plain) && plain.length <= 2 * 1024 * 1024) {
            out.put("kind", "text");
            // the text shown on the View page is a traceable copy too (backup for
            // anyone who takes the text out of the page with developer tools)
            Map<String, Object> copy = traceableCopy(doc, userId, version, plain, "VIEW");
            byte[] shown = copy == null ? plain : (byte[]) copy.get("bytes");
            out.put("text", new String(shown, java.nio.charset.StandardCharsets.UTF_8));
        } else if (type.startsWith("image/") && plain.length <= 15 * 1024 * 1024) {
            out.put("kind", "image");
            out.put("dataBase64", CryptoUtil.b64(plain));
        } else if (type.equals("application/pdf") && plain.length <= 15 * 1024 * 1024) {
            out.put("kind", "pdf");
            out.put("dataBase64", CryptoUtil.b64(plain));
        } else {
            out.put("kind", "unsupported");
        }
        return out;
    }

    // ================================================================
    // MAKER-CHECKER CHANGES (project extension)
    //   maker  : a user with MODIFY permission proposes a new version;
    //            it is encrypted, signed with the editor's key and stored
    //            at the CSP as PENDING. Other users keep seeing the
    //            current approved version.
    //   checker: the owner reviews the differences and approves or rejects.
    //   Every version is kept; the original upload is always version 1.
    // ================================================================

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> proposeChange(String userId, String docId, String searchId,
                                                          String newText, byte[] newBytes, String note) {
        Map<String, Object> doc = document(docId);
        String ownerId = (String) doc.get("ownerUserId");
        if (ownerId.equals(userId)) throw new ApiException(400, "You own this document - upload a new document instead");
        requirePermission(doc, userId, MODIFY, "change");
        Map<String, Object> c = fetchForSearch(userId, searchId, docId);
        int baseVersion = ((Number) c.getOrDefault("version", 1)).intValue();
        byte[] before = openDocument(ownerId, docId, c);
        byte[] after;
        if (newText != null) {
            // The editor worked on his own traceable copy: remove its hidden code and
            // put back the owner's wording wherever the editor did not change it.
            String clean = Watermark.strip(newText);
            if (TextDiff.isText(String.valueOf(doc.get("contentType")), String.valueOf(doc.get("fileName")), before)) {
                clean = TextVariation.restoreOriginalForms(new String(before, java.nio.charset.StandardCharsets.UTF_8), clean);
            }
            after = clean.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        else if (newBytes != null && newBytes.length > 0) after = newBytes;
        else throw new ApiException(400, "Provide the changed content");
        if (Arrays.equals(before, after)) throw new ApiException(400, "Nothing was changed");
        String why = note == null ? "" : note.trim();
        if (why.isEmpty()) throw new ApiException(400, "Describe what you changed");
        if (why.length() > 500) why = why.substring(0, 500);

        // Encrypt the new version exactly like an upload: a fresh random AES
        // key, wrapped under the owner's k, so authorized users can read it
        // after approval.
        Secrets owner = secrets(ownerId);
        DocumentCrypto.Encrypted enc = DocumentCrypto.encrypt(after, docId, owner.K.k);
        Arrays.fill(enc.fileKey, (byte) 0);
        // The editor signs this exact encrypted version (accountability).
        Secrets editor = secrets(userId);
        String hash = CryptoUtil.sha256Hex(enc.sealedDocument);
        String[] sig = SchnorrSignature.sign(mpk, editor.sk, editor.pk,
                minos.csp.CspServer.versionMessage(docId, baseVersion, hash, why));
        Map<String, Object> res = csp.post("/csp/api/documents/" + docId + "/versions", Http.map(
                "encryptedDocumentBase64", CryptoUtil.b64(enc.sealedDocument),
                "wrappedFileKeyBase64", CryptoUtil.b64(enc.wrappedFileKey),
                "editorPublicKey", Codec.enc(editor.pk),
                "baseVersion", baseVersion,
                "note", why,
                "sigR", sig[0], "sigS", sig[1]));
        int version = ((Number) res.get("version")).intValue();

        String summary = TextDiff.summary(before, after, String.valueOf(doc.get("contentType")),
                String.valueOf(doc.get("fileName")));
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        Map<String, Object> d = (Map<String, Object>) docs.get(docId);
        List<Object> versions = versionsOf(d);
        versions.add(Http.map(
                "version", version,
                "baseVersion", baseVersion,
                "status", "PENDING",
                "proposedBy", userId,
                "proposedAt", java.time.Instant.now().toString(),
                "note", why,
                "summary", summary,
                "sizeBytes", after.length));
        d.put("versions", versions);
        store.write(DOCUMENTS, docs);
        audit("CHANGE_PROPOSED", userId, "document " + docId + " version " + version + " (pending owner approval)");
        documentLog(docId, ownerId, userId, "CHANGE_PROPOSED", version, summary + " - \"" + why + "\"");
        return Http.map("documentId", docId, "version", version, "status", "PENDING", "summary", summary);
    }

    /** The version list of a document; version 1 is the owner's original upload. */
    @SuppressWarnings("unchecked")
    private List<Object> versionsOf(Map<String, Object> d) {
        if (d.get("versions") instanceof List) return (List<Object>) d.get("versions");
        List<Object> versions = new ArrayList<>();
        versions.add(Http.map(
                "version", 1,
                "baseVersion", 0,
                "status", "APPROVED",
                "proposedBy", d.get("ownerUserId"),
                "proposedAt", d.get("uploadedAt"),
                "note", "Original upload",
                "summary", "Original upload",
                "sizeBytes", d.get("sizeBytes")));
        return versions;
    }

    private int currentVersionOf(Map<String, Object> d) {
        Object v = d.get("currentVersion");
        return v instanceof Number ? ((Number) v).intValue() : 1;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> ownerChanges(String ownerId) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> d : documentsOf(ownerId)) {
            for (Object o : versionsOf(d)) {
                Map<String, Object> v = new LinkedHashMap<>((Map<String, Object>) o);
                if (((Number) v.get("version")).intValue() == 1) continue;
                v.put("documentId", d.get("documentId"));
                v.put("fileName", d.get("fileName"));
                v.put("currentVersion", currentVersionOf(d));
                out.add(v);
            }
        }
        Collections.reverse(out);
        return Http.map("changes", out);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> userChanges(String userId) {
        List<Object> out = new ArrayList<>();
        for (Map<String, Object> d : documentsOf(null)) {
            for (Object o : versionsOf(d)) {
                Map<String, Object> v = (Map<String, Object>) o;
                if (((Number) v.get("version")).intValue() == 1 || !userId.equals(v.get("proposedBy"))) continue;
                Map<String, Object> copy = new LinkedHashMap<>(v);
                copy.put("documentId", d.get("documentId"));
                copy.put("fileName", d.get("fileName"));
                copy.put("owner", d.get("ownerUserId"));
                out.add(copy);
            }
        }
        Collections.reverse(out);
        return Http.map("changes", out);
    }

    /** Owner review: line-by-line differences between the base version and the proposal. */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> changeDetails(String ownerId, String docId, int version) {
        Map<String, Object> doc = document(docId);
        if (!ownerId.equals(doc.get("ownerUserId"))) throw new ApiException(403, "Not your document");
        Map<String, Object> v = null;
        for (Object o : versionsOf(doc)) {
            if (((Number) ((Map<String, Object>) o).get("version")).intValue() == version) v = (Map<String, Object>) o;
        }
        if (v == null || version == 1) throw new ApiException(404, "Unknown change");
        int base = ((Number) v.get("baseVersion")).intValue();
        byte[] before = ownerVersionBytes(ownerId, docId, base);
        byte[] after = ownerVersionBytes(ownerId, docId, version);
        Map<String, Object> out = new LinkedHashMap<>(v);
        out.put("documentId", docId);
        out.put("fileName", doc.get("fileName"));
        out.put("currentVersion", currentVersionOf(doc));
        out.put("basedOnOlderVersion", base != currentVersionOf(doc));
        String type = String.valueOf(doc.get("contentType"));
        String name = String.valueOf(doc.get("fileName"));
        if (TextDiff.isText(type, name, before) && TextDiff.isText(type, name, after)) {
            out.put("kind", "text");
            out.put("lines", TextDiff.diff(new String(before, java.nio.charset.StandardCharsets.UTF_8),
                    new String(after, java.nio.charset.StandardCharsets.UTF_8)));
        } else {
            out.put("kind", "binary");
            out.put("beforeBytes", before.length);
            out.put("afterBytes", after.length);
        }
        documentLog(docId, ownerId, ownerId, "CHANGE_REVIEWED", version, "Owner opened the change for review");
        return out;
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> decideChange(String ownerId, String docId, int version,
                                                         boolean approve, String comment) {
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        Map<String, Object> d = (Map<String, Object>) docs.get(docId);
        if (d == null) throw new ApiException(404, "Unknown document");
        if (!ownerId.equals(d.get("ownerUserId"))) throw new ApiException(403, "Not your document");
        List<Object> versions = versionsOf(d);
        Map<String, Object> v = null;
        for (Object o : versions) {
            if (((Number) ((Map<String, Object>) o).get("version")).intValue() == version) v = (Map<String, Object>) o;
        }
        if (v == null || version == 1) throw new ApiException(404, "Unknown change");
        if (!"PENDING".equals(v.get("status"))) throw new ApiException(409, "This change was already decided");
        csp.post("/csp/api/documents/" + docId + "/versions/" + version + "/decision", Http.map("approve", approve));
        String why = comment == null ? "" : comment.trim();
        v.put("status", approve ? "APPROVED" : "REJECTED");
        v.put("decidedAt", java.time.Instant.now().toString());
        v.put("ownerComment", why);
        if (approve) {
            d.put("currentVersion", version);
            d.put("sizeBytes", v.get("sizeBytes"));
        }
        d.put("versions", versions);
        store.write(DOCUMENTS, docs);
        audit(approve ? "CHANGE_APPROVED" : "CHANGE_REJECTED", ownerId, "document " + docId + " version " + version);
        documentLog(docId, ownerId, (String) v.get("proposedBy"), approve ? "CHANGE_APPROVED" : "CHANGE_REJECTED", version,
                (approve ? "Owner approved the change" : "Owner rejected the change") + (why.isEmpty() ? "" : ": " + why));
        return Http.map("documentId", docId, "version", version, "status", v.get("status"),
                "currentVersion", currentVersionOf(d));
    }

    /** Recent activity on all documents of one owner (newest first). */
    public Map<String, Object> ownerDocumentLog(String ownerId) {
        List<Object> log = new ArrayList<>();
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        for (Map<String, Object> e : store.tailLog(DOCUMENT_LOG, 100000)) {
            if (ownerId.equals(e.get("ownerUserId"))) {
                Map<String, Object> copy = new LinkedHashMap<>(e);
                Object d = docs.get(e.get("documentId"));
                if (d instanceof Map) copy.put("fileName", ((Map<?, ?>) d).get("fileName"));
                log.add(copy);
            }
        }
        // tailLog returns the newest entries first
        if (log.size() > 200) log = new ArrayList<>(log.subList(0, 200));
        return Http.map("log", log);
    }

    /** Versions + full access log of one document, for its owner. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> documentHistory(String ownerId, String docId) {
        Map<String, Object> doc = document(docId);
        if (!ownerId.equals(doc.get("ownerUserId"))) throw new ApiException(403, "Not your document");
        List<Object> log = new ArrayList<>();
        for (Map<String, Object> e : store.tailLog(DOCUMENT_LOG, 100000)) {
            if (docId.equals(e.get("documentId"))) log.add(e);
        }
        Collections.reverse(log);
        List<Object> versions = new ArrayList<>(versionsOf(doc));
        Collections.reverse(versions);
        return Http.map("documentId", docId, "fileName", doc.get("fileName"), "policy", doc.get("policy"),
                "currentVersion", currentVersionOf(doc), "versions", versions, "log", log);
    }

    private byte[] ownerVersionBytes(String ownerId, String docId, int version) {
        Map<String, Object> c = csp.post("/csp/api/documents/" + docId + "/owner-retrieve",
                Http.map("submittedBy", ownerId, "version", version));
        return openDocument(ownerId, docId, c);
    }

    private void documentLog(String docId, String ownerId, String userId, String action, int version, String detail) {
        store.log(DOCUMENT_LOG, Http.map("documentId", docId, "ownerUserId", ownerId, "userId", userId,
                "action", action, "version", version, "detail", detail));
    }

    /** What a user may do with a document. */
    @SuppressWarnings("unchecked")
    public List<String> permissionsFor(Map<String, Object> doc, String userId) {
        List<String> out = new ArrayList<>();
        String ownerId = (String) doc.get("ownerUserId");
        if (ownerId.equals(userId)) {
            out.add(VIEW);
            out.add(DOWNLOAD);
            return out;
        }
        if (!Boolean.TRUE.equals(doc.get("requireApproval"))) {
            out.add(VIEW);
            out.add(DOWNLOAD);
            return out;
        }
        Map<String, Object> r = findRequest(store.readList(ACCESS_REQUESTS), (String) doc.get("documentId"), userId);
        if (r == null || !"APPROVED".equals(r.get("status"))) return out;
        Object p = r.get("permissions");
        if (!(p instanceof List)) {
            out.add(VIEW);
            out.add(DOWNLOAD);
            return out;
        }
        for (Object o : (List<Object>) p) out.add(String.valueOf(o));
        return out;
    }

    private static String describePermissions(List<String> p) {
        List<String> words = new ArrayList<>();
        if (p.contains(VIEW)) words.add("view");
        if (p.contains(DOWNLOAD)) words.add("download");
        if (p.contains(MODIFY)) words.add("modify (owner approves each change)");
        return String.join(", ", words);
    }

    public synchronized Map<String, Object> ownerDownload(String ownerId, String docId) {
        return ownerDownload(ownerId, docId, 0);
    }

    /** Owner download of any version; 0 = current, 1 = the original upload. */
    public synchronized Map<String, Object> ownerDownload(String ownerId, String docId, int version) {
        Map<String, Object> doc = document(docId);
        if (!ownerId.equals(doc.get("ownerUserId"))) throw new ApiException(403, "Not your document");
        Map<String, Object> c = csp.post("/csp/api/documents/" + docId + "/owner-retrieve",
                Http.map("submittedBy", ownerId, "version", version));
        byte[] plain = openDocument(ownerId, docId, c);
        int got = ((Number) c.getOrDefault("version", 1)).intValue();
        audit("OWNER_DOWNLOAD", ownerId, "document " + docId + " version " + got);
        documentLog(docId, ownerId, ownerId, "OWNER_DOWNLOADED", got,
                got == 1 ? "Owner downloaded the original version" : "Owner downloaded version " + got);
        String name = String.valueOf(doc.get("fileName"));
        if (version > 0 && got != currentVersionOf(doc)) {
            int dot = name.lastIndexOf('.');
            String tag = got == 1 ? "original" : "v" + got;
            name = dot > 0 ? name.substring(0, dot) + "-" + tag + name.substring(dot) : name + "-" + tag;
        }
        return Http.map("bytes", plain, "fileName", name, "contentType", doc.get("contentType"));
    }

    /** k is the secret Authorize releases ("return TK and k"); it unwraps the file key. */
    private byte[] openDocument(String ownerId, String docId, Map<String, Object> c) {
        byte[] k = secrets(ownerId).K.k;
        byte[] fileKey = DocumentCrypto.unwrapFileKey(k, docId, CryptoUtil.unb64((String) c.get("wrappedFileKeyBase64")));
        try {
            return DocumentCrypto.decrypt(fileKey, docId, CryptoUtil.unb64((String) c.get("encryptedDocumentBase64")));
        } finally {
            Arrays.fill(fileKey, (byte) 0);
        }
    }

    // ================================================================
    // REPLAY TEST: forward a previously used trapdoor unchanged
    // ================================================================

    public Map<String, Object> submitTrapdoor(String submittedBy, Map<String, Object> envelope) {
        requireSetup();
        Map<String, Object> res = csp.post("/csp/api/search", Http.map("envelope", envelope, "submittedBy", submittedBy));
        audit("TRAPDOOR_SUBMITTED", submittedBy, "manual trapdoor submission -> " + res.get("status"));
        res.remove("success");
        res.remove("retrievalTicket");   // the security console never downloads
        return res;
    }

    // ================================================================
    // 9. DETECT (Algorithm 9 / Algorithm 11) for a CSP alert
    // ================================================================

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> runDetect(String alertId) {
        requireSetup();
        Map<String, Object> alert = Codec.map(csp.get("/csp/api/alerts/" + alertId).get("alert"));
        Map<String, Object> env = Codec.map(alert.get("trapdoorEnvelope"));
        String docId = (String) alert.get("documentId");
        Map<String, Object> doc = document(docId);
        String ownerId = (String) doc.get("ownerUserId");

        Secrets owner = secrets(ownerId);
        KeyGen.K K = owner.K.withAccessStructure(AccessPolicy.fromExpression(mpk, (String) doc.get("policy")));
        List<String> W = (List<String>) (List<?>) vault.get("doc-" + docId).get("keywords");

        TrapGen.Trapdoor T = TrapGen.Trapdoor.fromJson(mpk, Codec.map(env.get("trapdoor")));
        Element pkc;
        String algorithm;
        String integrity;
        try {
            // Algorithm 11: verifies tk6, tk5, tk1/tk2, tk4 (and tk7), returns pk_c.
            pkc = Detect.detectEnhanced(mpk, T, owner.sk, K, W).pkc;
            algorithm = "11";
            integrity = "verified: trapdoor components are unmodified";
        } catch (IllegalStateException e) {
            // Algorithm 9: pk_c = tk3^(1/sk_o^2)
            pkc = Detect.detect(T.tk3, owner.sk);
            algorithm = "9";
            integrity = "FAILED (" + e.getMessage() + "); identity from tk3 only";
        }
        Map<String, Object> res = csp.post("/csp/api/alerts/" + alertId + "/detect-result", Http.map(
                "publicKey", Codec.enc(pkc),
                "tk3", Codec.enc(T.tk3),
                "algorithm", algorithm,
                "integrity", integrity));
        audit("DETECT", ownerId, "alert " + alertId + ": Algorithm " + algorithm + " -> " + res.get("identifiedUserId"));
        return Http.map("alertId", alertId, "identifiedUserId", res.get("identifiedUserId"),
                "algorithm", algorithm, "integrity", integrity);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> ownerAlerts(String ownerId) {
        requireSetup();
        List<Object> alerts = Codec.list(csp.get("/csp/api/alerts?ownerUserId=" + ownerId).get("alerts"));
        boolean changed = false;
        for (Object o : alerts) {
            Map<String, Object> a = Codec.map(o);
            if ("PENDING".equals(a.get("detectStatus"))) {
                try {
                    runDetect((String) a.get("alertId"));
                    changed = true;
                } catch (RuntimeException e) {
                    a.put("detectError", e.getMessage());
                }
            }
        }
        if (changed) alerts = Codec.list(csp.get("/csp/api/alerts?ownerUserId=" + ownerId).get("alerts"));
        List<Object> out = new ArrayList<>();
        for (Object o : alerts) {
            Map<String, Object> a = new LinkedHashMap<>(Codec.map(o));
            Object who = a.get("identifiedUserId");
            a.put("identifiedUserRevoked", who != null && isRevoked(ownerId, (String) who));
            Map<String, Object> d = (Map<String, Object>) store.readMap(DOCUMENTS).get(a.get("documentId"));
            if (d != null) a.put("fileName", d.get("fileName"));
            out.add(a);
        }
        java.util.Collections.reverse(out);
        List<Object> view = viewAlertsFor(ownerId);
        java.util.Collections.reverse(view);
        view.addAll(out);
        // mark which alerts the owner has already seen (the menu badge counts only new ones)
        java.util.Set<String> seen = seenAlertKeys(ownerId);
        int unseen = 0;
        for (Object o : view) {
            Map<String, Object> a = (Map<String, Object>) o;
            boolean s = seen.contains(alertKey(a));
            a.put("seen", s);
            if (!s) unseen++;
        }
        return Http.map("alerts", view, "unseen", unseen);
    }

    /** An alert counts as new again when a grouped alert repeats (its count grows). */
    static String alertKey(Map<String, Object> a) {
        return a.get("alertId") + "#" + (a.get("count") == null ? "" : String.valueOf(a.get("count")));
    }

    @SuppressWarnings("unchecked")
    private java.util.Set<String> seenAlertKeys(String ownerId) {
        Object list = store.readMap(ALERTS_SEEN).get(ownerId);
        java.util.Set<String> out = new java.util.HashSet<>();
        if (list instanceof List) for (Object k : (List<Object>) list) out.add(String.valueOf(k));
        return out;
    }

    /** Called when the owner opens the Security alerts page. */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> markAlertsSeen(String ownerId) {
        List<Object> keys = new ArrayList<>();
        for (Object o : (List<Object>) ownerAlerts(ownerId).get("alerts")) keys.add(alertKey((Map<String, Object>) o));
        Map<String, Object> all = store.readMap(ALERTS_SEEN);
        all.put(ownerId, keys);
        store.write(ALERTS_SEEN, all);
        return Http.map("seen", keys.size());
    }

    // ================================================================
    // REVOCATION (project extension, uses the paper's suspension hook)
    // ================================================================

    @SuppressWarnings("unchecked")
    public boolean isRevoked(String ownerId, String userId) {
        for (Object o : store.readList(REVOCATIONS)) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (ownerId.equals(r.get("ownerUserId")) && userId.equals(r.get("userId"))) return true;
        }
        return false;
    }

    public synchronized Map<String, Object> revoke(String ownerId, String userId, String alertId) {
        requireSetup();
        Map<String, Object> target = user(userId);
        if (ownerId.equals(userId)) throw new ApiException(400, "You cannot revoke yourself");
        if (!isRevoked(ownerId, userId)) {
            List<Object> list = store.readList(REVOCATIONS);
            list.add(Http.map("ownerUserId", ownerId, "userId", userId, "alertId", alertId,
                    "revokedAt", java.time.Instant.now().toString()));
            store.write(REVOCATIONS, list);
        }
        // tk3 = pk_c^(sk_o^2) is the value every trapdoor of this user carries for
        // this owner; the CSP refuses trapdoors linked to it (paper VI-A.4).
        Secrets owner = secrets(ownerId);
        Element pkc = Codec.g1(mpk, (String) target.get("publicKey"));
        Element tk3 = pkc.duplicate().powZn(owner.sk.duplicate().mul(owner.sk));
        csp.post("/csp/api/suspensions", Http.map("ownerUserId", ownerId, "userId", userId, "tk3", Codec.enc(tk3)));
        audit("REVOKE", ownerId, "revoked " + userId + (alertId == null ? "" : " (alert " + alertId + ")"));
        return Http.map("revoked", userId);
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> restore(String ownerId, String userId) {
        List<Object> list = store.readList(REVOCATIONS);
        list.removeIf(o -> ownerId.equals(((Map<String, Object>) o).get("ownerUserId"))
                && userId.equals(((Map<String, Object>) o).get("userId")));
        store.write(REVOCATIONS, list);
        csp.post("/csp/api/suspensions/remove", Http.map("ownerUserId", ownerId, "userId", userId));
        audit("RESTORE", ownerId, "restored " + userId);
        return Http.map("restored", userId);
    }

    @SuppressWarnings("unchecked")
    public List<Object> revocationsOf(String ownerId) {
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(REVOCATIONS)) {
            if (ownerId.equals(((Map<String, Object>) o).get("ownerUserId"))) out.add(o);
        }
        return out;
    }

    // ================================================================
    // ACCESS REQUESTS (project extension): the owner approves or denies
    // each user per document. Applies only to documents uploaded with
    // "require my approval". Authorize (Algorithm 5) still decides whether
    // the user's attributes satisfy (M, pi); approval is an extra gate.
    // ================================================================

    @SuppressWarnings("unchecked")
    private Map<String, Object> findRequest(List<Object> list, String docId, String userId) {
        for (Object o : list) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (docId.equals(r.get("documentId")) && userId.equals(r.get("userId"))) return r;
        }
        return null;
    }

    /** NONE, PENDING, APPROVED or DENIED. */
    public String approvalStatus(String docId, String userId) {
        Map<String, Object> r = findRequest(store.readList(ACCESS_REQUESTS), docId, userId);
        return r == null ? "NONE" : (String) r.get("status");
    }

    /**
     * Returns null when the user may continue (approved, approval not required,
     * or the user owns the document). Otherwise creates the request if needed
     * and returns PENDING or DENIED.
     */
    private synchronized String approvalGate(Map<String, Object> doc, String userId) {
        String ownerId = (String) doc.get("ownerUserId");
        if (ownerId.equals(userId) || !Boolean.TRUE.equals(doc.get("requireApproval"))) return null;
        String docId = (String) doc.get("documentId");
        List<Object> list = store.readList(ACCESS_REQUESTS);
        Map<String, Object> r = findRequest(list, docId, userId);
        if (r == null) {
            r = Http.map("requestId", "AR-" + CryptoUtil.randomId(6), "documentId", docId,
                    "fileName", doc.get("fileName"), "ownerUserId", ownerId, "userId", userId,
                    "userAttributes", new ArrayList<>(attributesOf(userId)),
                    "status", "PENDING", "requestedAt", java.time.Instant.now().toString());
            list.add(r);
            store.write(ACCESS_REQUESTS, list);
            audit("ACCESS_REQUESTED", userId, "access request " + r.get("requestId") + " for " + docId);
        }
        String st = (String) r.get("status");
        return "APPROVED".equals(st) ? null : st;
    }

    @SuppressWarnings("unchecked")
    public List<Object> accessRequestsForOwner(String ownerId) {
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(ACCESS_REQUESTS)) {
            if (ownerId.equals(((Map<String, Object>) o).get("ownerUserId"))) out.add(o);
        }
        Collections.reverse(out);
        return out;
    }

    @SuppressWarnings("unchecked")
    public List<Object> accessRequestsForUser(String userId) {
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(ACCESS_REQUESTS)) {
            if (userId.equals(((Map<String, Object>) o).get("userId"))) out.add(o);
        }
        Collections.reverse(out);
        return out;
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> decideAccessRequest(String ownerId, String requestId, boolean approve) {
        return decideAccessRequest(ownerId, requestId, approve, null);
    }

    /**
     * Owner decision on an access request. When approving, the owner chooses
     * what the user may do: VIEW (read in the browser), DOWNLOAD, MODIFY
     * (propose changes, which the owner must approve - maker-checker).
     * Anyone allowed to download or modify may also view.
     */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> decideAccessRequest(String ownerId, String requestId, boolean approve,
                                                                List<Object> permissions) {
        List<Object> list = store.readList(ACCESS_REQUESTS);
        for (Object o : list) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (!requestId.equals(r.get("requestId"))) continue;
            if (!ownerId.equals(r.get("ownerUserId"))) throw new ApiException(403, "Not your document");
            List<String> granted = new ArrayList<>();
            if (approve) {
                if (permissions == null) {
                    granted.add(VIEW);
                    granted.add(DOWNLOAD);
                } else {
                    boolean view = false, download = false, modify = false;
                    for (Object p : permissions) {
                        String name = String.valueOf(p).toUpperCase(Locale.ROOT);
                        if (name.equals(VIEW)) view = true;
                        else if (name.equals(DOWNLOAD)) download = true;
                        else if (name.equals(MODIFY)) modify = true;
                        else throw new ApiException(400, "Unknown permission: " + p);
                    }
                    if (download || modify) view = true;
                    if (!view) throw new ApiException(400, "Choose at least one permission");
                    if (view) granted.add(VIEW);
                    if (download) granted.add(DOWNLOAD);
                    if (modify) granted.add(MODIFY);
                }
            }
            r.put("status", approve ? "APPROVED" : "DENIED");
            r.put("permissions", granted);
            r.put("decidedAt", java.time.Instant.now().toString());
            store.write(ACCESS_REQUESTS, list);
            audit(approve ? "ACCESS_APPROVED" : "ACCESS_DENIED", ownerId,
                    r.get("userId") + " for " + r.get("documentId") + (approve ? " " + granted : ""));
            documentLog((String) r.get("documentId"), ownerId, (String) r.get("userId"),
                    approve ? "ACCESS_GRANTED" : "ACCESS_DENIED", 0,
                    approve ? "Permissions: " + describePermissions(granted) : "Access request denied");
            return Http.map("requestId", requestId, "status", r.get("status"), "permissions", granted);
        }
        throw new ApiException(404, "Access request not found");
    }

    // ================================================================
    // 10. TRACE (Algorithm 10): ownership claims
    // ================================================================

    /**
     * Ownership claim (dispute). Any logged-in user may claim any document.
     * Paper part: the help data hp is built from the claimant's own keys
     * (Algorithm 10, claimant side) and the CSP runs Trace.
     * Extension: the claim is signed with the claimant's registered key, the
     * CSP records it, alerts the real owner on a false claim, and blocks
     * claimants with repeated false claims.
     */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> claimOwnership(String claimantId, String docId, String keywordGuess,
                                                           String reason) {
        requireSetup();
        Map<String, Object> doc = document(docId);
        boolean isOwner = claimantId.equals(doc.get("ownerUserId"));
        Secrets claimant = secrets(claimantId);
        KeyGen.K K = claimant.K.withAccessStructure(AccessPolicy.fromExpression(mpk, (String) doc.get("policy")));
        String w;
        if (isOwner) {
            w = ((List<String>) (List<?>) vault.get("doc-" + docId).get("keywords")).get(0);
        } else {
            w = normalizeKeyword(keywordGuess == null || keywordGuess.isBlank() ? "guess" : keywordGuess);
        }
        String why = reason == null ? "" : reason.trim();
        if (why.length() > 500) why = why.substring(0, 500);
        Trace.HelpData hp = Trace.help(mpk, w, claimant.sk, claimant.pk, K);
        String helpJson = Json.write(hp.toJson());
        String claimedAt = java.time.Instant.now().toString();
        String message = minos.csp.CspServer.claimMessage(docId, claimedAt,
                CryptoUtil.sha256Hex(helpJson.getBytes(java.nio.charset.StandardCharsets.UTF_8)), why);
        String[] sig = SchnorrSignature.sign(mpk, claimant.sk, claimant.pk, message);
        Map<String, Object> res = csp.post("/csp/api/trace", Http.map(
                "documentId", docId, "helpDataJson", helpJson, "claimantPublicKey", Codec.enc(claimant.pk),
                "claimedAt", claimedAt, "reason", why, "sigR", sig[0], "sigS", sig[1]));
        boolean valid = Boolean.TRUE.equals(res.get("valid"));
        audit("TRACE", claimantId, "ownership claim on " + docId + " -> " + res.get("status"));
        Map<String, Object> out = new LinkedHashMap<>(res);
        out.remove("success");
        out.put("fileName", doc.get("fileName"));
        out.put("recordedOwner", doc.get("ownerUserId"));
        out.put("valid", valid);
        return out;
    }

    /** Claims filed by this user, and claims filed against documents this user owns. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> ownershipClaims(String userId) {
        requireSetup();
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        List<Object> mine = Codec.list(csp.get("/csp/api/ownership-claims?claimantUserId=" + userId).get("claims"));
        List<Object> against = Codec.list(csp.get("/csp/api/ownership-claims?ownerUserId=" + userId).get("claims"));
        for (List<Object> l : List.of(mine, against)) {
            for (Object o : l) {
                Map<String, Object> c = Codec.map(o);
                Map<String, Object> d = (Map<String, Object>) docs.get(c.get("documentId"));
                if (d != null) c.put("fileName", d.get("fileName"));
            }
        }
        return Http.map("myClaims", mine, "claimsOnMyDocuments", against);
    }

    // ================================================================
    // LEAK TRACING (project extension)
    //   Every text copy handed out (download or view) is unique:
    //   1. TextVariation: visible harmless differences (numbers, dates,
    //      word forms) chosen at random per copy - survive screenshots,
    //      printouts and copied lines;
    //   2. Watermark: a hidden, server-signed copy code at the end of every
    //      line - identifies copied or forwarded text exactly.
    //   The owner pastes leaked text into "Find the leaker" to identify
    //   the copy, its user and the time it was issued.
    // ================================================================

    static final int MIN_CHANGE_POINTS = 8;
    private final java.security.SecureRandom leakRandom = new java.security.SecureRandom();
    private final Map<String, String> versionTextCache = new ConcurrentHashMap<>();

    private byte[] watermarkKey() {
        if (!vault.has("watermark-key")) {
            byte[] k = new byte[32];
            leakRandom.nextBytes(k);
            vault.put("watermark-key", Http.map("key", CryptoUtil.b64(k)));
        }
        return CryptoUtil.unb64((String) vault.get("watermark-key").get("key"));
    }

    /** Builds and records a unique copy; null when the document is not traced. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> traceableCopy(Map<String, Object> doc, String userId, int version, byte[] plain, String channel) {
        String ownerId = (String) doc.get("ownerUserId");
        if (ownerId.equals(userId) || Boolean.FALSE.equals(doc.get("leakTracing"))) return null;
        if (!TextDiff.isText(String.valueOf(doc.get("contentType")), String.valueOf(doc.get("fileName")), plain)) return null;
        String original = new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        int points = TextVariation.countPoints(original);
        String docId = (String) doc.get("documentId");
        List<Object> copies = store.readList(LEAK_COPIES);
        // Random choices, spread apart: of 64 random candidates keep the one that differs
        // most from the closest copy already issued for this version, so no two users
        // get near-identical copies even when many users have the document.
        List<String> issued = new ArrayList<>();
        for (Object o : copies) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (docId.equals(r.get("documentId")) && ((Number) r.get("version")).intValue() == version) {
                issued.add(String.valueOf(r.get("bits")));
            }
        }
        String bits = "";
        int bestDistance = -1;
        for (int attempt = 0; attempt < (issued.isEmpty() ? 1 : 64); attempt++) {
            StringBuilder b = new StringBuilder(points);
            for (int i = 0; i < points; i++) b.append(leakRandom.nextBoolean() ? '1' : '0');
            String candidate = b.toString();
            int nearest = Integer.MAX_VALUE;
            for (String other : issued) nearest = Math.min(nearest, hamming(candidate, other));
            if (nearest > bestDistance) {
                bestDistance = nearest;
                bits = candidate;
            }
        }
        byte[] id = new byte[Watermark.ID_BYTES];
        leakRandom.nextBytes(id);
        String copyId = Watermark.hex(id);
        String varied = TextVariation.apply(original, bits);
        String marked = Watermark.embed(varied, watermarkKey(), id);
        copies.add(Http.map(
                "copyId", copyId,
                "documentId", docId,
                "ownerUserId", ownerId,
                "userId", userId,
                "version", version,
                "channel", channel,
                "bits", bits,
                "issuedAt", java.time.Instant.now().toString()));
        store.write(LEAK_COPIES, copies);
        return Http.map("bytes", marked.getBytes(java.nio.charset.StandardCharsets.UTF_8), "copyId", copyId);
    }

    static int hamming(String a, String b) {
        int d = Math.abs(a.length() - b.length());
        for (int i = 0; i < Math.min(a.length(), b.length()); i++) if (a.charAt(i) != b.charAt(i)) d++;
        return d;
    }

    private String versionText(String ownerId, String docId, int version) {
        return versionTextCache.computeIfAbsent(docId + "#" + version, k ->
                new String(ownerVersionBytes(ownerId, docId, version), java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Owner's "Find the leaker": identifies which issued copy a leaked text came from. */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> traceLeak(String ownerId, String leakedText) {
        requireSetup();
        if (leakedText == null || leakedText.isBlank()) throw new ApiException(400, "Paste the leaked text or upload the file");
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        List<Object> copies = store.readList(LEAK_COPIES);
        Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        for (Object o : copies) byId.put((String) ((Map<String, Object>) o).get("copyId"), (Map<String, Object>) o);

        // 1. hidden code (exact)
        Watermark.Found found = Watermark.extract(leakedText, watermarkKey());
        List<Object> exact = new ArrayList<>();
        int otherOwner = 0;
        for (Map.Entry<String, Integer> e : found.valid.entrySet()) {
            Map<String, Object> r = byId.get(e.getKey());
            if (r == null) continue;
            if (!ownerId.equals(r.get("ownerUserId"))) { otherOwner++; continue; }
            exact.add(describeCopy(r, docs, "hidden code in " + e.getValue() + " line" + (e.getValue() == 1 ? "" : "s"), 1));
        }

        // 2. visible variations (screenshots, printouts, text whose hidden code was lost).
        //    Text recognition can misread a few change points, so a copy is accepted when
        //    most of the observed points agree with it; the best-agreeing copies win.
        String clean = Watermark.strip(leakedText);
        List<Object> wording = new ArrayList<>();
        List<Map<String, Object>> ranking = new ArrayList<>();
        java.util.Set<String> exactIds = new java.util.HashSet<>();
        for (Object o : exact) exactIds.add((String) ((Map<String, Object>) o).get("copyId"));
        int bestMatched = 0, bestMismatched = Integer.MAX_VALUE, observedPoints = 0;
        Map<String, List<Map<String, Object>>> groups = new LinkedHashMap<>();
        for (Object o : copies) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (!ownerId.equals(r.get("ownerUserId"))) continue;
            groups.computeIfAbsent(r.get("documentId") + "#" + r.get("version"), k -> new ArrayList<>()).add(r);
        }
        for (Map.Entry<String, List<Map<String, Object>>> g : groups.entrySet()) {
            Map<String, Object> first = g.getValue().get(0);
            String docId = (String) first.get("documentId");
            int version = ((Number) first.get("version")).intValue();
            if (!docs.containsKey(docId)) continue;
            String original;
            try {
                original = versionText(ownerId, docId, version);
            } catch (RuntimeException e) {
                continue;
            }
            List<TextVariation.Observation> obs = TextVariation.locate(original, clean);
            if (obs.isEmpty()) continue;
            observedPoints = Math.max(observedPoints, obs.size());
            int allowed = obs.size() / 8;   // one misread point per 8 observed (keeps false matches rare)
            for (Map<String, Object> r : g.getValue()) {
                String bits = String.valueOf(r.get("bits"));
                int mismatched = 0;
                for (TextVariation.Observation ob : obs) {
                    char issued = ob.point < bits.length() ? bits.charAt(ob.point) : '0';
                    if (issued != ob.bit) mismatched++;
                }
                int matched = obs.size() - mismatched;
                if (!"VIEW".equals(r.get("channel"))) {   // the table lists downloaded copies only
                Map<String, Object> rank = describeCopy(r, docs, matched + " of " + obs.size(), 0);
                rank.put("observed", obs.size());
                rank.put("matched", matched);
                rank.put("percent", Math.round(1000.0 * matched / obs.size()) / 10.0);
                rank.put("hiddenCode", exactIds.contains((String) r.get("copyId")));
                ranking.add(rank);
                }
                if (mismatched > allowed) continue;
                if (matched > bestMatched || (matched == bestMatched && mismatched < bestMismatched)) {
                    bestMatched = matched;
                    bestMismatched = mismatched;
                    wording.clear();
                } else if (matched < bestMatched || mismatched > bestMismatched) {
                    continue;
                }
                Map<String, Object> d = describeCopy(r, docs, matched + " of " + obs.size()
                        + " wording difference" + (obs.size() == 1 ? "" : "s") + " match", 0);
                d.put("observed", obs.size());
                d.put("mismatched", mismatched);
                wording.add(d);
            }
        }
        for (Object o : wording) ((Map<String, Object>) o).put("candidates", wording.size());

        String verdict;
        if (!exact.isEmpty()) {
            verdict = exact.size() == 1 ? "EXACT" : "SEVERAL_EXACT";
        } else if (wording.size() == 1) {
            verdict = "WORDING_UNIQUE";
        } else if (!wording.isEmpty()) {
            verdict = "WORDING_SEVERAL";
        } else {
            verdict = "NOT_FOUND";
        }
        String summary = verdict.equals("EXACT") || verdict.equals("WORDING_UNIQUE")
                ? "copy " + ((Map<String, Object>) (exact.isEmpty() ? wording.get(0) : exact.get(0))).get("copyId")
                + " of " + ((Map<String, Object>) (exact.isEmpty() ? wording.get(0) : exact.get(0))).get("userId")
                : verdict;
        // ranking: every copy of the documents found, best match first
        ranking.sort((x, y) -> {
            int c = Boolean.compare((Boolean) y.get("hiddenCode"), (Boolean) x.get("hiddenCode"));
            if (c != 0) return c;
            c = Double.compare((Double) y.get("percent"), (Double) x.get("percent"));
            if (c != 0) return c;
            return Integer.compare((Integer) y.get("matched"), (Integer) x.get("matched"));
        });
        // keep only the document(s) the best entry belongs to
        List<Object> rankingOut = new ArrayList<>();
        if (!ranking.isEmpty()) {
            Map<String, Object> top = !exact.isEmpty() ? (Map<String, Object>) exact.get(0) : ranking.get(0);
            Object topDoc = top.get("documentId"), topVersion = top.get("version");
            for (Map<String, Object> r : ranking) {
                if (r.get("documentId").equals(topDoc) && String.valueOf(r.get("version")).equals(String.valueOf(topVersion))
                        && rankingOut.size() < 30) rankingOut.add(r);
            }
        }

        // modifications: compare the leaked text with the original of the identified document
        Map<String, Object> modifications = null;
        Map<String, Object> subject = !exact.isEmpty() ? (Map<String, Object>) exact.get(0)
                : !wording.isEmpty() ? (Map<String, Object>) wording.get(0) : null;
        if (subject != null) {
            try {
                String original = versionText(ownerId, (String) subject.get("documentId"),
                        ((Number) subject.get("version")).intValue());
                modifications = LeakDiff.compare(original, leakedText);
                modifications.put("fileName", subject.get("fileName"));
                modifications.put("version", subject.get("version"));
            } catch (RuntimeException e) {
                modifications = null;
            }
        }

        for (Object o : exact.isEmpty() ? wording : exact) {
            Map<String, Object> m = (Map<String, Object>) o;
            documentLog((String) m.get("documentId"), ownerId, (String) m.get("userId"), "LEAK_TRACED",
                    ((Number) m.get("version")).intValue(), "Leak check matched " + m.get("channel").toString().toLowerCase(Locale.ROOT)
                            + " copy " + m.get("copyId") + " (" + m.get("evidence") + ")");
        }
        audit("LEAK_CHECK", ownerId, verdict + " - " + summary);
        return Http.map(
                "verdict", verdict,
                "exactMatches", exact,
                "wordingMatches", exact.isEmpty() ? wording : new ArrayList<>(),
                "alteredMarks", found.invalid,
                "observedPoints", observedPoints,
                "ranking", rankingOut,
                "copiesCompared", ranking.size(),
                "modifications", modifications,
                "otherOwnersCopies", otherOwner);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> describeCopy(Map<String, Object> r, Map<String, Object> docs, String evidence, int candidates) {
        Map<String, Object> d = (Map<String, Object>) docs.get(r.get("documentId"));
        String uid = (String) r.get("userId");
        Object name = uid;
        try {
            name = user(uid).get("displayName");
        } catch (RuntimeException e) {
            // user removed
        }
        return Http.map(
                "copyId", r.get("copyId"),
                "userId", uid,
                "displayName", name,
                "documentId", r.get("documentId"),
                "fileName", d == null ? r.get("documentId") : d.get("fileName"),
                "version", r.get("version"),
                "channel", r.get("channel"),
                "issuedAt", r.get("issuedAt"),
                "evidence", evidence,
                "candidates", candidates);
    }

    /** All traceable copies of one document (for its owner). */
    @SuppressWarnings("unchecked")
    public Map<String, Object> issuedCopies(String ownerId, String docId) {
        Map<String, Object> doc = document(docId);
        if (!ownerId.equals(doc.get("ownerUserId"))) throw new ApiException(403, "Not your document");
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(LEAK_COPIES)) {
            Map<String, Object> r = (Map<String, Object>) o;
            if (docId.equals(r.get("documentId"))) {
                Map<String, Object> c = new LinkedHashMap<>(r);
                c.remove("bits");
                out.add(c);
            }
        }
        Collections.reverse(out);
        return Http.map("copies", out);
    }

    // ---------------- View-page protection events ----------------

    static final java.util.Set<String> VIEW_EVENTS = new java.util.HashSet<>(java.util.Arrays.asList(
            "COPY_ATTEMPT", "PRINT_ATTEMPT", "PRINT_SCREEN", "WINDOW_LEFT"));

    /** Reported by the View page; copy, print and Print Screen attempts alert the owner. */
    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> viewEvent(String userId, String docId, String event) {
        Map<String, Object> doc = document(docId);
        if (!VIEW_EVENTS.contains(event)) throw new ApiException(400, "Unknown event");
        if (!permissionsFor(doc, userId).contains(VIEW)) throw new ApiException(403, "No access to this document");
        String ownerId = (String) doc.get("ownerUserId");
        int version = currentVersionOf(doc);
        String label = event.equals("COPY_ATTEMPT") ? "Tried to copy text (blocked)"
                : event.equals("PRINT_ATTEMPT") ? "Tried to print (blocked)"
                : event.equals("PRINT_SCREEN") ? "Pressed Print Screen (page blurred)"
                : "Left the window while the document was open (page blurred)";
        documentLog(docId, ownerId, userId, event, version, label);
        if (event.equals("WINDOW_LEFT") || ownerId.equals(userId)) return Http.map("logged", true, "alert", false);
        List<Object> alerts = store.readList(VIEW_ALERTS);
        long now = System.currentTimeMillis();
        for (Object o : alerts) {
            Map<String, Object> a = (Map<String, Object>) o;
            if (userId.equals(a.get("userId")) && docId.equals(a.get("documentId")) && event.equals(a.get("event"))
                    && now - ((Number) a.get("lastAt")).longValue() < 10 * 60 * 1000L) {
                a.put("count", ((Number) a.get("count")).intValue() + 1);
                a.put("lastAt", now);
                store.write(VIEW_ALERTS, alerts);
                return Http.map("logged", true, "alert", true);
            }
        }
        alerts.add(Http.map("alertId", "V-" + CryptoUtil.randomId(6), "type", "VIEW_PROTECTION", "event", event,
                "label", label, "userId", userId, "documentId", docId, "ownerUserId", ownerId,
                "firstAt", now, "lastAt", now, "count", 1));
        store.write(VIEW_ALERTS, alerts);
        return Http.map("logged", true, "alert", true);
    }

    @SuppressWarnings("unchecked")
    private List<Object> viewAlertsFor(String ownerId) {
        Map<String, Object> docs = store.readMap(DOCUMENTS);
        List<Object> out = new ArrayList<>();
        for (Object o : store.readList(VIEW_ALERTS)) {
            Map<String, Object> a = (Map<String, Object>) o;
            if (!ownerId.equals(a.get("ownerUserId"))) continue;
            Map<String, Object> c = new LinkedHashMap<>(a);
            c.put("identifiedUserId", a.get("userId"));
            c.put("identifiedUserRevoked", isRevoked(ownerId, (String) a.get("userId")));
            Map<String, Object> d = (Map<String, Object>) docs.get(a.get("documentId"));
            if (d != null) c.put("fileName", d.get("fileName"));
            out.add(c);
        }
        return out;
    }

    // ================================================================
    // Information pages
    // ================================================================

    public Map<String, Object> accessInfo(String userId) {
        requireSetup();
        Set<String> Sc = attributesOf(userId);
        List<Map<String, Object>> docs = new ArrayList<>();
        for (Map<String, Object> d : documentsOf(null)) {
            AccessPolicy p = AccessPolicy.fromExpression(mpk, (String) d.get("policy"));
            String owner = (String) d.get("ownerUserId");
            docs.add(Http.map(
                    "documentId", d.get("documentId"),
                    "fileName", d.get("fileName"),
                    "owner", owner,
                    "policy", d.get("policy"),
                    "matrix", d.get("matrixRows") + " x " + d.get("matrixColumns"),
                    "satisfiedByMyAttributes", p.isSatisfiedBy(mpk.getPairing(), Sc),
                    "revokedByOwner", isRevoked(owner, userId),
                    "requireApproval", Boolean.TRUE.equals(d.get("requireApproval")),
                    "approval", owner.equals(userId) || !Boolean.TRUE.equals(d.get("requireApproval"))
                            ? "NOT_REQUIRED" : approvalStatus((String) d.get("documentId"), userId),
                    "permissions", permissionsFor(d, userId)));
        }
        return Http.map(
                "user", publicUser(user(userId)),
                "universe", new ArrayList<>(mpk.getAttributes()),
                "documents", docs);
    }

    public Map<String, Object> ownerActivity(String ownerId) {
        return Http.map("records", csp.get("/csp/api/trapdoor-records?ownerUserId=" + ownerId + "&limit=100").get("records"));
    }

    public Map<String, Object> userActivity(String userId) {
        return Http.map("records", csp.get("/csp/api/trapdoor-records?submittedBy=" + userId + "&limit=50").get("records"));
    }

    @SuppressWarnings("unchecked")
    public List<Object> usersList() {
        List<Object> out = new ArrayList<>();
        for (Object o : store.readMap(USERS).values()) out.add(publicUser((Map<String, Object>) o));
        return out;
    }

    public Map<String, Object> cspLogs() {
        return csp.get("/csp/api/logs?limit=60");
    }

    public List<Map<String, Object>> auditLog(int max) {
        return store.tailLog(AUDIT, max);
    }

    private void audit(String event, String userId, String detail) {
        store.log(AUDIT, Http.map("event", event, "userId", userId, "detail", detail));
    }

    static String fingerprint(String b64) {
        return CryptoUtil.sha256Hex(b64.getBytes(StandardCharsets.UTF_8)).substring(0, 16);
    }
}
