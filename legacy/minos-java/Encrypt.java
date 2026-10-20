import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import java.security.MessageDigest;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 4: Encrypt
 *
 * Paper:
 * Minos: Bringing Accountability and Traceability
 * to Attribute-Based Keyword Search.
 *
 * Algorithm 4:
 *
 * Input:
 *   mpk  - public parameters
 *   Phi  - inverted index: keyword -> document IDs
 *   sko  - owner's secret key
 *   K    - output tuple of KeyGen
 *
 * Output:
 *   L    - encrypted keyword index
 *
 * Application extension:
 *   The actual document is encrypted separately using
 *   an independent AES-256-GCM key for each document.
 *
 * The actual document AES key must never be sent to CSP.
 */
public class Encrypt {

    private static final int NONCE_LENGTH = 12;

    private static final int GCM_TAG_BITS = 128;

    private static final SecureRandom RANDOM =
            new SecureRandom();


    /*
     * One entry of encrypted index L.
     *
     * Attribute entry:
     *   ct1, ct2
     *
     * Keyword entry:
     *   ct3, ct4
     *
     * Plaintext keyword is intentionally not stored.
     */
    public static class Entry {

        public final String type;

        public final int row;

        public final String ct1;

        public final String ct2;

        public final String ct3;

        public final String ct4;


        private Entry(
                String type,
                int row,
                Element ct1,
                Element ct2,
                String ct3,
                String ct4) {

            this.type = type;

            this.row = row;

            this.ct1 = encodeElement(ct1);

            this.ct2 = encodeElement(ct2);

            this.ct3 = ct3;

            this.ct4 = ct4;
        }
    }


    /*
     * Result of encryption.
     *
     * L:
     *   Minos encrypted index.
     *
     * encryptedDocumentBase64:
     *   Actual encrypted document bytes.
     *
     * documentNonceBase64:
     *   AES-GCM nonce for document.
     *
     * ownerDocumentKeyBase64:
     *   AES key for actual document.
     *   STORE OWNER-SIDE ONLY.
     */
    public static class Result {

        public final List<Entry> L =
                new ArrayList<>();

        public final String documentId;

        public final String encryptedDocumentBase64;

        public final String documentNonceBase64;

        public final String ownerDocumentKeyBase64;


        private Result(
                String documentId,
                byte[] encryptedDocument,
                byte[] documentNonce,
                byte[] documentKey) {

            this.documentId = documentId;

            this.encryptedDocumentBase64 =
                    Base64.getEncoder()
                            .encodeToString(
                                    encryptedDocument
                            );

            this.documentNonceBase64 =
                    Base64.getEncoder()
                            .encodeToString(
                                    documentNonce
                            );

            this.ownerDocumentKeyBase64 =
                    Base64.getEncoder()
                            .encodeToString(
                                    documentKey
                            );
        }


        /*
         * Serialize data intended for CSP.
         *
         * This method DOES NOT serialize:
         *   - plaintext keywords
         *   - the document AES key
         *
         * Only encrypted data is included.
         */
        public String toCspJson() {

            StringBuilder json =
                    new StringBuilder();

            json.append("{");

            json.append("\"documentId\":\"")
                    .append(escapeJson(documentId))
                    .append("\",");

            json.append("\"encryptedDocumentBase64\":\"")
                    .append(encryptedDocumentBase64)
                    .append("\",");

            json.append("\"documentNonceBase64\":\"")
                    .append(documentNonceBase64)
                    .append("\",");

            json.append("\"indexEntries\":[");

            for (int i = 0; i < L.size(); i++) {

                Entry entry = L.get(i);

                if (i > 0) {
                    json.append(",");
                }

                json.append("{");

                json.append("\"type\":\"")
                        .append(entry.type)
                        .append("\",");

                json.append("\"row\":")
                        .append(entry.row)
                        .append(",");

                json.append("\"ct1\":")
                        .append(jsonString(entry.ct1))
                        .append(",");

                json.append("\"ct2\":")
                        .append(jsonString(entry.ct2))
                        .append(",");

                json.append("\"ct3\":")
                        .append(jsonString(entry.ct3))
                        .append(",");

                json.append("\"ct4\":")
                        .append(jsonString(entry.ct4));

                json.append("}");
            }

            json.append("]}");

            return json.toString();
        }
    }


    /*
     * ------------------------------------------------
     * ALGORITHM 4: ENCRYPT
     * ------------------------------------------------
     *
     * The first method implements Algorithm 4.
     *
     * The documentId and documentBytes parameters are
     * application-level additions for web integration.
     */
    public static Result encrypt(
            Setup.PublicParameters mpk,
            Map<String, List<String>> Phi,
            Element ownerSecretKey,
            Element ownerPublicKey,
            KeyGen.K K,
            byte[] documentBytes) throws Exception {

        return encrypt(
                mpk,
                Phi,
                ownerSecretKey,
                ownerPublicKey,
                K,
                "document",
                documentBytes
        );
    }


    /*
     * Application-integrated encryption method.
     *
     * documentId:
     *   Unique document identifier generated by backend.
     *
     * documentBytes:
     *   Raw bytes read from uploaded file.
     */
    public static Result encrypt(
            Setup.PublicParameters mpk,
            Map<String, List<String>> Phi,
            Element ownerSecretKey,
            Element ownerPublicKey,
            KeyGen.K K,
            String documentId,
            byte[] documentBytes) throws Exception {

        /*
         * Validate inputs.
         */
        if (mpk == null ||
                Phi == null ||
                ownerSecretKey == null ||
                ownerPublicKey == null ||
                K == null ||
                documentId == null ||
                documentBytes == null) {

            throw new IllegalArgumentException(
                    "Encrypt input cannot be null"
            );
        }

        if (documentId.trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "Document ID cannot be empty"
            );
        }

        if (K.k == null ||
                K.M == null ||
                K.pi == null ||
                K.sk2 == null) {

            throw new IllegalArgumentException(
                    "KeyGen tuple K is incomplete"
            );
        }


        Pairing pairing = mpk.getPairing();


        /*
         * --------------------------------------------
         * PAPER LINE 1
         *
         * k, M, pi, sk2 <- K
         * --------------------------------------------
         */

        byte[] k = K.k;

        Element[][] M = K.M;

        String[] pi = K.pi;

        Element sk2 = K.sk2;


        /*
         * n1 = number of attributes in pi.
         */
        int n1 = pi.length;

        if (n1 == 0 || M.length != n1) {

            throw new IllegalArgumentException(
                    "Invalid M dimensions"
            );
        }

        if (M[0] == null ||
                M[0].length < 2) {

            throw new IllegalArgumentException(
                    "M must have at least two columns"
            );
        }

        /*
         * n2 = number of columns in M.
         */
        int n2 = M[0].length;

        for (int i = 0; i < n1; i++) {

            if (M[i] == null ||
                    M[i].length != n2) {

                throw new IllegalArgumentException(
                        "M must be rectangular"
                );
            }

            if (!mpk.getU().containsKey(pi[i])) {

                throw new IllegalArgumentException(
                        "Attribute not in universe: "
                                + pi[i]
                );
            }
        }


        /*
         * --------------------------------------------
         * APPLICATION EXTENSION:
         *
         * Encrypt the actual document with a SEPARATE
         * random AES-256-GCM key.
         *
         * This key is NOT the Minos index key k.
         * --------------------------------------------
         */

        byte[] documentKey =
                new byte[32];

        RANDOM.nextBytes(documentKey);

        byte[] documentNonce =
                new byte[NONCE_LENGTH];

        RANDOM.nextBytes(documentNonce);

        byte[] encryptedDocument =
                aesGcmEncrypt(
                        documentKey,
                        documentNonce,
                        documentBytes
                );


        /*
         * Initialize output.
         */
        Result result =
                new Result(
                        documentId,
                        encryptedDocument,
                        documentNonce,
                        documentKey
                );


        /*
         * --------------------------------------------
         * PAPER LINE 2
         *
         * L <- empty set
         * --------------------------------------------
         *
         * Result.L is initialized as an empty list.
         */


        /*
         * --------------------------------------------
         * PAPER LINE 3
         *
         * s0 <- Zp
         * --------------------------------------------
         */

        Element s0 =
                pairing.getZr()
                        .newRandomElement();


        /*
         * --------------------------------------------
         * PAPER LINE 4
         *
         * r <- Zp^n1
         * --------------------------------------------
         */

        Element[] r =
                new Element[n1];

        for (int i = 0; i < n1; i++) {

            r[i] =
                    pairing.getZr()
                            .newRandomElement();
        }


        /*
         * --------------------------------------------
         * PAPER LINE 5
         *
         * v <- Zp^(n2-1)
         * --------------------------------------------
         */

        Element[] v =
                new Element[n2 - 1];

        for (int j = 0; j < n2 - 1; j++) {

            v[j] =
                    pairing.getZr()
                            .newRandomElement();
        }


        /*
         * --------------------------------------------
         * PAPER LINES 6-9
         *
         * For i in [n1]:
         *
         *   ct1,i <- g^(r_i)
         *
         *   ct2,i <- pko^(M_i(s0 || v)^T)
         *             * pi(i)^(r_i)
         *
         *   L.add(ct1,i, ct2,i)
         * --------------------------------------------
         */


        /*
         * Construct vector:
         *
         * (s0 || v)^T
         *
         * Length = n2.
         */
        Element[] sVector =
                new Element[n2];

        sVector[0] = s0;

        for (int j = 1; j < n2; j++) {

            sVector[j] = v[j - 1];
        }


        for (int i = 0; i < n1; i++) {


            /*
             * PAPER LINE 7
             *
             * ct1,i <- g^(r_i)
             */
            Element ct1 =
                    mpk.getG()
                            .duplicate()
                            .powZn(r[i])
                            .getImmutable();


            /*
             * Calculate:
             *
             * M_i * (s0 || v)^T
             *
             * This is a dot product in Zp.
             */
            Element dotProduct =
                    pairing.getZr()
                            .newZeroElement();

            for (int j = 0; j < n2; j++) {

                Element product =
                        M[i][j]
                                .duplicate()
                                .mul(sVector[j]);

                dotProduct.add(product);
            }


            /*
             * PAPER LINE 8
             *
             * ct2,i <- pko^[M_i(s0||v)^T]
             *           * pi(i)^(r_i)
             *
             * pi(i) is represented by the
             * corresponding H1 attribute element.
             */
            String attribute =
                    pi[i];

            Element piElement =
                    mpk.getAttributeElement(
                            attribute
                    );

            Element firstTerm =
                    ownerPublicKey
                            .duplicate()
                            .powZn(dotProduct);

            Element secondTerm =
                    piElement
                            .duplicate()
                            .powZn(r[i]);

            Element ct2 =
                    firstTerm
                            .mul(secondTerm)
                            .getImmutable();


            /*
             * PAPER LINE 9
             *
             * L.add(ct1,i, ct2,i)
             */
            result.L.add(
                    new Entry(
                            "attribute",
                            i,
                            ct1,
                            ct2,
                            null,
                            null
                    )
            );
        }


        /*
         * --------------------------------------------
         * PAPER LINE 10
         *
         * For (w, ids) in Phi:
         * --------------------------------------------
         */

        for (Map.Entry<String, List<String>> item :
                Phi.entrySet()) {

            String w = item.getKey();

            List<String> ids =
                    item.getValue();

            if (w == null ||
                    ids == null) {

                throw new IllegalArgumentException(
                        "Invalid Phi entry"
                );
            }


            /*
             * ----------------------------------------
             * PAPER LINE 11
             *
             * ct3,w <- sk2^(s0*H2(w) + sko)
             * ----------------------------------------
             */

            Element H2w =
                    mpk.getHashFunctions()
                            .H2(w);

            Element exponent =
                    s0.duplicate()
                            .mul(H2w)
                            .add(ownerSecretKey);

            Element ct3Element =
                    sk2.duplicate()
                            .powZn(exponent)
                            .getImmutable();

            String ct3 =
                    Base64.getEncoder()
                            .encodeToString(
                                    ct3Element.toBytes()
                            );


            /*
             * ----------------------------------------
             * PAPER LINE 12
             *
             * ct4,w <- Enc(k, ids)
             *
             * k is the Minos index key from KeyGen.
             *
             * This is NOT the actual document AES key.
             * ----------------------------------------
             */

            String idsPlaintext =
                    String.join("\n", ids);

            byte[] idsBytes =
                    idsPlaintext.getBytes(
                            StandardCharsets.UTF_8
                    );

            /*
             * Derive AES key from Minos k.
             *
             * AES requires a valid AES key size.
             */
            byte[] indexAesKey =
                    MessageDigest
                            .getInstance("SHA-256")
                            .digest(k);

            byte[] indexNonce =
                    new byte[NONCE_LENGTH];

            RANDOM.nextBytes(indexNonce);

            byte[] encryptedIds =
                    aesGcmEncrypt(
                            indexAesKey,
                            indexNonce,
                            idsBytes
                    );

            /*
             * Store nonce || ciphertext as ct4.
             *
             * This lets the authorized decryptor
             * recover the nonce from the first
             * 12 bytes.
             */
            byte[] combinedCt4 =
                    new byte[
                            indexNonce.length
                                    + encryptedIds.length
                    ];

            System.arraycopy(
                    indexNonce,
                    0,
                    combinedCt4,
                    0,
                    indexNonce.length
            );

            System.arraycopy(
                    encryptedIds,
                    0,
                    combinedCt4,
                    indexNonce.length,
                    encryptedIds.length
            );

            String ct4 =
                    Base64.getEncoder()
                            .encodeToString(
                                    combinedCt4
                            );


            /*
             * ----------------------------------------
             * PAPER LINE 13
             *
             * L.add(ct3,w, ct4,w)
             * ----------------------------------------
             *
             * The keyword w is NOT stored in Entry.
             */
            result.L.add(
                    new Entry(
                            "keyword",
                            -1,
                            null,
                            null,
                            ct3,
                            ct4
                    )
            );
        }


        /*
         * --------------------------------------------
         * PAPER LINE 14
         *
         * Return L.
         * --------------------------------------------
         *
         * Result includes:
         *   - L
         *   - encrypted document
         *   - document nonce
         *   - owner-only document AES key
         *
         * Only L and encrypted document data should
         * be forwarded to CSP.
         */

        return result;
    }


    /*
     * ------------------------------------------------
     * AES-GCM HELPER
     * ------------------------------------------------
     *
     * Used for both:
     *   - encrypted document
     *   - encrypted index posting list
     *
     * Caller supplies a different key and nonce
     * for each encryption.
     */
    private static byte[] aesGcmEncrypt(
            byte[] key,
            byte[] nonce,
            byte[] plaintext) throws Exception {

        Cipher cipher =
                Cipher.getInstance(
                        "AES/GCM/NoPadding"
                );

        SecretKeySpec keySpec =
                new SecretKeySpec(
                        key,
                        "AES"
                );

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(
                        GCM_TAG_BITS,
                        nonce
                );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                keySpec,
                gcmSpec
        );

        return cipher.doFinal(plaintext);
    }


    /*
     * ------------------------------------------------
     * DECRYPT ACTUAL DOCUMENT
     * ------------------------------------------------
     *
     * This is application-level document decryption.
     *
     * It is not the Minos Search or Decrypt algorithm.
     *
     * The caller must possess the document AES key.
     */
    public static byte[] decryptDocument(
            String ownerDocumentKeyBase64,
            String nonceBase64,
            String encryptedDocumentBase64)
            throws Exception {

        byte[] key =
                Base64.getDecoder()
                        .decode(
                                ownerDocumentKeyBase64
                        );

        byte[] nonce =
                Base64.getDecoder()
                        .decode(
                                nonceBase64
                        );

        byte[] ciphertext =
                Base64.getDecoder()
                        .decode(
                                encryptedDocumentBase64
                        );

        Cipher cipher =
                Cipher.getInstance(
                        "AES/GCM/NoPadding"
                );

        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(
                        key,
                        "AES"
                ),
                new GCMParameterSpec(
                        GCM_TAG_BITS,
                        nonce
                )
        );

        return cipher.doFinal(ciphertext);
    }


    /*
     * ------------------------------------------------
     * SAVE DOCUMENT KEY OWNER-SIDE
     * ------------------------------------------------
     *
     * One key file per document.
     *
     * Example:
     *
     * private/owner-keys/document-1001.key
     *
     * Do not put this directory inside CSP storage.
     */
    public static void saveOwnerDocumentKey(
            Path ownerOnlyDirectory,
            String documentId,
            String ownerDocumentKeyBase64)
            throws IOException {

        Files.createDirectories(
                ownerOnlyDirectory
        );

        String safeId =
                documentId.replaceAll(
                        "[^a-zA-Z0-9_-]",
                        "_"
                );

        Path keyFile =
                ownerOnlyDirectory.resolve(
                        safeId + ".key"
                );

        Files.writeString(
                keyFile,
                ownerDocumentKeyBase64,
                StandardCharsets.UTF_8
        );
    }


    /*
     * Load the owner-held document AES key.
     */
    public static String loadOwnerDocumentKey(
            Path ownerOnlyDirectory,
            String documentId)
            throws IOException {

        String safeId =
                documentId.replaceAll(
                        "[^a-zA-Z0-9_-]",
                        "_"
                );

        Path keyFile =
                ownerOnlyDirectory.resolve(
                        safeId + ".key"
                );

        if (!Files.exists(keyFile)) {

            throw new IOException(
                    "Document key not found: "
                            + documentId
            );
        }

        return Files.readString(
                keyFile,
                StandardCharsets.UTF_8
        ).trim();
    }


    /*
     * Write encrypted document bytes to disk.
     *
     * Use this for CSP ciphertext storage.
     */
    public static void writeEncryptedDocument(
            Path outputPath,
            String encryptedDocumentBase64)
            throws IOException {

        Path parent =
                outputPath.getParent();

        if (parent != null) {

            Files.createDirectories(parent);
        }

        byte[] encryptedBytes =
                Base64.getDecoder()
                        .decode(
                                encryptedDocumentBase64
                        );

        Files.write(
                outputPath,
                encryptedBytes
        );
    }


    /*
     * ------------------------------------------------
     * JSON HELPERS
     * ------------------------------------------------
     */

    private static String encodeElement(
            Element element) {

        if (element == null) {
            return null;
        }

        return Base64.getEncoder()
                .encodeToString(
                        element.toBytes()
                );
    }


    private static String jsonString(
            String value) {

        if (value == null) {
            return "\"\"";
        }

        return "\"" +
                escapeJson(value) +
                "\"";
    }


    private static String escapeJson(
            String value) {

        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}