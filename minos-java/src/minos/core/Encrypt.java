package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 4: Encrypt (builds the searchable encrypted index L)
 *
 * <pre>
 *   Input : mpk, inverted index Phi (keyword w -> document identifiers),
 *           owner private key sk_o, key set K = (sk1, sk2, k, M, pi)
 *   Output: L
 *
 *   1:  k, M, pi, sk2 <- K
 *   2:  L <- empty
 *   3:  s0 <- Zp
 *   4:  r  <- Zp^n1
 *   5:  v  <- Zp^(n2-1)
 *   6:  for i in [n1] do
 *   7:     ct1,i <- g^(r_i)
 *   8:     ct2,i <- pk_o^(M_i . (s0||v)) * pi(i)^(r_i)
 *   9:     L.add(ct1,i, ct2,i)
 *   10: for (w, ids) in Phi do
 *   11:    ct3,w <- sk2^(s0 * H2(w) + sk_o)
 *   12:    ct4,w <- Enc(k, ids)
 *   13:    L.add(ct3,w, ct4,w)
 *   14: return L
 * </pre>
 *
 * Only the paper's Algorithm 4 is here. Encrypting the file itself is a
 * project extension (minos.ext.DocumentCrypto).
 *
 * Enc(k, .) in line 12 is AES-GCM with the key SHA-256(k) and a random
 * 96-bit nonce; ct4 = nonce || ciphertext (the paper names AES for Enc).
 */
public class Encrypt {

    static final int NONCE_LENGTH = 12;
    static final int GCM_TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    /** One entry of L: attribute rows carry (ct1, ct2), keyword rows (ct3, ct4). */
    public static class Entry {
        public final String type;   // "attribute" or "keyword"
        public final int row;
        public final String ct1;
        public final String ct2;
        public final String ct3;
        public final String ct4;

        Entry(String type, int row, String ct1, String ct2, String ct3, String ct4) {
            this.type = type;
            this.row = row;
            this.ct1 = ct1;
            this.ct2 = ct2;
            this.ct3 = ct3;
            this.ct4 = ct4;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", type);
            m.put("row", row);
            m.put("ct1", ct1 == null ? "" : ct1);
            m.put("ct2", ct2 == null ? "" : ct2);
            m.put("ct3", ct3 == null ? "" : ct3);
            m.put("ct4", ct4 == null ? "" : ct4);
            return m;
        }
    }

    public static List<Entry> encrypt(
            Setup.PublicParameters mpk,
            Map<String, List<String>> Phi,
            Element sko,
            Element pko,
            KeyGen.K K) throws Exception {

        // ------------------------------------------------------------
        // Input checks
        // ------------------------------------------------------------
        if (mpk == null || Phi == null || sko == null || pko == null || K == null) {
            throw new IllegalArgumentException("Encrypt input cannot be null");
        }
        if (!K.hasAccessStructure() || K.sk2 == null || K.k == null) {
            throw new IllegalArgumentException("KeyGen tuple K is incomplete");
        }
        if (Phi.isEmpty()) {
            throw new IllegalArgumentException("Inverted index is empty");
        }

        Pairing pairing = mpk.getPairing();
        Field Zp = pairing.getZr();
        Element g = mpk.getG();

        // ------------------------------------------------------------
        // Line 1: k, M, pi, sk2 <- K
        // ------------------------------------------------------------
        byte[] k = K.k;
        Element[][] M = K.M;
        String[] pi = K.pi;
        Element sk2 = K.sk2;

        int n1 = pi.length;
        if (n1 == 0 || M.length != n1 || M[0].length < 1) {
            throw new IllegalArgumentException("Invalid access structure dimensions");
        }
        int n2 = M[0].length;
        for (int i = 0; i < n1; i++) {
            if (M[i].length != n2) {
                throw new IllegalArgumentException("M must be rectangular");
            }
            if (!mpk.getU().containsKey(pi[i])) {
                throw new IllegalArgumentException("Attribute not in universe: " + pi[i]);
            }
        }

        // ------------------------------------------------------------
        // Line 2: L <- empty
        // ------------------------------------------------------------
        List<Entry> L = new ArrayList<>();

        // ------------------------------------------------------------
        // Line 3: s0 <- Zp      (the shared secret)
        // ------------------------------------------------------------
        Element s0 = Zp.newRandomElement().getImmutable();

        // ------------------------------------------------------------
        // Line 4: r <- Zp^n1    (one random value per row)
        // ------------------------------------------------------------
        Element[] r = new Element[n1];
        for (int i = 0; i < n1; i++) {
            r[i] = Zp.newRandomElement().getImmutable();
        }

        // ------------------------------------------------------------
        // Line 5: v <- Zp^(n2-1), and the vector (s0 || v)
        // ------------------------------------------------------------
        Element[] s0v = new Element[n2];
        s0v[0] = s0;
        for (int j = 1; j < n2; j++) {
            s0v[j] = Zp.newRandomElement().getImmutable();
        }

        // ------------------------------------------------------------
        // Lines 6-9: for i in [n1]
        // ------------------------------------------------------------
        for (int i = 0; i < n1; i++) {

            // Line 7: ct1,i <- g^(r_i)
            Element gCopy = g.duplicate();
            Element ct1 = gCopy.powZn(r[i]).getImmutable();

            // The share lambda_i = M_i . (s0 || v), computed term by term.
            Element lambda = Zp.newZeroElement();
            for (int j = 0; j < n2; j++) {
                Element term = M[i][j].duplicate();
                term.mul(s0v[j]);
                lambda.add(term);
            }

            // Line 8: ct2,i <- pk_o^(lambda_i) * pi(i)^(r_i)
            Element firstFactor = pko.duplicate().powZn(lambda);
            Element attributeElement = mpk.getAttributeElement(pi[i]);
            Element secondFactor = attributeElement.duplicate().powZn(r[i]);
            Element ct2 = firstFactor.mul(secondFactor).getImmutable();

            // Line 9: L.add(ct1,i, ct2,i)
            Entry attributeEntry = new Entry("attribute", i, Codec.enc(ct1), Codec.enc(ct2), null, null);
            L.add(attributeEntry);
        }

        // AES key for Enc(k, .): SHA-256(k)
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] indexKey = sha256.digest(k);

        // ------------------------------------------------------------
        // Lines 10-13: for (w, ids) in Phi
        // ------------------------------------------------------------
        Iterator<Map.Entry<String, List<String>>> items = Phi.entrySet().iterator();
        while (items.hasNext()) {
            Map.Entry<String, List<String>> item = items.next();
            String w = item.getKey();
            List<String> ids = item.getValue();
            if (w == null || w.isEmpty() || ids == null) {
                throw new IllegalArgumentException("Invalid Phi entry");
            }

            // Line 11: ct3,w <- sk2^(s0 * H2(w) + sk_o)
            Element h2w = mpk.getHashFunctions().H2(w);
            Element exponent = s0.duplicate();
            exponent.mul(h2w);
            exponent.add(sko);
            Element ct3 = sk2.duplicate().powZn(exponent).getImmutable();

            // Line 12: ct4,w <- Enc(k, ids)
            //   ids are written one per line.
            StringBuilder idText = new StringBuilder();
            for (int t = 0; t < ids.size(); t++) {
                if (t > 0) {
                    idText.append('\n');
                }
                idText.append(ids.get(t));
            }
            byte[] plain = idText.toString().getBytes(StandardCharsets.UTF_8);

            byte[] nonce = new byte[NONCE_LENGTH];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(indexKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            byte[] body = cipher.doFinal(plain);

            // ct4 = nonce || body, copied byte by byte
            byte[] ct4 = new byte[nonce.length + body.length];
            for (int b = 0; b < nonce.length; b++) {
                ct4[b] = nonce[b];
            }
            for (int b = 0; b < body.length; b++) {
                ct4[nonce.length + b] = body[b];
            }

            // Line 13: L.add(ct3,w, ct4,w)  - the keyword itself is NOT stored
            Entry keywordEntry = new Entry("keyword", -1, null, null, Codec.enc(ct3), Codec.b64(ct4));
            L.add(keywordEntry);
        }

        // ------------------------------------------------------------
        // Line 14: return L
        // ------------------------------------------------------------
        return L;
    }

    /** L as JSON objects, ready to be sent to the CSP. */
    public static List<Map<String, Object>> toJson(List<Entry> L) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (int i = 0; i < L.size(); i++) {
            out.add(L.get(i).toJson());
        }
        return out;
    }
}
