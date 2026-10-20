import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Minos - Algorithm 5: Authorize
 *
 * Client side (paper lines 1-8):
 *   builds the Schnorr / Fiat-Shamir proof rho that the client
 *   owns the private key sk_c behind its identity pk_c.
 *
 * Data-owner side (paper lines 9-21):
 *   checks pk_c is registered, verifies rho, checks the client's
 *   attributes satisfy (M, pi), and issues the search token TK.
 *
 * Deviations from the printed paper (see README of the algorithms):
 *   - tk3 = pk_c^(sk_o^2) so that Detect can divide by sk_o^2.
 *   - tk5, tk6 are the Algorithm 11 (enhanced Detect) components.
 *   - tk7 = e(tk3, sk2) is an extra component. The printed Search
 *     equation e(tk3*tk4, ct3) * Delta = 1 cannot hold for the
 *     ciphertext of Algorithm 4, so Search needs tk7 (see Search).
 */
public class Authorize {

    // ------------------------------------------------
    // PROOF rho = (g, g^tau, g^d)
    // ------------------------------------------------

    public static class Proof {

        public final Element gTau;
        public final Element gd;

        public Proof(Element gTau, Element gd) {
            this.gTau = gTau;
            this.gd = gd;
        }

        public Map<String, Object> toJson() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("gTau", Codec.enc(gTau));
            out.put("gd", Codec.enc(gd));
            return out;
        }

        public static Proof fromJson(
                Setup.PublicParameters mpk,
                Map<String, Object> json) {

            return new Proof(
                    Codec.g1(mpk, Codec.str(json, "gTau")),
                    Codec.g1(mpk, Codec.str(json, "gd")));
        }
    }

    // ------------------------------------------------
    // SEARCH TOKEN TK
    // ------------------------------------------------

    public static class Token {

        // Row index i of M -> element. Only rows with gamma_i != 0.
        public final Map<Integer, Element> tk1 = new LinkedHashMap<>();
        public final Map<Integer, Element> tk2 = new LinkedHashMap<>();

        public Element tk3;
        public Element tk4;
        public Element tk5;   // GT
        public String tk6;
        public Element tk7;   // GT

        public Map<String, Object> toJson() {

            Map<String, Object> out = new LinkedHashMap<>();

            out.put("tk1", rowsToJson(tk1));
            out.put("tk2", rowsToJson(tk2));
            out.put("tk3", Codec.enc(tk3));
            out.put("tk4", Codec.enc(tk4));
            out.put("tk5", Codec.enc(tk5));
            out.put("tk6", tk6);
            out.put("tk7", Codec.enc(tk7));

            return out;
        }

        public void load(
                Setup.PublicParameters mpk,
                Map<String, Object> json) {

            rowsFromJson(mpk, Codec.list(json.get("tk1")), tk1);
            rowsFromJson(mpk, Codec.list(json.get("tk2")), tk2);

            tk3 = Codec.g1(mpk, Codec.str(json, "tk3"));
            tk4 = Codec.g1(mpk, Codec.str(json, "tk4"));
            tk5 = Codec.gt(mpk, Codec.str(json, "tk5"));
            tk6 = Codec.str(json, "tk6");
            tk7 = Codec.gt(mpk, Codec.str(json, "tk7"));
        }

        public static Token fromJson(
                Setup.PublicParameters mpk,
                Map<String, Object> json) {

            Token token = new Token();
            token.load(mpk, json);
            return token;
        }

        private static List<Object> rowsToJson(Map<Integer, Element> rows) {

            List<Object> out = new ArrayList<>();

            for (Map.Entry<Integer, Element> e : rows.entrySet()) {

                Map<String, Object> item = new LinkedHashMap<>();

                item.put("row", e.getKey());
                item.put("value", Codec.enc(e.getValue()));

                out.add(item);
            }

            return out;
        }

        private static void rowsFromJson(
                Setup.PublicParameters mpk,
                List<Object> items,
                Map<Integer, Element> target) {

            for (Object item : items) {

                Map<String, Object> entry = Codec.map(item);

                target.put(
                        ((Number) entry.get("row")).intValue(),
                        Codec.g1(mpk, Codec.str(entry, "value")));
            }
        }
    }

    // ------------------------------------------------
    // CLIENT SIDE: LINES 1-8
    // ------------------------------------------------

    public static Proof clientProof(
            Setup.PublicParameters mpk,
            Element pkc,
            Element skc) {

        Pairing pairing = mpk.getPairing();

        // Line 2: tau <- Zp
        Element tau = pairing.getZr().newRandomElement().getImmutable();

        // Line 3: g^tau
        Element gTau = mpk.getG().duplicate().powZn(tau).getImmutable();

        // Line 4: c <- H2(g, pk_c, g^tau)
        Element c = challenge(mpk, pkc, gTau);

        // Line 5: d <- tau - c * sk_c
        Element d = tau.duplicate()
                .sub(c.duplicate().mul(skc))
                .getImmutable();

        // Line 6: g^d
        Element gd = mpk.getG().duplicate().powZn(d).getImmutable();

        // Lines 7-8: rho = (g, g^tau, g^d) is sent to the data owner.
        return new Proof(gTau, gd);
    }

    static Element challenge(
            Setup.PublicParameters mpk,
            Element pkc,
            Element gTau) {

        return mpk.getHashFunctions().H2(
                Codec.enc(mpk.getG())
                        + "|" + Codec.enc(pkc)
                        + "|" + Codec.enc(gTau));
    }

    // ------------------------------------------------
    // DATA OWNER SIDE: LINES 9-21
    // ------------------------------------------------

    /**
     * @param R   registered public keys, Base64(pk.toBytes())
     * @param Sc  attribute set of the requesting client
     * @param K   output of KeyGen for the requested document
     * @param sko owner's private key
     */
    public static Token ownerAuthorize(
            Setup.PublicParameters mpk,
            Set<String> R,
            Element pkc,
            Proof rho,
            Set<String> Sc,
            KeyGen.K K,
            Element sko) {

        Pairing pairing = mpk.getPairing();

        // Line 9: verify pk_c is a legitimate (registered) client.
        if (!R.contains(Codec.enc(pkc))) {
            throw new IllegalArgumentException(
                    "pk_c is not a registered user");
        }

        // Line 10: verify the client holds sk_c:
        //          g^tau == g^d * pk_c^c
        Element c = challenge(mpk, pkc, rho.gTau);

        Element check = rho.gd.duplicate()
                .mul(pkc.duplicate().powZn(c));

        // Line 11: if a verification failed, output bottom.
        if (!check.isEqual(rho.gTau)) {
            throw new IllegalArgumentException(
                    "Proof of private-key ownership failed");
        }

        // Line 12: does Sc satisfy (M, pi)?
        // I = row indexes of M whose attribute is in Sc.
        List<Integer> I = new ArrayList<>();

        for (int i = 0; i < K.pi.length; i++) {
            if (Sc.contains(K.pi[i])) {
                I.add(i);
            }
        }

        if (I.isEmpty()) {
            throw new IllegalArgumentException(
                    "Attributes do not satisfy the access structure");
        }

        // Line 13: find {gamma_i} with sum(gamma_i * M_i) = (1,0,...,0)
        Element[] gamma = solveGamma(pairing, K.M, I);

        if (gamma == null) {
            throw new IllegalArgumentException(
                    "Attributes do not satisfy the access structure");
        }

        Token TK = new Token();

        Element tk5 = pairing.getGT().newOneElement();

        // Lines 14-16: for each i in I
        for (int t = 0; t < I.size(); t++) {

            if (gamma[t].isZero()) continue;

            int i = I.get(t);

            // Line 15: tk1,i <- sk1,pi(i)^gamma_i
            Element tk1i = K.sk1.get(K.pi[i])
                    .duplicate()
                    .powZn(gamma[t])
                    .getImmutable();

            // Line 16: tk2,i <- sk2^gamma_i
            Element tk2i = K.sk2
                    .duplicate()
                    .powZn(gamma[t])
                    .getImmutable();

            TK.tk1.put(i, tk1i);
            TK.tk2.put(i, tk2i);

            // Algorithm 11: tk5 = prod e(tk1,i * tk2,i, pk_c)
            tk5.mul(pairing.pairing(
                    tk1i.duplicate().mul(tk2i),
                    pkc));
        }

        // Line 17: tk3 <- pk_c^(sk_o^2)
        TK.tk3 = pkc.duplicate()
                .powZn(sko.duplicate().mul(sko))
                .getImmutable();

        // Line 18: tk4 <- pk_c^(sk_o)
        TK.tk4 = pkc.duplicate().powZn(sko).getImmutable();

        TK.tk5 = tk5.getImmutable();

        // Algorithm 11: tk6 <- H(sk_o, tk3, tk5)
        TK.tk6 = tk6(sko, TK.tk3, TK.tk5);

        // Extra component used by Search: tk7 <- e(tk3, sk2)
        TK.tk7 = pairing.pairing(TK.tk3, K.sk2).getImmutable();

        // Line 19: TK <- ({tk1,i}, {tk2,i}, tk3, tk4, ...)
        // Lines 20-21: k <- K; return TK and k (done by the caller).
        return TK;
    }

    static String tk6(Element sko, Element tk3, Element tk5) {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            String input = Codec.enc(sko)
                    + "|" + Codec.enc(tk3)
                    + "|" + Codec.enc(tk5);

            return Codec.b64(digest.digest(
                    input.getBytes(StandardCharsets.UTF_8)));

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Solves  sum_{i in I} gamma_i * M_i = (1, 0, ..., 0)  over Zp by
     * Gaussian elimination. Returns null when no solution exists.
     */
    static Element[] solveGamma(
            Pairing pairing,
            Element[][] M,
            List<Integer> I) {

        int m = I.size();
        int n2 = M[0].length;

        // Augmented matrix: n2 equations, m unknowns, one column for b.
        Element[][] a = new Element[n2][m + 1];

        for (int j = 0; j < n2; j++) {

            for (int t = 0; t < m; t++) {
                a[j][t] = M[I.get(t)][j].duplicate();
            }

            a[j][m] = (j == 0
                    ? pairing.getZr().newOneElement()
                    : pairing.getZr().newZeroElement());
        }

        int[] pivotColumn = new int[n2];
        int rank = 0;

        for (int col = 0; col < m && rank < n2; col++) {

            int pivot = -1;

            for (int r = rank; r < n2; r++) {
                if (!a[r][col].isZero()) {
                    pivot = r;
                    break;
                }
            }

            if (pivot < 0) continue;

            Element[] swap = a[pivot];
            a[pivot] = a[rank];
            a[rank] = swap;

            Element inverse = a[rank][col].duplicate().invert();

            for (int c = col; c <= m; c++) {
                a[rank][c] = a[rank][c].duplicate().mul(inverse);
            }

            for (int r = 0; r < n2; r++) {

                if (r == rank || a[r][col].isZero()) continue;

                Element factor = a[r][col].duplicate();

                for (int c = col; c <= m; c++) {
                    a[r][c] = a[r][c].duplicate()
                            .sub(factor.duplicate().mul(a[rank][c]));
                }
            }

            pivotColumn[rank] = col;
            rank++;
        }

        // Inconsistent system: a zero row with a non-zero right side.
        for (int r = rank; r < n2; r++) {
            if (!a[r][m].isZero()) {
                return null;
            }
        }

        Element[] gamma = new Element[m];

        for (int t = 0; t < m; t++) {
            gamma[t] = pairing.getZr().newZeroElement().getImmutable();
        }

        for (int r = 0; r < rank; r++) {
            gamma[pivotColumn[r]] = a[r][m].getImmutable();
        }

        return gamma;
    }
}
