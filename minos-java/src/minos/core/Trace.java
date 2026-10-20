package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 10: Trace (traceable ownership)
 *
 * The claimant builds help data hp for one keyword w from their own keys;
 * the CSP checks it against the stored encrypted index L. Only the real
 * owner can build help data that passes, because it needs sk_o and the
 * KeyGen secrets (sk1, sk2) that encrypted the index.
 *
 * <pre>
 *   Help data (claimant side)
 *     { sk1,pi(i)^gamma_i , sk2^gamma_i }   for the rows i in I
 *     P1 = pk_o ^ (1 / H2(w))
 *     C0 = e(sk2, pk_o) ^ (sk_o / H2(w))
 *
 *   Algorithm 10 (CSP side)
 *     1: for (ct3,w, ct4,w) in L do
 *     2:    t1 <- e(ct3,w, P1) / C0                    (corrected)
 *     3:    t2 <- prod e(ct2,i, sk2^gamma_i) / e(ct1,i, sk1^gamma_i)
 *     4:    if t1 = t2 then
 *     5:       return true
 *     6: return false
 * </pre>
 *
 * Why it works (exponents of e(g,g)):
 *   t2 = sk_o * r * s0
 *   t1 = r*(s0*H2(w) + sk_o) * sk_o/H2(w) - r*sk_o^2/H2(w) = sk_o * r * s0
 *
 * The printed line 2, t1 = e(ct3,w, pk_o^(H2(w) + sk_o)), does not equal t2
 * for the ciphertext of Algorithm 4, so P1 and C0 replace it (checked
 * numerically in test/PaperEquationCheck).
 */
public class Trace {

    /** The help data hp. */
    public static class HelpData {
        public final Map<Integer, Element> sk1Gamma = new LinkedHashMap<>();
        public final Map<Integer, Element> sk2Gamma = new LinkedHashMap<>();
        public Element P1;   // in G
        public Element C0;   // in GT

        public Map<String, Object> toJson() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("sk1Gamma", rows(sk1Gamma));
            out.put("sk2Gamma", rows(sk2Gamma));
            out.put("P1", Codec.enc(P1));
            out.put("C0", Codec.enc(C0));
            return out;
        }

        public static HelpData fromJson(Setup.PublicParameters mpk, Map<String, Object> json) {
            HelpData h = new HelpData();
            load(mpk, Codec.list(json.get("sk1Gamma")), h.sk1Gamma);
            load(mpk, Codec.list(json.get("sk2Gamma")), h.sk2Gamma);
            h.P1 = Codec.g1(mpk, Codec.str(json, "P1"));
            h.C0 = Codec.gt(mpk, Codec.str(json, "C0"));
            return h;
        }

        private static List<Object> rows(Map<Integer, Element> source) {
            List<Object> out = new ArrayList<>();
            Iterator<Map.Entry<Integer, Element>> it = source.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<Integer, Element> e = it.next();
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("row", e.getKey());
                item.put("value", Codec.enc(e.getValue()));
                out.add(item);
            }
            return out;
        }

        private static void load(Setup.PublicParameters mpk, List<Object> items, Map<Integer, Element> target) {
            for (int i = 0; i < items.size(); i++) {
                Map<String, Object> entry = Codec.map(items.get(i));
                int row = Search.rowNumber(entry.get("row"));
                target.put(row, Codec.g1(mpk, Codec.str(entry, "value")));
            }
        }
    }

    // ================================================================
    // CLAIMANT SIDE: build the help data hp
    // ================================================================

    public static HelpData help(Setup.PublicParameters mpk, String w, Element sko, Element pko, KeyGen.K K) {
        if (mpk == null || w == null || sko == null || pko == null || K == null) {
            throw new IllegalArgumentException("Trace help input cannot be null");
        }
        Pairing pairing = mpk.getPairing();

        // I = every row of the document's access structure.
        List<Integer> I = new ArrayList<>();
        for (int i = 0; i < K.pi.length; i++) {
            I.add(i);
        }

        // gamma with sum(gamma_i * M_i) = (1, 0, ..., 0)
        Element[] gamma = Authorize.solveGamma(pairing, K.M, I);
        if (gamma == null) {
            throw new IllegalStateException("Cannot reconstruct the secret from the access structure");
        }

        HelpData hp = new HelpData();
        for (int t = 0; t < I.size(); t++) {
            if (gamma[t].isZero()) {
                continue;
            }
            int i = I.get(t);
            // sk1,pi(i) ^ gamma_i
            Element sk1Attribute = K.sk1.get(K.pi[i]);
            Element sk1g = sk1Attribute.duplicate().powZn(gamma[t]).getImmutable();
            // sk2 ^ gamma_i
            Element sk2g = K.sk2.duplicate().powZn(gamma[t]).getImmutable();
            hp.sk1Gamma.put(i, sk1g);
            hp.sk2Gamma.put(i, sk2g);
        }

        // P1 = pk_o ^ (1 / H2(w))
        Element inverseH = mpk.getHashFunctions().H2(w).duplicate().invert();
        hp.P1 = pko.duplicate().powZn(inverseH).getImmutable();

        // C0 = e(sk2, pk_o) ^ (sk_o / H2(w))
        Element exponent = sko.duplicate().mul(inverseH);
        hp.C0 = pairing.pairing(K.sk2, pko).powZn(exponent).getImmutable();
        return hp;
    }

    // ================================================================
    // CSP SIDE: Algorithm 10
    // ================================================================

    public static boolean trace(Setup.PublicParameters mpk, List<Map<String, Object>> L, HelpData hp) {
        Pairing pairing = mpk.getPairing();

        // Read L: attribute rows (ct1, ct2) and keyword rows (ct3).
        Map<Integer, Element> ct1 = new LinkedHashMap<>();
        Map<Integer, Element> ct2 = new LinkedHashMap<>();
        List<Element> ct3List = new ArrayList<>();
        for (int e = 0; e < L.size(); e++) {
            Map<String, Object> entry = L.get(e);
            if ("attribute".equals(entry.get("type"))) {
                int row = Search.rowNumber(entry.get("row"));
                ct1.put(row, Codec.g1(mpk, Codec.str(entry, "ct1")));
                ct2.put(row, Codec.g1(mpk, Codec.str(entry, "ct2")));
            } else {
                ct3List.add(Codec.g1(mpk, Codec.str(entry, "ct3")));
            }
        }

        // ------------------------------------------------------------
        // Line 3: t2 <- prod e(ct2,i, sk2^gamma_i) / e(ct1,i, sk1^gamma_i)
        //   (does not depend on w, so it is computed once)
        // ------------------------------------------------------------
        Element numerator = pairing.getGT().newOneElement();
        Element denominator = pairing.getGT().newOneElement();
        Iterator<Map.Entry<Integer, Element>> rows = hp.sk1Gamma.entrySet().iterator();
        while (rows.hasNext()) {
            Map.Entry<Integer, Element> row = rows.next();
            int i = row.getKey();
            Element ct1i = ct1.get(i);
            Element ct2i = ct2.get(i);
            Element sk2g = hp.sk2Gamma.get(i);
            if (ct1i == null || ct2i == null || sk2g == null) {
                return false;
            }
            numerator.mul(pairing.pairing(ct2i, sk2g));
            denominator.mul(pairing.pairing(ct1i, row.getValue()));
        }
        Element t2 = numerator.div(denominator);

        // ------------------------------------------------------------
        // Lines 1-2: for each keyword entry, t1 <- e(ct3,w, P1) / C0
        // ------------------------------------------------------------
        for (int t = 0; t < ct3List.size(); t++) {
            Element t1 = pairing.pairing(ct3List.get(t), hp.P1);
            t1.div(hp.C0);

            // Lines 4-5: if t1 = t2 then return true
            if (t1.isEqual(t2)) {
                return true;
            }
        }

        // ------------------------------------------------------------
        // Line 6: return false
        // ------------------------------------------------------------
        return false;
    }
}
