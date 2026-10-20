package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 7: Search (run by the CSP)
 *
 * <pre>
 *   Input : encrypted index L of one document, trapdoor T
 *   Output: C, the ct4 values whose keyword matches the trapdoor
 *
 *   1: C <- empty
 *   2: ({ct1,i}, {ct2,i}) <- L
 *   3: Delta <- prod e(tk1,i, ct1,i) / prod e(ct2,i, tk2,i)
 *   4: for (ct3,w, ct4,w) in L do
 *   5:    if e(tk3 * tk4, ct3,w) * Delta = 1 then      (corrected, see below)
 *   6:       C <- C u {ct4,w}
 *   7: return C
 * </pre>
 *
 * Why it works (exponents of e(g,g)):
 *   Delta = - sk_o * r * sk_c * s0
 *   ct3   = r * (s0*H2(w) + sk_o)          (in G)
 *   tk4   = sk_c * sk_o / H2(w')            (in G)
 *   tk7   = - r * sk_c * sk_o^2 / H2(w')
 *   e(tk4, ct3) * Delta * tk7 = r*sk_c*sk_o*s0*(H2(w)/H2(w') - 1)
 * which is 1 exactly when H2(w) = H2(w').
 *
 * The printed line 5 e(tk3*tk4, ct3) * Delta = 1 cannot hold for the
 * ciphertext of Algorithm 4 (ct3 mixes s0 and sk_o); tk7 removes the sk_o
 * part. Checked numerically in test/PaperEquationCheck.
 */
public class Search {

    /**
     * Trapdoor consistency check done by the CSP before searching (paper
     * Section VI-D: tk1 and tk2 can be verified with tk5). No secret needed:
     *   tk5 = prod e(T.tk1,i * T.tk2,i, g)
     * A trapdoor whose attribute components were altered fails this test.
     */
    public static boolean verifyTk5(Setup.PublicParameters mpk, TrapGen.Trapdoor T) {
        Pairing pairing = mpk.getPairing();
        Element g = mpk.getG();

        // tk1 and tk2 must be non-empty and cover exactly the same rows.
        if (T.tk1.isEmpty()) {
            return false;
        }
        if (T.tk1.size() != T.tk2.size()) {
            return false;
        }
        Iterator<Integer> rows = T.tk1.keySet().iterator();
        while (rows.hasNext()) {
            if (!T.tk2.containsKey(rows.next())) {
                return false;
            }
        }

        Element product = pairing.getGT().newOneElement();
        Iterator<Map.Entry<Integer, Element>> entries = T.tk1.entrySet().iterator();
        while (entries.hasNext()) {
            Map.Entry<Integer, Element> entry = entries.next();
            Element tk1i = entry.getValue();
            Element tk2i = T.tk2.get(entry.getKey());
            Element sum = tk1i.duplicate().mul(tk2i);
            Element pairingValue = pairing.pairing(sum, g);
            product.mul(pairingValue);
        }
        return product.isEqual(T.tk5);
    }

    public static List<String> search(Setup.PublicParameters mpk, List<Map<String, Object>> L, TrapGen.Trapdoor T) {

        if (mpk == null || L == null || T == null) {
            throw new IllegalArgumentException("Search input cannot be null");
        }
        Pairing pairing = mpk.getPairing();

        // ------------------------------------------------------------
        // Line 1: C <- empty
        // ------------------------------------------------------------
        List<String> C = new ArrayList<>();

        // ------------------------------------------------------------
        // Line 2: ({ct1,i}, {ct2,i}) <- L
        //   Attribute entries: row -> (ct1, ct2); keyword entries: (ct3, ct4).
        // ------------------------------------------------------------
        Map<Integer, Element> ct1 = new HashMap<>();
        Map<Integer, Element> ct2 = new HashMap<>();
        List<Element> ct3List = new ArrayList<>();
        List<String> ct4List = new ArrayList<>();
        for (int e = 0; e < L.size(); e++) {
            Map<String, Object> entry = L.get(e);
            Object type = entry.get("type");
            if ("attribute".equals(type)) {
                int row = rowNumber(entry.get("row"));
                ct1.put(row, Codec.g1(mpk, Codec.str(entry, "ct1")));
                ct2.put(row, Codec.g1(mpk, Codec.str(entry, "ct2")));
            } else {
                ct3List.add(Codec.g1(mpk, Codec.str(entry, "ct3")));
                ct4List.add(Codec.str(entry, "ct4"));
            }
        }

        // ------------------------------------------------------------
        // Line 3: Delta <- prod e(tk1,i, ct1,i) / prod e(ct2,i, tk2,i)
        // ------------------------------------------------------------
        Element numerator = pairing.getGT().newOneElement();
        Element denominator = pairing.getGT().newOneElement();
        Iterator<Map.Entry<Integer, Element>> rows = T.tk1.entrySet().iterator();
        while (rows.hasNext()) {
            Map.Entry<Integer, Element> row = rows.next();
            int i = row.getKey();
            Element tk1i = row.getValue();
            Element tk2i = T.tk2.get(i);
            Element ct1i = ct1.get(i);
            Element ct2i = ct2.get(i);
            if (ct1i == null || ct2i == null || tk2i == null) {
                throw new IllegalArgumentException("Trapdoor does not match this index");
            }
            Element top = pairing.pairing(tk1i, ct1i);
            Element bottom = pairing.pairing(ct2i, tk2i);
            numerator.mul(top);
            denominator.mul(bottom);
        }
        Element delta = numerator.div(denominator);

        // ------------------------------------------------------------
        // Lines 4-6: for (ct3,w, ct4,w) in L
        // ------------------------------------------------------------
        for (int t = 0; t < ct3List.size(); t++) {
            Element ct3w = ct3List.get(t);

            // Line 5 (corrected): e(tk4, ct3,w) * Delta * tk7 = 1 ?
            Element value = pairing.pairing(T.tk4, ct3w);
            value.mul(delta);
            value.mul(T.tk7);

            if (value.isOne()) {
                // Line 6: C <- C u {ct4,w}
                C.add(ct4List.get(t));
            }
        }

        // ------------------------------------------------------------
        // Line 7: return C
        // ------------------------------------------------------------
        return C;
    }

    /** The "row" field of an index entry, written as a number or as text. */
    static int rowNumber(Object value) {
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        String text = String.valueOf(value);
        int result = 0;
        boolean negative = false;
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (i == 0 && ch == '-') {
                negative = true;
            } else if (ch >= '0' && ch <= '9') {
                result = result * 10 + (ch - '0');
            } else {
                throw new IllegalArgumentException("Invalid row number: " + text);
            }
        }
        return negative ? -result : result;
    }
}
