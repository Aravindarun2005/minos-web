import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 7: Search (executed by the CSP)
 *
 * Input : encrypted index L of one document, trapdoor T
 * Output: C = the ct4 values whose keyword matches the trapdoor
 *
 * Correctness (exponents in GT, e(g,g) = base):
 *
 *   Delta = prod e(tk1,i, ct1,i) / prod e(ct2,i, tk2,i)
 *         = e(g,g)^( - sk_o * r * sk_c * s0 )
 *
 *   ct3   = g^( r * (s0*H2(w) + sk_o) )
 *   tk4   = g^( sk_c * sk_o / H2(w') )
 *   tk7   = e(g,g)^( - r * sk_c * sk_o^2 / H2(w') )
 *
 *   e(tk4, ct3) * Delta * tk7
 *     = e(g,g)^( r*sk_c*sk_o * s0 * (H2(w)/H2(w') - 1) )
 *
 * which equals 1 exactly when H2(w) = H2(w').
 *
 * PAPER line 5 prints e(tk3*tk4, ct3) * Delta = 1. With the ciphertext
 * of Algorithm 4 that equation cannot hold, because ct3 mixes s0 and
 * sk_o in its exponent. tk7 is the extra term that removes the sk_o part.
 */
public class Search {

    public static List<String> search(
            Setup.PublicParameters mpk,
            List<Map<String, Object>> L,
            TrapGen.Trapdoor T) {

        Pairing pairing = mpk.getPairing();

        // Attribute entries: row -> (ct1, ct2)
        Map<Integer, Element[]> attributeRows = new HashMap<>();

        // Keyword entries: (ct3, ct4)
        List<Object[]> keywordEntries = new ArrayList<>();

        for (Map<String, Object> entry : L) {

            if ("attribute".equals(entry.get("type"))) {

                int row = Integer.parseInt(
                        String.valueOf(entry.get("row")));

                attributeRows.put(row, new Element[]{
                        Codec.g1(mpk, Codec.str(entry, "ct1")),
                        Codec.g1(mpk, Codec.str(entry, "ct2"))
                });

            } else {

                keywordEntries.add(new Object[]{
                        Codec.g1(mpk, Codec.str(entry, "ct3")),
                        Codec.str(entry, "ct4")
                });
            }
        }

        // Line 1: C <- empty set
        List<String> C = new ArrayList<>();

        // Line 2: ({ct1,i}, {ct2,i}) <- L (attribute entries above)

        // Line 3: Delta <- prod e(tk1,i, ct1,i) / prod e(ct2,i, tk2,i)
        Element numerator = pairing.getGT().newOneElement();
        Element denominator = pairing.getGT().newOneElement();

        for (Map.Entry<Integer, Element> e : T.tk1.entrySet()) {

            Element[] ct = attributeRows.get(e.getKey());
            Element tk2i = T.tk2.get(e.getKey());

            if (ct == null || tk2i == null) {
                throw new IllegalArgumentException(
                        "Trapdoor does not match this index");
            }

            numerator.mul(pairing.pairing(e.getValue(), ct[0]));
            denominator.mul(pairing.pairing(ct[1], tk2i));
        }

        Element delta = numerator.div(denominator);

        // Lines 4-6: for each (ct3,w, ct4,w) in L
        for (Object[] keyword : keywordEntries) {

            Element ct3 = (Element) keyword[0];

            // Line 5: PAPER e(tk3*tk4, ct3,w) * Delta = 1
            //         FIX   e(tk4, ct3,w) * Delta * tk7 = 1
            Element value = pairing.pairing(T.tk4, ct3)
                    .mul(delta)
                    .mul(T.tk7);

            if (value.isOne()) {

                // Line 6: C <- ct4,w
                C.add((String) keyword[1]);
            }
        }

        // Lines 7-8: return C
        return C;
    }
}
