import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 10: Trace (traceable ownership)
 *
 * The owner builds help data hp for one keyword w of the document and
 * the CSP checks it against the stored encrypted index. Only the owner
 * can build valid help data, because it needs sk_o and the KeyGen
 * secrets (sk1, sk2) of that document.
 *
 * Help data:
 *   { sk1,pi(i)^gamma_i , sk2^gamma_i } for the rows in I
 *   P1 = pk_o^(1 / H2(w))
 *   C0 = e(sk2, pk_o)^(sk_o / H2(w))
 *
 * Check (exponents of e(g,g)):
 *   t2 = prod e(ct2,i, sk2^gamma_i) / e(ct1,i, sk1^gamma_i) = sk_o * r * s0
 *   t1 = e(ct3,w, P1) / C0
 *      = r*(s0*H2(w) + sk_o) * sk_o/H2(w)  -  r*sk_o^2/H2(w)
 *      = sk_o * r * s0
 *
 * PAPER line 2 prints t1 = e(ct3,w, pk_o^(H2(w) + sk_o)); with the
 * ciphertext of Algorithm 4 that value depends on s0 in a way the
 * verifier cannot cancel, so P1 and C0 replace it.
 */
public class Trace {

    public static class HelpData {

        public final Map<Integer, Element> sk1Gamma = new LinkedHashMap<>();
        public final Map<Integer, Element> sk2Gamma = new LinkedHashMap<>();
        public Element P1;   // G
        public Element C0;   // GT

        public Map<String, Object> toJson() {

            Map<String, Object> out = new LinkedHashMap<>();

            out.put("sk1Gamma", rows(sk1Gamma));
            out.put("sk2Gamma", rows(sk2Gamma));
            out.put("P1", Codec.enc(P1));
            out.put("C0", Codec.enc(C0));

            return out;
        }

        public static HelpData fromJson(
                Setup.PublicParameters mpk,
                Map<String, Object> json) {

            HelpData h = new HelpData();

            load(mpk, Codec.list(json.get("sk1Gamma")), h.sk1Gamma);
            load(mpk, Codec.list(json.get("sk2Gamma")), h.sk2Gamma);

            h.P1 = Codec.g1(mpk, Codec.str(json, "P1"));
            h.C0 = Codec.gt(mpk, Codec.str(json, "C0"));

            return h;
        }

        private static List<Object> rows(Map<Integer, Element> source) {

            List<Object> out = new ArrayList<>();

            for (Map.Entry<Integer, Element> e : source.entrySet()) {

                Map<String, Object> item = new LinkedHashMap<>();

                item.put("row", e.getKey());
                item.put("value", Codec.enc(e.getValue()));

                out.add(item);
            }

            return out;
        }

        private static void load(
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
    // OWNER SIDE: build help data hp
    // ------------------------------------------------

    public static HelpData help(
            Setup.PublicParameters mpk,
            String w,
            Element sko,
            Element pko,
            KeyGen.K K) {

        Pairing pairing = mpk.getPairing();

        // I = all rows of the document's access structure.
        List<Integer> I = new ArrayList<>();

        for (int i = 0; i < K.pi.length; i++) {
            I.add(i);
        }

        Element[] gamma = Authorize.solveGamma(pairing, K.M, I);

        if (gamma == null) {
            throw new IllegalStateException(
                    "Cannot reconstruct the secret from the access structure");
        }

        HelpData hp = new HelpData();

        for (int t = 0; t < I.size(); t++) {

            if (gamma[t].isZero()) continue;

            int i = I.get(t);

            hp.sk1Gamma.put(i, K.sk1.get(K.pi[i])
                    .duplicate().powZn(gamma[t]).getImmutable());

            hp.sk2Gamma.put(i, K.sk2
                    .duplicate().powZn(gamma[t]).getImmutable());
        }

        Element invH = mpk.getHashFunctions().H2(w)
                .duplicate().invert();

        hp.P1 = pko.duplicate().powZn(invH).getImmutable();

        hp.C0 = pairing.pairing(K.sk2, pko)
                .powZn(sko.duplicate().mul(invH))
                .getImmutable();

        return hp;
    }

    // ------------------------------------------------
    // CSP SIDE: Algorithm 10
    // ------------------------------------------------

    public static boolean trace(
            Setup.PublicParameters mpk,
            List<Map<String, Object>> L,
            HelpData hp) {

        Pairing pairing = mpk.getPairing();

        Map<Integer, Element[]> attributeRows = new LinkedHashMap<>();
        List<Element> ct3List = new ArrayList<>();

        for (Map<String, Object> entry : L) {

            if ("attribute".equals(entry.get("type"))) {

                int row = Integer.parseInt(
                        String.valueOf(entry.get("row")));

                attributeRows.put(row, new Element[]{
                        Codec.g1(mpk, Codec.str(entry, "ct1")),
                        Codec.g1(mpk, Codec.str(entry, "ct2"))
                });

            } else {
                ct3List.add(Codec.g1(mpk, Codec.str(entry, "ct3")));
            }
        }

        // Line 3: t2 <- prod e(ct2,i, sk2^gamma_i) / e(ct1,i, sk1^gamma_i)
        Element numerator = pairing.getGT().newOneElement();
        Element denominator = pairing.getGT().newOneElement();

        for (Map.Entry<Integer, Element> e : hp.sk1Gamma.entrySet()) {

            Element[] ct = attributeRows.get(e.getKey());
            Element sk2g = hp.sk2Gamma.get(e.getKey());

            if (ct == null || sk2g == null) return false;

            numerator.mul(pairing.pairing(ct[1], sk2g));
            denominator.mul(pairing.pairing(ct[0], e.getValue()));
        }

        Element t2 = numerator.div(denominator);

        // Lines 1-2: for each keyword entry, t1 <- e(ct3,w, P1) / C0
        for (Element ct3 : ct3List) {

            Element t1 = pairing.pairing(ct3, hp.P1)
                    .div(hp.C0);

            // Lines 4-5: if t1 = t2 return true
            if (t1.isEqual(t2)) return true;
        }

        // Line 6: return false
        return false;
    }
}
