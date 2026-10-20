import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 9 (Detect) and Algorithm 11 (Enhanced Detect)
 *
 * Both are run by the data owner on a trapdoor the CSP forwarded.
 * They identify the registered user who generated the trapdoor.
 */
public class Detect {

    public static class Result {

        public final Element pkc;
        public final String keyword;

        public Result(Element pkc, String keyword) {
            this.pkc = pkc;
            this.keyword = keyword;
        }
    }

    // ------------------------------------------------
    // ALGORITHM 9
    // ------------------------------------------------

    /**
     * Line 1: pk_c <- tk3^(1 / sk_o^2)
     *
     * Lines 2-4 (send pk_c and tk3 to the CSP, R[pk_c] <- tk3) are
     * performed by the servers when the owner revokes the user.
     */
    public static Element detect(
            Element tk3,
            Element sko) {

        Element inverse = sko.duplicate().mul(sko).invert();

        return tk3.duplicate().powZn(inverse).getImmutable();
    }

    // ------------------------------------------------
    // ALGORITHM 11
    // ------------------------------------------------

    /**
     * @param W  dictionary of keywords of the document
     * @param K  KeyGen output of the document (needs sk1, sk2, M, pi)
     * @throws IllegalStateException with the paper's "Error" outcome
     */
    public static Result detectEnhanced(
            Setup.PublicParameters mpk,
            TrapGen.Trapdoor T,
            Element sko,
            KeyGen.K K,
            Collection<String> W) {

        Pairing pairing = mpk.getPairing();
        Element g = mpk.getG();

        // Line 1: tk6' <- H(sk_o, tk3, tk5)
        String expected = Authorize.tk6(sko, T.tk3, T.tk5);

        // Lines 2-3: if tk6' != tk6 return Error
        if (!expected.equals(T.tk6)) {
            throw new IllegalStateException(
                    "Error: tk3 or tk5 was modified");
        }

        // Line 4: pk_c <- tk3^(1 / sk_o^2)
        Element pkc = detect(T.tk3, sko);

        // Line 5: tk5' <- prod e(tk1,i * tk2,i, g)
        // (equals prod e(issued tk1,i * tk2,i, pk_c) by bilinearity)
        Element tk5 = pairing.getGT().newOneElement();

        for (Map.Entry<Integer, Element> e : T.tk1.entrySet()) {

            Element tk2i = T.tk2.get(e.getKey());

            if (tk2i == null) {
                throw new IllegalStateException(
                        "Error: tk1 and tk2 do not match");
            }

            tk5.mul(pairing.pairing(
                    e.getValue().duplicate().mul(tk2i),
                    g));
        }

        // Lines 6-7: if tk5' != tk5 return Error
        if (!tk5.isEqual(T.tk5)) {
            throw new IllegalStateException(
                    "Error: tk1 or tk2 was modified");
        }

        // Lines 11-13: each attribute component must be sk_c-power of
        // the owner's key: e(tk1,i, g) = e(sk1,pi(i), pk_c)^gamma_i
        List<Integer> rows = new ArrayList<>(T.tk1.keySet());

        Element[] gamma = Authorize.solveGamma(pairing, K.M, rows);

        if (gamma == null) {
            throw new IllegalStateException(
                    "Error: trapdoor rows do not satisfy (M, pi)");
        }

        for (int t = 0; t < rows.size(); t++) {

            int i = rows.get(t);

            Element expected1 = pairing.pairing(
                    K.sk1.get(K.pi[i]), pkc)
                    .powZn(gamma[t]);

            Element expected2 = pairing.pairing(K.sk2, pkc)
                    .powZn(gamma[t]);

            if (!pairing.pairing(T.tk1.get(i), g).isEqual(expected1)
                    || !pairing.pairing(T.tk2.get(i), g)
                    .isEqual(expected2)) {

                throw new IllegalStateException(
                        "Error: attribute components were modified");
            }
        }

        // Line 8: for w in W
        for (String w : W) {

            Element invH = mpk.getHashFunctions().H2(w)
                    .duplicate().invert();

            // Line 9: tk4' <- pk_c^(sk_o / H2(w))
            // (PAPER: pk_c^(sk_o * H2(w)), matching the fixed TrapGen)
            Element tk4 = pkc.duplicate()
                    .powZn(sko.duplicate().mul(invH));

            // Line 10: if tk4' = tk4
            if (tk4.isEqual(T.tk4)) {

                // tk7 must equal e(tk3, sk2)^(-1 / H2(w))
                Element tk7 = pairing.pairing(T.tk3, K.sk2)
                        .powZn(invH.duplicate().negate());

                if (!tk7.isEqual(T.tk7)) {
                    throw new IllegalStateException(
                            "Error: tk7 was modified");
                }

                // Line 14: return pk_c
                return new Result(pkc, w);
            }
        }

        // Line 15: return Error
        throw new IllegalStateException(
                "Error: tk4 matches no keyword of the dictionary");
    }
}
