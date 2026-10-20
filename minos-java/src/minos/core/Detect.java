package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 9 (Detect) and Algorithm 11 (Enhanced Detect)
 *
 * Both are run by the data owner on a trapdoor the CSP forwarded, and they
 * identify the registered user the trapdoor was generated for.
 *
 * <pre>
 * Algorithm 9
 *   1: pk_c <- tk3 ^ (1 / sk_o^2)
 *   2: send pk_c, tk3 to the CSP
 *   3: R[pk_c] <- tk3                 (CSP)
 *   4: return pk_c
 *
 * Algorithm 11
 *   1:  tk6' <- H(sk_o, tk3, tk5)
 *   2:  if tk6' != tk6 then
 *   3:     return Error
 *   4:  pk_c <- tk3 ^ (1 / sk_o^2)
 *   5:  tk5' <- prod e(tk1,i * tk2,i, g)
 *   6:  if tk5' != tk5 then
 *   7:     return Error
 *   8:  for w in W do
 *   9:     tk4' <- pk_c ^ (sk_o / H2(w))     (matches the corrected TrapGen)
 *   10:    if tk4' = tk4 then
 *   11-13:    check every attribute component against sk1, sk2, gamma
 *   14:       return pk_c
 *   15: return Error
 * </pre>
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

    // ================================================================
    // ALGORITHM 9
    // ================================================================

    /**
     * Line 1: pk_c <- tk3 ^ (1 / sk_o^2).
     * Lines 2-4 (send to the CSP, R[pk_c] <- tk3) are done by the Minos
     * Server together with the CSP Server.
     */
    public static Element detect(Element tk3, Element sko) {
        if (tk3 == null || sko == null) {
            throw new IllegalArgumentException("tk3 and sk_o are required");
        }
        // sk_o^2
        Element skoSquared = sko.duplicate();
        skoSquared.mul(sko);
        // 1 / sk_o^2
        Element inverse = skoSquared.invert();
        // tk3 ^ (1 / sk_o^2)
        Element pkc = tk3.duplicate().powZn(inverse);
        return pkc.getImmutable();
    }

    // ================================================================
    // ALGORITHM 11
    // ================================================================

    /**
     * @param W  the keywords of the document
     * @param K  the KeyGen output of the document (sk1, sk2, M, pi)
     * @throws IllegalStateException for the paper's "Error" outcome
     */
    public static Result detectEnhanced(
            Setup.PublicParameters mpk,
            TrapGen.Trapdoor T,
            Element sko,
            KeyGen.K K,
            Collection<String> W) {

        Pairing pairing = mpk.getPairing();
        Element g = mpk.getG();

        // ------------------------------------------------------------
        // Line 1: tk6' <- H(sk_o, tk3, tk5)
        // ------------------------------------------------------------
        String tk6Expected = Authorize.tk6(sko, T.tk3, T.tk5);

        // ------------------------------------------------------------
        // Lines 2-3: if tk6' != tk6 then return Error
        // ------------------------------------------------------------
        if (!tk6Expected.equals(T.tk6)) {
            throw new IllegalStateException("Error: tk3 or tk5 was modified");
        }

        // ------------------------------------------------------------
        // Line 4: pk_c <- tk3 ^ (1 / sk_o^2)
        // ------------------------------------------------------------
        Element pkc = detect(T.tk3, sko);

        // ------------------------------------------------------------
        // Line 5: tk5' <- prod e(tk1,i * tk2,i, g)
        // ------------------------------------------------------------
        Element tk5Expected = pairing.getGT().newOneElement();
        Iterator<Map.Entry<Integer, Element>> rows = T.tk1.entrySet().iterator();
        while (rows.hasNext()) {
            Map.Entry<Integer, Element> row = rows.next();
            Element tk2i = T.tk2.get(row.getKey());
            if (tk2i == null) {
                throw new IllegalStateException("Error: tk1 and tk2 do not match");
            }
            Element sum = row.getValue().duplicate().mul(tk2i);
            tk5Expected.mul(pairing.pairing(sum, g));
        }

        // ------------------------------------------------------------
        // Lines 6-7: if tk5' != tk5 then return Error
        // ------------------------------------------------------------
        if (!tk5Expected.isEqual(T.tk5)) {
            throw new IllegalStateException("Error: tk1 or tk2 was modified");
        }

        // ------------------------------------------------------------
        // Lines 11-13: every attribute component must be the sk_c power of
        // the owner's own key:  e(tk1,i, g) = e(sk1,pi(i), pk_c)^gamma_i
        //                       e(tk2,i, g) = e(sk2, pk_c)^gamma_i
        // ------------------------------------------------------------
        List<Integer> I = new ArrayList<>();
        Iterator<Integer> keys = T.tk1.keySet().iterator();
        while (keys.hasNext()) {
            I.add(keys.next());
        }
        Element[] gamma = Authorize.solveGamma(pairing, K.M, I);
        if (gamma == null) {
            throw new IllegalStateException("Error: trapdoor rows do not satisfy (M, pi)");
        }
        for (int t = 0; t < I.size(); t++) {
            int i = I.get(t);
            Element sk1Attribute = K.sk1.get(K.pi[i]);
            Element expected1 = pairing.pairing(sk1Attribute, pkc).powZn(gamma[t]);
            Element expected2 = pairing.pairing(K.sk2, pkc).powZn(gamma[t]);
            Element actual1 = pairing.pairing(T.tk1.get(i), g);
            Element actual2 = pairing.pairing(T.tk2.get(i), g);
            if (!actual1.isEqual(expected1)) {
                throw new IllegalStateException("Error: attribute components were modified");
            }
            if (!actual2.isEqual(expected2)) {
                throw new IllegalStateException("Error: attribute components were modified");
            }
        }

        // ------------------------------------------------------------
        // Line 8: for w in W
        // ------------------------------------------------------------
        Iterator<String> words = W.iterator();
        while (words.hasNext()) {
            String w = words.next();
            Element inverseH = mpk.getHashFunctions().H2(w).duplicate().invert();

            // Line 9: tk4' <- pk_c ^ (sk_o / H2(w))
            Element exponent = sko.duplicate().mul(inverseH);
            Element tk4Expected = pkc.duplicate().powZn(exponent);

            // Line 10: if tk4' = tk4
            if (tk4Expected.isEqual(T.tk4)) {
                // tk7 must equal e(tk3, sk2)^(-1 / H2(w))
                Element minusInverseH = inverseH.duplicate().negate();
                Element tk7Expected = pairing.pairing(T.tk3, K.sk2).powZn(minusInverseH);
                if (!tk7Expected.isEqual(T.tk7)) {
                    throw new IllegalStateException("Error: tk7 was modified");
                }
                // Line 14: return pk_c
                return new Result(pkc, w);
            }
        }

        // ------------------------------------------------------------
        // Line 15: return Error
        // ------------------------------------------------------------
        throw new IllegalStateException("Error: tk4 matches no keyword of the dictionary");
    }
}
