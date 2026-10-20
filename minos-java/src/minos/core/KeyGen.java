package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.SecureRandom;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Minos - Algorithm 3: Key Generation (KeyGen)
 *
 * <pre>
 *   Input : mpk
 *   Output: K = ({sk1,v}_{v in U}, sk2, k, M, pi)
 *
 *   Set the access structure
 *     1: M  <- Zp^(n1 x n2)
 *     2: pi : [n1] -> U        (injective)
 *   Generate the secret keys
 *     3: r  <- Zp
 *     4: for v in U do
 *     5:    sk1,v <- v^r
 *     6: sk2 <- g^r
 *     7: k   <- {0,1}^lambda
 *     8: K   <- ({sk1,v}, sk2, k, M, pi)
 *     9: return K
 * </pre>
 *
 * How the project uses it:
 *   - Lines 3-7 run automatically right after Register for every account
 *     (keyGen(mpk)). The result is kept only in the Minos Server's
 *     encrypted key vault, never at the CSP.
 *   - Lines 1-2 depend on which roles may read a document, which is known
 *     only when the owner uploads it, so they run per document
 *     (withAccessStructure). A random matrix encodes no usable rule, so M
 *     is built from the owner's rule with AccessPolicy (LSSS matrix).
 */
public class KeyGen {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** The key tuple K of the paper. */
    public static class K {

        /** sk1,v for every attribute v of the universe U (attribute name -> sk1,v). */
        public Map<String, Element> sk1;

        /** sk2 = g^r */
        public Element sk2;

        /** k, the lambda-bit symmetric secret. */
        public byte[] k;

        /** Access matrix M (n1 rows x n2 columns); null until lines 1-2 run. */
        public Element[][] M;

        /** pi(i): the attribute that row i of M belongs to. */
        public String[] pi;

        /** Lines 1-2 for one document: returns K with (M, pi) attached. */
        public K withAccessStructure(AccessPolicy policy) {
            if (policy == null) {
                throw new IllegalArgumentException("An access policy is required");
            }
            K complete = new K();
            complete.sk1 = this.sk1;
            complete.sk2 = this.sk2;
            complete.k = this.k;
            // Line 1: M
            complete.M = policy.M;
            // Line 2: pi
            complete.pi = policy.pi;
            return complete;
        }

        /** True once lines 1-2 have been applied. */
        public boolean hasAccessStructure() {
            if (M == null) {
                return false;
            }
            if (pi == null) {
                return false;
            }
            return true;
        }
    }

    /** Algorithm 3, lines 3-9 (the access structure is attached per document). */
    public static K keyGen(Setup.PublicParameters mpk) {
        if (mpk == null) {
            throw new IllegalArgumentException("Public parameters are required");
        }

        Pairing pairing = mpk.getPairing();
        Field Zp = pairing.getZr();
        Element g = mpk.getG();
        Map<String, Element> U = mpk.getU();
        K result = new K();

        // ------------------------------------------------------------
        // Line 3: r <- Zp
        //   r = 0 would make every key the identity element.
        // ------------------------------------------------------------
        Element r = Zp.newRandomElement();
        while (r.isZero()) {
            r = Zp.newRandomElement();
        }
        r = r.getImmutable();

        // ------------------------------------------------------------
        // Lines 4-5: for v in U do sk1,v <- v^r
        // ------------------------------------------------------------
        result.sk1 = new LinkedHashMap<>();
        Iterator<Map.Entry<String, Element>> attributes = U.entrySet().iterator();
        while (attributes.hasNext()) {
            Map.Entry<String, Element> entry = attributes.next();
            String attributeName = entry.getKey();
            Element v = entry.getValue();
            Element vCopy = v.duplicate();
            Element sk1v = vCopy.powZn(r).getImmutable();
            result.sk1.put(attributeName, sk1v);
        }

        // ------------------------------------------------------------
        // Line 6: sk2 <- g^r
        // ------------------------------------------------------------
        Element gCopy = g.duplicate();
        result.sk2 = gCopy.powZn(r).getImmutable();

        // ------------------------------------------------------------
        // Line 7: k <- {0,1}^lambda
        //   lambda bits = lambda / 8 bytes, at least 16 bytes (128 bits).
        // ------------------------------------------------------------
        int lengthInBytes = mpk.getLambda() / 8;
        if (lengthInBytes < 16) {
            lengthInBytes = 16;
        }
        result.k = new byte[lengthInBytes];
        RANDOM.nextBytes(result.k);

        // ------------------------------------------------------------
        // Lines 8-9: K <- ({sk1,v}, sk2, k, M, pi); return K
        //   M and pi are attached per document (withAccessStructure).
        // ------------------------------------------------------------
        result.M = null;
        result.pi = null;
        return result;
    }

    /** The complete Algorithm 3 (lines 1-9) in one call. */
    public static K keyGen(Setup.PublicParameters mpk, AccessPolicy policy) {
        K keys = keyGen(mpk);
        return keys.withAccessStructure(policy);
    }
}
