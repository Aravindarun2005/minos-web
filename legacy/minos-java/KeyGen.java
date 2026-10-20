
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class KeyGen {

    public static class K {

        public Map<String, Element> sk1;
        public Element sk2;
        public byte[] k;

        public Element[][] M;
        public String[] pi;
    }

    // Algorithm 3: Key Generation
    public static K keyGen(
            Setup.PublicParameters mpk,
            Set<String> selectedAttributes,
            int n1,
            int n2) {

        if (mpk == null) {
            throw new IllegalArgumentException(
                    "Public parameters are required");
        }

        if (selectedAttributes == null ||
                selectedAttributes.isEmpty()) {
            throw new IllegalArgumentException(
                    "Attribute set cannot be empty");
        }

        if (n1 <= 0 || n2 <= 0) {
            throw new IllegalArgumentException(
                    "Invalid matrix dimensions");
        }

        Set<String> U = mpk.getAttributes();

        Set<String> attributes =
                new LinkedHashSet<>(selectedAttributes);

        if (n1 != attributes.size()) {
            throw new IllegalArgumentException(
                    "n1 must equal the number of mapped attributes");
        }

        for (String attribute : attributes) {
            if (!U.contains(attribute)) {
                throw new IllegalArgumentException(
                        "Unknown attribute: " + attribute);
            }
        }

        Pairing pairing = mpk.getPairing();

        K result = new K();

        SecureRandom random = new SecureRandom();

        // Line 1:
        // M <- Zp^(n1 x n2)
        //
        // PAPER: M is a random matrix. A random M gives no usable
        // access policy: a user holding a single attribute could
        // never satisfy sum(gamma_i * M_i) = (1,0,...,0).
        //
        // Here every row is (1,0,...,0). The access structure
        // becomes "attribute pi(1) OR pi(2) OR ...": any one
        // listed attribute reconstructs s0 with gamma_i = 1.

        result.M = new Element[n1][n2];

        for (int i = 0; i < n1; i++) {
            for (int j = 0; j < n2; j++) {

                result.M[i][j] =
                        (j == 0
                                ? pairing.getZr().newOneElement()
                                : pairing.getZr().newZeroElement())
                                .getImmutable();
            }
        }

        // Line 2:
        // Define injective pi: [n1] -> U

        result.pi = new String[n1];

        int row = 0;

        for (String attribute : attributes) {
            result.pi[row] = attribute;
            row++;
        }

        // Line 3:
        // r <- Zp

        Element r = pairing.getZr()
                .newRandomElement()
                .getImmutable();

        // Lines 4 and 5:
        // For every v in U:
        // sk1,v <- v^r

        result.sk1 = new LinkedHashMap<>();

        for (String attribute : U) {

            Element v =
                    mpk.getAttributeElement(attribute);

            Element sk1v =
                    v.duplicate()
                            .powZn(r)
                            .getImmutable();

            result.sk1.put(attribute, sk1v);
        }

        // Line 6:
        // sk2 <- g^r

        result.sk2 =
                mpk.getG()
                        .duplicate()
                        .powZn(r)
                        .getImmutable();

        // Line 7:
        // k <- {0,1}^lambda

        int lambda = mpk.getLambda();

        result.k = new byte[lambda / 8];

        random.nextBytes(result.k);

        // Lines 8 and 9:
        // K <- ( {sk1,v}, sk2, k, M, pi )
        // Return K

        return result;
    }
}