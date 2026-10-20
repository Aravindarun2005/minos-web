package minos.core;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Minos - Algorithm 1: Setup
 *
 *   1: G = (p, G, GT, e, g) <- GroupGen(1^lambda)
 *   2: H1 : {0,1}* -> G ,  H2 : {0,1}* -> Zp
 *   3-5: for a in A: v <- H1(a); U <- U u {v}
 *   6-7: mpk <- (lambda, G, H1, H2, U); return mpk
 *
 * GroupGen: JPBC type-A symmetric pairing on y^2 = x^3 + x with a 160-bit
 * group order (the paper's parameters, Section VII-C).
 * mpk is persisted with MinosStorage and loaded on every later start; it is
 * never regenerated.
 */
public class Setup {

    public static class PublicParameters {

        private final int lambda;
        private final PairingParameters pairingParameters;
        private final Pairing pairing;
        private final BigInteger p;
        private final Element g;
        private final HashFunctions hashFunctions;
        private final Set<String> attributes;
        private final Map<String, Element> U;

        public PublicParameters(
                int lambda,
                PairingParameters pairingParameters,
                Pairing pairing,
                BigInteger p,
                Element g,
                HashFunctions hashFunctions,
                Set<String> attributes,
                Map<String, Element> U) {

            this.lambda = lambda;
            this.pairingParameters = pairingParameters;
            this.pairing = pairing;
            this.p = p;
            this.g = g;
            this.hashFunctions = hashFunctions;
            this.attributes = new LinkedHashSet<>(attributes);
            this.U = new LinkedHashMap<>(U);
        }

        public int getLambda() {
            return lambda;
        }

        public PairingParameters getPairingParameters() {
            return pairingParameters;
        }

        public Pairing getPairing() {
            return pairing;
        }

        public BigInteger getP() {
            return p;
        }

        public Element getG() {
            return g;
        }

        public HashFunctions getHashFunctions() {
            return hashFunctions;
        }

        public Set<String> getAttributes() {
            return new LinkedHashSet<>(attributes);
        }

        public Map<String, Element> getU() {
            return new LinkedHashMap<>(U);
        }

        public Element getAttributeElement(String attribute) {

            Element value = U.get(attribute);

            if (value == null) {
                throw new IllegalArgumentException(
                        "Attribute not found: " + attribute);
            }

            return value.duplicate().getImmutable();
        }
    }

    public static PublicParameters setup(
            int lambda,
            Set<String> attributeUniverse) {

        if (lambda <= 0) {
            throw new IllegalArgumentException(
                    "Invalid security parameter");
        }

        if (attributeUniverse == null ||
                attributeUniverse.isEmpty()) {
            throw new IllegalArgumentException(
                    "Attribute universe is empty");
        }

        // Input: the attribute names A of the organisation (trimmed, no duplicates).
        Set<String> A = new LinkedHashSet<>();

        for (String attribute : attributeUniverse) {

            if (attribute == null ||
                    attribute.trim().isEmpty()) {
                throw new IllegalArgumentException(
                        "Invalid attribute");
            }

            A.add(attribute.trim());
        }

        // ------------------------------------------------------------
        // Line 1: G = (p, G, GT, e, g) <- GroupGen(1^lambda)
        //   Type-A symmetric pairing on y^2 = x^3 + x, 160-bit group order
        //   p and 512-bit base field (the paper's parameters).
        // ------------------------------------------------------------
        TypeACurveGenerator generator =
                new TypeACurveGenerator(160, 512);

        PairingParameters parameters =
                generator.generate();

        Pairing pairing =
                PairingFactory.getPairing(parameters);

        BigInteger p =
                pairing.getG1().getOrder();

        Element g =
                pairing.getG1()
                        .newRandomElement()
                        .getImmutable();

        // ------------------------------------------------------------
        // Line 2: choose H1 : {0,1}* -> G  and  H2 : {0,1}* -> Zp
        // ------------------------------------------------------------
        HashFunctions hashFunctions =
                new HashFunctions(pairing);

        // ------------------------------------------------------------
        // Lines 3-5: U <- empty; for a in A do v <- H1(a); U <- U u {v}
        // ------------------------------------------------------------
        Map<String, Element> U =
                new LinkedHashMap<>();

        for (String attribute : A) {

            // Line 4: v <- H1(a)
            Element v = hashFunctions.H1(attribute);

            // Line 5: U <- U u {v}

            U.put(
                    attribute,
                    v.getImmutable());
        }

        // ------------------------------------------------------------
        // Lines 6-7: mpk <- (lambda, G, H1, H2, U); return mpk
        // ------------------------------------------------------------
        return new PublicParameters(
                lambda,
                parameters,
                pairing,
                p,
                g,
                hashFunctions,
                A,
                U);
    }

    public static PublicParameters runSetup(
            Set<String> attributes,
            Path storageFile)
            throws Exception {

        if (java.nio.file.Files.exists(storageFile)) {
            throw new IllegalStateException(
                    "Minos is already initialized");
        }

        PublicParameters mpk =
                setup(160, attributes);

        MinosStorage.save(storageFile, mpk);

        return mpk;
    }

    public static PublicParameters loadSetup(
            Path storageFile)
            throws Exception {

        return MinosStorage.load(storageFile);
    }
    
    public static String toJson(
            PublicParameters mpk) {

        StringBuilder json = new StringBuilder();

        json.append("{");

        json.append("\"lambda\":")
                .append(mpk.getLambda())
                .append(",");

        json.append("\"p\":\"")
                .append(mpk.getP())
                .append("\",");

        json.append("\"g\":\"")
                .append(escapeJson(
                        mpk.getG().toString()))
                .append("\",");

        json.append("\"attributes\":[");

        boolean first = true;

        for (String attribute : mpk.getAttributes()) {

            if (!first) {
                json.append(",");
            }

            json.append("\"")
                    .append(escapeJson(attribute))
                    .append("\"");

            first = false;
        }

        json.append("],");

        json.append("\"U\":{");

        first = true;

        for (Map.Entry<String, Element> entry :
                mpk.getU().entrySet()) {

            if (!first) {
                json.append(",");
            }

            json.append("\"")
                    .append(escapeJson(entry.getKey()))
                    .append("\":\"")
                    .append(escapeJson(
                            entry.getValue().toString()))
                    .append("\"");

            first = false;
        }

        json.append("}");

        json.append("}");

        return json.toString();
    }

    private static String escapeJson(String value) {

        StringBuilder escaped = new StringBuilder();

        for (int i = 0; i < value.length(); i++) {

            char c = value.charAt(i);

            switch (c) {

                case '"':
                    escaped.append("\\\"");
                    break;

                case '\\':
                    escaped.append("\\\\");
                    break;

                case '\n':
                    escaped.append("\\n");
                    break;

                case '\r':
                    escaped.append("\\r");
                    break;

                case '\t':
                    escaped.append("\\t");
                    break;

                default:
                    if (c < 0x20) {
                        escaped.append(
                                String.format(
                                        "\\u%04x",
                                        (int) c));
                    } else {
                        escaped.append(c);
                    }
            }
        }

        return escaped.toString();
    }
}