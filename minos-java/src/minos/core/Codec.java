package minos.core;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;

/**
 * Encoding helpers shared by the Minos algorithms.
 *
 * Every group element travels between the Minos server, the CSP server and
 * the browser as Base64(element.toBytes()).
 */
public final class Codec {

    private Codec() {
    }

    public static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    public static byte[] unb64(String value) {
        return Base64.getDecoder().decode(value);
    }

    public static String enc(Element element) {
        return b64(element.toBytes());
    }

    public static Element g1(Setup.PublicParameters mpk, String value) {
        return mpk.getPairing().getG1()
                .newElementFromBytes(unb64(value))
                .getImmutable();
    }

    public static Element zr(Setup.PublicParameters mpk, String value) {
        return mpk.getPairing().getZr()
                .newElementFromBytes(unb64(value))
                .getImmutable();
    }

    public static Element gt(Setup.PublicParameters mpk, String value) {
        return mpk.getPairing().getGT()
                .newElementFromBytes(unb64(value))
                .getImmutable();
    }

    // ------------------------------------------------
    // JSON access helpers
    // ------------------------------------------------

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object value) {

        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("Expected a JSON object");
        }

        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object value) {

        if (!(value instanceof List)) {
            throw new IllegalArgumentException("Expected a JSON array");
        }

        return (List<Object>) value;
    }

    public static String str(Map<String, Object> object, String key) {

        Object value = object.get(key);

        if (!(value instanceof String) || ((String) value).isEmpty()) {
            throw new IllegalArgumentException("Missing field: " + key);
        }

        return (String) value;
    }

    // ------------------------------------------------
    // K <-> JSON
    // ------------------------------------------------

    public static Map<String, Object> kToJson(KeyGen.K K) {

        Map<String, Object> out = new LinkedHashMap<>();

        Map<String, Object> sk1 = new LinkedHashMap<>();

        for (Map.Entry<String, Element> e : K.sk1.entrySet()) {
            sk1.put(e.getKey(), enc(e.getValue()));
        }

        out.put("sk1", sk1);
        out.put("sk2", enc(K.sk2));
        out.put("k", b64(K.k));

        if (!K.hasAccessStructure()) {
            return out;
        }

        List<Object> M = new ArrayList<>();

        for (Element[] row : K.M) {

            List<Object> r = new ArrayList<>();

            for (Element cell : row) {
                r.add(enc(cell));
            }

            M.add(r);
        }

        out.put("M", M);

        List<Object> pi = new ArrayList<>();

        for (String attribute : K.pi) {
            pi.add(attribute);
        }

        out.put("pi", pi);

        return out;
    }

    public static KeyGen.K kFromJson(
            Setup.PublicParameters mpk,
            Map<String, Object> json) {

        KeyGen.K K = new KeyGen.K();

        K.sk1 = new LinkedHashMap<>();

        for (Map.Entry<String, Object> e : map(json.get("sk1")).entrySet()) {
            K.sk1.put(e.getKey(), g1(mpk, (String) e.getValue()));
        }

        K.sk2 = g1(mpk, str(json, "sk2"));
        K.k = unb64(str(json, "k"));

        if (json.get("M") == null) {
            return K;
        }

        List<Object> rows = list(json.get("M"));

        K.M = new Element[rows.size()][];

        for (int i = 0; i < rows.size(); i++) {

            List<Object> cells = list(rows.get(i));

            K.M[i] = new Element[cells.size()];

            for (int j = 0; j < cells.size(); j++) {
                K.M[i][j] = zr(mpk, (String) cells.get(j));
            }
        }

        List<Object> pi = list(json.get("pi"));

        K.pi = new String[pi.size()];

        for (int i = 0; i < pi.size(); i++) {
            K.pi[i] = (String) pi.get(i);
        }

        return K;
    }
}
