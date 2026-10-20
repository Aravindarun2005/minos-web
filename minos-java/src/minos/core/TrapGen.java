package minos.core;

import it.unisa.dia.gas.jpbc.Element;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Minos - Algorithm 6: TrapGen
 *
 * <pre>
 *   Input : mpk, keyword w, client private key sk_c, search token TK
 *   Output: trapdoor T
 *
 *   1: ({tk1,i}, {tk2,i}, tk3, tk4) <- TK
 *   2: for i in I do
 *   3:    tk1,i <- tk1,i ^ sk_c
 *   4:    tk2,i <- tk2,i ^ sk_c
 *   5: tk4 <- tk4 ^ H2(w)                 (corrected, see below)
 *   6: T <- ({tk1,i}, {tk2,i}, tk3, tk4)
 *   7: return T
 * </pre>
 *
 * Correction (checked numerically in test/PaperEquationCheck):
 *   line 5 uses the exponent 1/H2(w) instead of H2(w), and the extra
 *   component tk7 = e(tk3, sk2) from Authorize is raised to -1/H2(w).
 *   With the Algorithm 4 ciphertext ct3 = sk2^(s0 H2(w) + sk_o), only this
 *   makes  e(tk4, ct3) * Delta * tk7 = 1  hold exactly when the trapdoor
 *   keyword equals the stored keyword (see Search).
 *
 * tk5 and tk6 (Algorithm 11) are copied unchanged.
 *
 * TrapGen is deterministic in (TK, w, sk_c), exactly as in the paper. The
 * one-time use of each search is an application envelope around T
 * (minos.ext.TrapdoorEnvelope); it does not change T.
 */
public class TrapGen {

    /** The trapdoor T: the same components as the token TK. */
    public static class Trapdoor extends Authorize.Token {

        public static Trapdoor fromJson(Setup.PublicParameters mpk, Map<String, Object> json) {
            Trapdoor t = new Trapdoor();
            t.load(mpk, json);
            return t;
        }

        /**
         * A fixed byte encoding of every component, used to compute a
         * reliable trapdoor hash that does not depend on JSON formatting.
         * Layout: "MINOS-T", tk1 rows (sorted), tk2 rows (sorted), tk3,
         * tk4, tk5, tk6, tk7. Every length and row number is written as a
         * 4-byte big-endian integer.
         */
        public byte[] canonicalBytes() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] label = "MINOS-T".getBytes(StandardCharsets.US_ASCII);
            writeBytes(out, label);
            writeRows(out, tk1);
            writeRows(out, tk2);
            writeElement(out, tk3);
            writeElement(out, tk4);
            writeElement(out, tk5);
            byte[] six = tk6.getBytes(StandardCharsets.US_ASCII);
            writeInt(out, six.length);
            writeBytes(out, six);
            writeElement(out, tk7);
            return out.toByteArray();
        }

        private static void writeRows(ByteArrayOutputStream out, Map<Integer, Element> rows) {
            // Collect the row numbers and sort them (insertion sort).
            List<Integer> keys = new ArrayList<>();
            Iterator<Integer> it = rows.keySet().iterator();
            while (it.hasNext()) {
                keys.add(it.next());
            }
            for (int i = 1; i < keys.size(); i++) {
                int current = keys.get(i);
                int j = i - 1;
                while (j >= 0 && keys.get(j) > current) {
                    keys.set(j + 1, keys.get(j));
                    j = j - 1;
                }
                keys.set(j + 1, current);
            }
            writeInt(out, keys.size());
            for (int i = 0; i < keys.size(); i++) {
                int row = keys.get(i);
                writeInt(out, row);
                writeElement(out, rows.get(row));
            }
        }

        private static void writeElement(ByteArrayOutputStream out, Element e) {
            byte[] b = e.toBytes();
            writeInt(out, b.length);
            writeBytes(out, b);
        }

        private static void writeInt(ByteArrayOutputStream out, int value) {
            out.write((value >>> 24) & 0xFF);
            out.write((value >>> 16) & 0xFF);
            out.write((value >>> 8) & 0xFF);
            out.write(value & 0xFF);
        }

        private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                out.write(bytes[i]);
            }
        }
    }

    public static Trapdoor trapGen(Setup.PublicParameters mpk, String w, Element skc, Authorize.Token TK) {

        // ------------------------------------------------------------
        // Input checks
        // ------------------------------------------------------------
        if (mpk == null || skc == null || TK == null) {
            throw new IllegalArgumentException("TrapGen input cannot be null");
        }
        if (w == null || w.isEmpty()) {
            throw new IllegalArgumentException("Keyword is empty");
        }

        Trapdoor T = new Trapdoor();

        // ------------------------------------------------------------
        // Line 1: ({tk1,i}, {tk2,i}, tk3, tk4) <- TK
        // ------------------------------------------------------------
        Map<Integer, Element> tk1 = TK.tk1;
        Map<Integer, Element> tk2 = TK.tk2;
        Element tk3 = TK.tk3;
        Element tk4 = TK.tk4;

        // ------------------------------------------------------------
        // Lines 2-4: for i in I
        // ------------------------------------------------------------
        Iterator<Map.Entry<Integer, Element>> rows = tk1.entrySet().iterator();
        while (rows.hasNext()) {
            Map.Entry<Integer, Element> row = rows.next();
            int i = row.getKey();

            // Line 3: tk1,i <- tk1,i ^ sk_c
            Element tk1i = row.getValue().duplicate().powZn(skc).getImmutable();
            T.tk1.put(i, tk1i);

            // Line 4: tk2,i <- tk2,i ^ sk_c
            Element issuedTk2i = tk2.get(i);
            if (issuedTk2i == null) {
                throw new IllegalArgumentException("Search token rows of tk1 and tk2 differ");
            }
            Element tk2i = issuedTk2i.duplicate().powZn(skc).getImmutable();
            T.tk2.put(i, tk2i);
        }

        // ------------------------------------------------------------
        // Line 5 (corrected): tk4 <- tk4 ^ (1 / H2(w))
        // ------------------------------------------------------------
        Element h2w = mpk.getHashFunctions().H2(w);
        Element inverseH = h2w.duplicate().invert();
        T.tk4 = tk4.duplicate().powZn(inverseH).getImmutable();

        // Correction component: tk7 <- tk7 ^ (-1 / H2(w))
        Element minusInverseH = inverseH.duplicate().negate();
        T.tk7 = TK.tk7.duplicate().powZn(minusInverseH).getImmutable();

        // tk3 (identity binding), tk5 and tk6 (Algorithm 11) are unchanged.
        T.tk3 = tk3;
        T.tk5 = TK.tk5;
        T.tk6 = TK.tk6;

        // ------------------------------------------------------------
        // Lines 6-7: T <- (...); return T
        // ------------------------------------------------------------
        return T;
    }
}
