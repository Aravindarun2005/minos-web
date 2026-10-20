import it.unisa.dia.gas.jpbc.Element;

import java.security.SecureRandom;
import java.util.Map;

/**
 * Minos - Algorithm 6: TrapGen
 *
 * Input : mpk, keyword w, client private key sk_c, search token TK
 * Output: trapdoor T
 *
 * Every call also adds a fresh random nonce and a timestamp, so two
 * trapdoors for the same keyword are never identical. The CSP accepts
 * each trapdoor once and raises an alert if it is submitted again.
 */
public class TrapGen {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static class Trapdoor extends Authorize.Token {

        public String nonce;
        public long timestamp;

        @Override
        public Map<String, Object> toJson() {
            Map<String, Object> out = super.toJson();
            out.put("nonce", nonce);
            out.put("timestamp", timestamp);
            return out;
        }

        public static Trapdoor fromJson(
                Setup.PublicParameters mpk,
                Map<String, Object> json) {

            Trapdoor t = new Trapdoor();
            t.load(mpk, json);
            t.nonce = Codec.str(json, "nonce");
            t.timestamp = ((Number) json.get("timestamp")).longValue();
            return t;
        }
    }

    public static Trapdoor trapGen(
            Setup.PublicParameters mpk,
            String w,
            Element skc,
            Authorize.Token TK) {

        Trapdoor T = new Trapdoor();

        // Line 1: (tk1, tk2, tk3, tk4) <- TK
        // Lines 2-4: for each i in I
        for (Map.Entry<Integer, Element> e : TK.tk1.entrySet()) {

            int i = e.getKey();

            // Line 3: tk1,i <- tk1,i^(sk_c)
            T.tk1.put(i, e.getValue().duplicate()
                    .powZn(skc).getImmutable());

            // Line 4: tk2,i <- tk2,i^(sk_c)
            T.tk2.put(i, TK.tk2.get(i).duplicate()
                    .powZn(skc).getImmutable());
        }

        Element invH = mpk.getHashFunctions().H2(w)
                .duplicate().invert();

        // Line 5: PAPER: tk4 <- tk4^H2(w)
        //         FIX:   tk4 <- tk4^(1 / H2(w))
        // With ct3 = sk2^(s0*H2(w) + sk_o) only the inverse exponent
        // makes the s0 term cancel against Delta in Search.
        T.tk4 = TK.tk4.duplicate().powZn(invH).getImmutable();

        // Extra: tk7 <- tk7^(-1 / H2(w)) cancels the sk_o term of ct3.
        T.tk7 = TK.tk7.duplicate()
                .powZn(invH.duplicate().negate())
                .getImmutable();

        // tk3, tk5, tk6 are copied unchanged.
        T.tk3 = TK.tk3;
        T.tk5 = TK.tk5;
        T.tk6 = TK.tk6;

        // Extension: one-time-use nonce and timestamp.
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);

        T.nonce = Codec.b64(nonce);
        T.timestamp = System.currentTimeMillis();

        // Lines 6-7: T <- (...); return T
        return T;
    }
}
