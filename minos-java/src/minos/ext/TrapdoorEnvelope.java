package minos.ext;

import it.unisa.dia.gas.jpbc.Element;
import minos.common.CryptoUtil;
import minos.core.Setup;
import minos.core.TrapGen;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PROJECT EXTENSION - one-time trapdoor envelope (NOT part of the paper).
 *
 * Minos TrapGen (Algorithm 6) is deterministic in (TK, w, sk_c): searching
 * the same keyword twice yields the same cryptographic components. To make
 * every submitted trapdoor single-use and fresh WITHOUT modifying the Minos
 * algorithm, the unchanged Minos trapdoor T is wrapped in an envelope:
 *
 *   trapdoorId   random 128-bit id
 *   documentId   index the trapdoor was authorized for
 *   nonce        random 128-bit one-time authorization nonce
 *   issuedAt / expiresAt
 *   coreHash     SHA-256(canonical bytes of T)
 *   ownerSig     Schnorr signature by the data owner (sk_o) over all of
 *                the above, produced at the end of Authorize. The CSP
 *                verifies it with pk_o from the document metadata.
 *
 * Because the signature covers the nonce and the hash of T, an attacker
 * holding a leaked trapdoor can neither change the nonce (to evade replay
 * detection) nor alter T. The CSP accepts each trapdoorHash / nonce once.
 *
 * trapdoorHash = SHA-256(canonical(T) || envelope fields) is the reliable
 * identifier used for replay detection: it is computed from decoded group
 * elements, so JSON re-formatting does not change it.
 */
public final class TrapdoorEnvelope {

    private TrapdoorEnvelope() {
    }

    public static final long VALIDITY_MS = 10 * 60 * 1000L;

    public static Map<String, Object> issue(
            Setup.PublicParameters mpk,
            String documentId,
            TrapGen.Trapdoor T,
            Element sko,
            Element pko) {

        Map<String, Object> env = new LinkedHashMap<>();
        long now = System.currentTimeMillis();
        env.put("version", "minos-envelope/1");
        env.put("trapdoorId", "T-" + CryptoUtil.randomId(8));
        env.put("documentId", documentId);
        env.put("nonce", CryptoUtil.b64(CryptoUtil.random(16)));
        env.put("issuedAt", now);
        env.put("expiresAt", now + VALIDITY_MS);
        env.put("coreHash", CryptoUtil.sha256Hex(T.canonicalBytes()));
        String[] sig = SchnorrSignature.sign(mpk, sko, pko, signedMessage(env));
        env.put("ownerSigR", sig[0]);
        env.put("ownerSigS", sig[1]);
        env.put("trapdoor", T.toJson());
        return env;
    }

    public static String signedMessage(Map<String, Object> env) {
        return "minos-envelope/1"
                + "|" + env.get("trapdoorId")
                + "|" + env.get("documentId")
                + "|" + env.get("nonce")
                + "|" + num(env.get("issuedAt"))
                + "|" + num(env.get("expiresAt"))
                + "|" + env.get("coreHash");
    }

    /** Reliable trapdoor identifier (hex SHA-256). */
    public static String trapdoorHash(TrapGen.Trapdoor T, Map<String, Object> env) {
        return CryptoUtil.sha256Hex(T.canonicalBytes(),
                signedMessage(env).getBytes(StandardCharsets.UTF_8));
    }

    public static long num(Object o) {
        if (o instanceof Number) return ((Number) o).longValue();
        try {
            return Long.parseLong(String.valueOf(o));
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
