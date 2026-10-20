package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Hash functions of Minos Setup (Algorithm 1, line 2):
 *
 *   H1 : {0,1}* -> G     H2 : {0,1}* -> Zp
 *
 * The paper implements them with SHA-256 (Section VII-C).
 *
 * BUG FIX: the previous version passed the raw input to JPBC's
 * Element.setFromHash(). That method is NOT a hash function - it only uses
 * the first |p| bytes (20 bytes for Zp) of its input. Consequences were:
 *   - keywords sharing their first 20 characters had equal H2 values, so a
 *     trapdoor for one matched the other;
 *   - the Schnorr challenge c = H2(g, pk_c, g^tau) in Authorize was
 *     constant (its first 20 bytes are always enc(g)), which made the proof
 *     of private-key ownership forgeable.
 * Now the input is first hashed with SHA-256 under a domain-separation tag.
 */
public class HashFunctions {

    private final Pairing pairing;

    public HashFunctions(Pairing pairing) {
        if (pairing == null) {
            throw new IllegalArgumentException("Pairing cannot be null");
        }
        this.pairing = pairing;
    }

    /** H1 : {0,1}* -> G   (hash-to-curve on the SHA-256 digest). */
    public Element H1(String attribute) {
        if (attribute == null || attribute.isEmpty()) {
            throw new IllegalArgumentException("Attribute cannot be empty");
        }
        byte[] digest = sha256("MINOS-H1", attribute);
        Element result = pairing.getG1().newElement();
        result.setFromHash(digest, 0, digest.length);
        return result.getImmutable();
    }

    /** H2 : {0,1}* -> Zp   (SHA-256 digest reduced mod p). */
    public Element H2(String message) {
        if (message == null) {
            throw new IllegalArgumentException("Hash input cannot be null");
        }
        BigInteger value = new BigInteger(1, sha256("MINOS-H2", message))
                .mod(pairing.getZr().getOrder());
        Element result = pairing.getZr().newElement();
        result.set(value);
        return result.getImmutable();
    }

    private static byte[] sha256(String domain, String message) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            d.update(domain.getBytes(StandardCharsets.UTF_8));
            d.update((byte) 0);
            d.update(message.getBytes(StandardCharsets.UTF_8));
            return d.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
