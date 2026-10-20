package minos.ext;

import it.unisa.dia.gas.jpbc.Element;
import minos.core.Codec;
import minos.core.Setup;

/**
 * PROJECT EXTENSION - Schnorr signature in the Minos group G (Fiat-Shamir,
 * the same construction the paper uses for the proof rho in Authorize,
 * Section III-D), keyed by a registered Minos key pair (pk = g^sk).
 *
 *   sign  : t <- Zp, R = g^t, c = H2(R, pk, m), s = t + c*sk  -> (R, s)
 *   verify: g^s == R * pk^c
 */
public final class SchnorrSignature {

    private SchnorrSignature() {
    }

    public static String[] sign(Setup.PublicParameters mpk, Element sk, Element pk, String message) {
        Element t = mpk.getPairing().getZr().newRandomElement().getImmutable();
        Element R = mpk.getG().duplicate().powZn(t).getImmutable();
        Element c = challenge(mpk, R, pk, message);
        Element s = t.duplicate().add(c.duplicate().mul(sk)).getImmutable();
        return new String[]{Codec.enc(R), Codec.enc(s)};
    }

    public static boolean verify(Setup.PublicParameters mpk, Element pk, String message, String Rb64, String sb64) {
        try {
            Element R = Codec.g1(mpk, Rb64);
            Element s = Codec.zr(mpk, sb64);
            Element c = challenge(mpk, R, pk, message);
            Element left = mpk.getG().duplicate().powZn(s);
            Element right = R.duplicate().mul(pk.duplicate().powZn(c));
            return left.isEqual(right);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Element challenge(Setup.PublicParameters mpk, Element R, Element pk, String m) {
        return mpk.getHashFunctions().H2("minos-sig|" + Codec.enc(R) + "|" + Codec.enc(pk) + "|" + m);
    }
}
