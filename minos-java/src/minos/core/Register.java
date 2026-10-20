package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Minos - Algorithm 2: User Registration (Register)
 *
 * <pre>
 *   Input : mpk, registration list R
 *   Output: pk, sk, R
 *
 *   User side
 *     1: beta <- Zp
 *     2: pk   <- g^beta
 *     3: sk   <- beta
 *     4: send pk to the CSP
 *   CSP side
 *     5: R.add(pk)
 *     6: return pk, sk, R
 * </pre>
 *
 * register() runs every line and returns the list R the CSP holds after
 * line 5. In the running system the CSP Server performs line 5 on its own
 * persistent registration list (folder public-keys/).
 */
public class Register {

    /** The three outputs of Algorithm 2. */
    public static class RegistrationResult {

        /** pk = g^beta, the public identity of the user. */
        public final Element pk;

        /** sk = beta, the private key of the user. */
        public final Element sk;

        /** R after line 5: every registered public key, Base64 encoded. */
        public final Set<String> R;

        public RegistrationResult(Element pk, Element sk, Set<String> R) {
            this.pk = pk;
            this.sk = sk;
            this.R = R;
        }
    }

    public static RegistrationResult register(Setup.PublicParameters mpk, Set<String> R) {

        // ------------------------------------------------------------
        // Input checks
        // ------------------------------------------------------------
        if (mpk == null) {
            throw new IllegalArgumentException("Public parameters mpk are required");
        }
        if (R == null) {
            throw new IllegalArgumentException("Registration list R is required");
        }

        Pairing pairing = mpk.getPairing();
        Field Zp = pairing.getZr();
        Element g = mpk.getG();

        // ------------------------------------------------------------
        // Line 1: beta <- Zp
        //   A zero beta would give pk = 1 (the identity element), which
        //   is not a usable identity, so a new value is drawn.
        // ------------------------------------------------------------
        Element beta = Zp.newRandomElement();
        while (beta.isZero()) {
            beta = Zp.newRandomElement();
        }
        beta = beta.getImmutable();

        // ------------------------------------------------------------
        // Line 2: pk <- g^beta
        // ------------------------------------------------------------
        Element gCopy = g.duplicate();
        Element pkValue = gCopy.powZn(beta);
        Element pk = pkValue.getImmutable();

        // ------------------------------------------------------------
        // Line 3: sk <- beta
        // ------------------------------------------------------------
        Element sk = beta;

        // ------------------------------------------------------------
        // Line 4: send pk to the CSP
        //   pk travels as Base64(pk.toBytes()).
        // ------------------------------------------------------------
        String pkForCsp = Codec.enc(pk);

        // ------------------------------------------------------------
        // Line 5: R.add(pk)   (CSP side)
        //   R is copied element by element so the caller's list is not
        //   changed, then pk is added if it is not already present.
        // ------------------------------------------------------------
        Set<String> updatedR = new LinkedHashSet<>();
        Iterator<String> existing = R.iterator();
        while (existing.hasNext()) {
            String registeredKey = existing.next();
            updatedR.add(registeredKey);
        }
        boolean alreadyRegistered = false;
        Iterator<String> check = updatedR.iterator();
        while (check.hasNext()) {
            if (check.next().equals(pkForCsp)) {
                alreadyRegistered = true;
            }
        }
        if (!alreadyRegistered) {
            updatedR.add(pkForCsp);
        }

        // ------------------------------------------------------------
        // Line 6: return pk, sk, R
        // ------------------------------------------------------------
        return new RegistrationResult(pk, sk, updatedR);
    }
}
