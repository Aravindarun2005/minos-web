import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.LinkedHashSet;
import java.util.Set;

public class Register {

    public static class RegistrationResult {

        public final Element pk;
        public final Element sk;
        public final Set<String> R;

        public RegistrationResult(
                Element pk,
                Element sk,
                Set<String> R) {

            this.pk = pk;
            this.sk = sk;
            this.R = R;
        }
    }

    public static RegistrationResult register(
            Setup.PublicParameters mpk,
            Set<String> R) {

        Pairing pairing = mpk.getPairing();

        Element beta =
                pairing.getZr()
                        .newRandomElement()
                        .getImmutable();

        Element pk =
                mpk.getG()
                        .duplicate()
                        .powZn(beta)
                        .getImmutable();

        Element sk = beta;

        Set<String> updatedR =
                new LinkedHashSet<>(R);

        updatedR.add(
                java.util.Base64.getEncoder()
                        .encodeToString(pk.toBytes()));

        return new RegistrationResult(
                pk,
                sk,
                updatedR);
    }
}