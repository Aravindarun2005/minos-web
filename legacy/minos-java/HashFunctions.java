
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.nio.charset.StandardCharsets;

public class HashFunctions {

    private final Pairing pairing;

    public HashFunctions(Pairing pairing) {
        if (pairing == null) {
            throw new IllegalArgumentException(
                    "Pairing cannot be null");
        }

        this.pairing = pairing;
    }

    public Element H1(String attribute) {

        if (attribute == null || attribute.isEmpty()) {
            throw new IllegalArgumentException(
                    "Attribute cannot be empty");
        }

        byte[] input =
                attribute.getBytes(StandardCharsets.UTF_8);

        Field<?> group = pairing.getG1();

        Element result = group.newElement();

        result.setFromHash(
                input,
                0,
                input.length);

        return result.getImmutable();
    }

    public Element H2(String message) {

        if (message == null) {
            throw new IllegalArgumentException(
                    "Hash input cannot be null");
        }

        byte[] input =
                message.getBytes(StandardCharsets.UTF_8);

        Field<?> scalarField = pairing.getZr();

        Element result = scalarField.newElement();

        result.setFromHash(
                input,
                0,
                input.length);

        return result.getImmutable();
    }
}