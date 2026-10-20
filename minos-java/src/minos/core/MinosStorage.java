package minos.core;


import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class MinosStorage {

    private static final int MAGIC = 0x4D494E4F;
    private static final int VERSION = 1;
    private static final int MAX_STRING_LENGTH = 1000000;
    private static final int MAX_ELEMENT_LENGTH = 1000000;
    private static final int MAX_ATTRIBUTES = 10000;

    public static void save(
            Path file,
            Setup.PublicParameters mpk)
            throws IOException {

        Path parent = file.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path temporary = file.resolveSibling(
                file.getFileName().toString() + ".tmp");

        try (DataOutputStream out =
                     new DataOutputStream(
                             new BufferedOutputStream(
                                     Files.newOutputStream(temporary)))) {

            out.writeInt(MAGIC);
            out.writeInt(VERSION);
            out.writeInt(mpk.getLambda());

            writeString(
                    out,
                    mpk.getPairingParameters().toString());

            writeBytes(
                    out,
                    mpk.getG().toBytes());

            Set<String> attributes =
                    mpk.getAttributes();

            out.writeInt(attributes.size());

            for (String attribute : attributes) {

                writeString(out, attribute);

                Element element =
                        mpk.getAttributeElement(attribute);

                writeBytes(
                        out,
                        element.toBytes());
            }
        }

        try {
            Files.move(
                    temporary,
                    file,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(
                    temporary,
                    file,
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    public static Setup.PublicParameters load(Path file)
            throws IOException {

        if (!Files.exists(file)) {
            throw new IOException(
                    "Minos setup file does not exist");
        }

        try (DataInputStream in =
                     new DataInputStream(
                             new BufferedInputStream(
                                     Files.newInputStream(file)))) {

            int magic = in.readInt();

            if (magic != MAGIC) {
                throw new IOException(
                        "Invalid Minos setup file");
            }

            int version = in.readInt();

            if (version != VERSION) {
                throw new IOException(
                        "Unsupported setup file version");
            }

            int lambda = in.readInt();

            String parameterText = readString(in);

            PropertiesParameters parameters =
                    new PropertiesParameters();

            parameters.load(
                    new ByteArrayInputStream(
                            parameterText.getBytes(
                                    StandardCharsets.UTF_8)));

            PairingParameters pairingParameters =
                    parameters;

            Pairing pairing =
                    PairingFactory.getPairing(
                            pairingParameters);

            byte[] generatorBytes = readBytes(in);

            Element g =
                    pairing.getG1()
                            .newElementFromBytes(generatorBytes)
                            .getImmutable();

            int count = in.readInt();

            if (count < 1 || count > MAX_ATTRIBUTES) {
                throw new IOException(
                        "Invalid attribute count");
            }

            Set<String> attributes =
                    new LinkedHashSet<>();

            Map<String, Element> U =
                    new LinkedHashMap<>();

            for (int i = 0; i < count; i++) {

                String attribute = readString(in);

                byte[] elementBytes = readBytes(in);

                Element element =
                        pairing.getG1()
                                .newElementFromBytes(elementBytes)
                                .getImmutable();

                if (!attributes.add(attribute)) {
                    throw new IOException(
                            "Duplicate attribute in setup file");
                }

                U.put(attribute, element);
            }

            if (in.read() != -1) {
                throw new IOException(
                        "Unexpected data in setup file");
            }

            HashFunctions hashFunctions =
                    new HashFunctions(pairing);

            return new Setup.PublicParameters(
                    lambda,
                    pairingParameters,
                    pairing,
                    pairing.getG1().getOrder(),
                    g,
                    hashFunctions,
                    attributes,
                    U);
        }
    }

    private static void writeString(
            DataOutputStream out,
            String value) throws IOException {

        writeBytes(
                out,
                value.getBytes(StandardCharsets.UTF_8));
    }

    private static String readString(
            DataInputStream in) throws IOException {

        return new String(
                readBytes(in),
                StandardCharsets.UTF_8);
    }

    private static void writeBytes(
            DataOutputStream out,
            byte[] value) throws IOException {

        out.writeInt(value.length);
        out.write(value);
    }

    private static byte[] readBytes(
            DataInputStream in) throws IOException {

        int length = in.readInt();

        if (length < 0 ||
                length > MAX_ELEMENT_LENGTH) {
            throw new IOException(
                    "Invalid data length");
        }

        byte[] value = new byte[length];

        in.readFully(value);

        return value;
    }
}