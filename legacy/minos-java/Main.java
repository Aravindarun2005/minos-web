
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import it.unisa.dia.gas.jpbc.Element;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

public class Main {

    private static String b64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static String json(String value) {
        if (value == null) return "null";

        return "\"" + value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r") + "\"";
    }

    public static void main(String[] args) {
        try {
            if (args.length < 2) {
                throw new IllegalArgumentException(
                    "Usage: Main setup|load|register|keygen|encrypt|authorize-proof|authorize|trapgen|search|decrypt|detect|trace-help|trace|decrypt-document <file> [args]"
                );
            }

            String command = args[0];
            Path file = Paths.get(args[1]).toAbsolutePath();

            switch (command) {

                case "setup": {
                    if (args.length < 3) {
                        throw new IllegalArgumentException(
                            "Supply at least one attribute"
                        );
                    }

                    Set<String> attributes = new LinkedHashSet<>();

                    for (int i = 2; i < args.length; i++) {
                        attributes.add(args[i]);
                    }

                    Setup.PublicParameters mpk =
                        Setup.runSetup(attributes, file);

                    System.out.println(Setup.toJson(mpk));
                    break;
                }

                case "load": {
                    Setup.PublicParameters mpk =
                        Setup.loadSetup(file);

                    System.out.println(Setup.toJson(mpk));
                    break;
                }

                case "register": {
                    if (args.length < 3) {
                        throw new IllegalArgumentException(
                            "Usage: register <file> <username>"
                        );
                    }

                    String username = args[2];

                    Setup.PublicParameters mpk =
                        Setup.loadSetup(file);

                    Set<String> registrationSet =
                        new LinkedHashSet<>();

                    Register.RegistrationResult result =
                        Register.register(mpk, registrationSet);

                    boolean valid = mpk.getG()
                        .duplicate()
                        .powZn(result.sk)
                        .isEqual(result.pk);

                    if (!valid) {
                        throw new IllegalStateException(
                            "Registration public key verification failed"
                        );
                    }

                    System.out.println(
                        "{"
                        + "\"success\":true,"
                        + "\"username\":" + json(username) + ","
                        + "\"publicKey\":" + json(b64(result.pk.toBytes())) + ","
                        + "\"privateKey\":" + json(b64(result.sk.toBytes())) + ","
                        + "\"verified\":true"
                        + "}"
                    );

                    break;
                }

                case "keygen": {

                    Setup.PublicParameters mpk =
                        Setup.loadSetup(file);

                    Set<String> selected = new LinkedHashSet<>();

                    for (int i = 2; i < args.length; i++) {
                        selected.add(args[i]);
                    }

                    // Matrix dimensions
                    // n1 = number of rows
                    // n2 = number of columns
                    int n1 = selected.size();
                    int n2 = 2;

                    // Execute Algorithm 3: KeyGen
                    KeyGen.K keys =
                        KeyGen.keyGen(mpk, selected, n1, n2);

                    StringBuilder out = new StringBuilder();

                    out.append("{\"success\":true");

                    // Serialize sk1
                    out.append(",\"sk1\":{");

                    boolean first = true;

                    for (String attribute : keys.sk1.keySet()) {

                        if (!first) {
                            out.append(",");
                        }

                        first = false;

                        out.append(json(attribute))
                           .append(":")
                           .append(json(
                               b64(keys.sk1.get(attribute).toBytes())
                           ));
                    }

                    out.append("}");

                    // Serialize sk2
                    out.append(",\"sk2\":")
                       .append(json(b64(keys.sk2.toBytes())));

                    // Serialize symmetric key k
                    out.append(",\"k\":")
                       .append(json(b64(keys.k)));

                    // Serialize matrix M
                    out.append(",\"M\":[");

                    for (int i = 0; i < keys.M.length; i++) {

                        if (i > 0) {
                            out.append(",");
                        }

                        out.append("[");

                        for (int j = 0; j < keys.M[i].length; j++) {

                            if (j > 0) {
                                out.append(",");
                            }

                            out.append(json(
                                b64(keys.M[i][j].toBytes())
                            ));
                        }

                        out.append("]");
                    }

                    out.append("]");

                    // Serialize pi: row-to-attribute mapping
                    out.append(",\"pi\":[");

                    for (int i = 0; i < keys.pi.length; i++) {

                        if (i > 0) {
                            out.append(",");
                        }

                        out.append(json(keys.pi[i]));
                    }

                    out.append("]");

                    // Serialize selected attributes
                    out.append(",\"attributes\":[");

                    first = true;

                    for (String attribute : selected) {

                        if (!first) {
                            out.append(",");
                        }

                        first = false;

                        out.append(json(attribute));
                    }

                    out.append("]}");

                    System.out.println(out);

                    break;
                }


                case "encrypt": {
                    // encrypt <setupFile> <ownerSkB64> <ownerPkB64>
                    //         <documentId> <documentPath> <commaKeywords>
                    //         <commaAttributes> <ownerKeyDirectory>
                    if (args.length < 9) {
                        throw new IllegalArgumentException(
                            "Usage: encrypt <setupFile> <ownerSkB64> <ownerPkB64> <documentId> <documentPath> <keywordsCSV> <attributesCSV> <ownerKeyDirectory>"
                        );
                    }

                    Setup.PublicParameters mpk = Setup.loadSetup(file);
                    String ownerSkB64 = args[2];
                    String ownerPkB64 = args[3];
                    String documentId = args[4];
                    Path documentPath = Paths.get(args[5]).toAbsolutePath();
                    String keywordsCSV = args[6];
                    String attributesCSV = args[7];
                    Path ownerKeyDirectory = Paths.get(args[8]).toAbsolutePath();

                    Element ownerSk = mpk.getPairing().getZr()
                        .newElementFromBytes(Base64.getDecoder().decode(ownerSkB64))
                        .getImmutable();

                    Element ownerPk = mpk.getG().getField()
                        .newElementFromBytes(Base64.getDecoder().decode(ownerPkB64))
                        .getImmutable();

                    Set<String> selected = new LinkedHashSet<>();
                    for (String a : attributesCSV.split(",")) {
                        if (!a.trim().isEmpty()) selected.add(a.trim());
                    }
                    if (selected.isEmpty()) {
                        throw new IllegalArgumentException("At least one attribute is required");
                    }

                    Set<String> keywordSet = new LinkedHashSet<>();
                    for (String w : keywordsCSV.split(",")) {
                        if (!w.trim().isEmpty()) keywordSet.add(w.trim().toLowerCase());
                    }
                    if (keywordSet.isEmpty()) {
                        throw new IllegalArgumentException("At least one keyword is required");
                    }

                    KeyGen.K keys = KeyGen.keyGen(mpk, selected, selected.size(), 2);

                    Map<String, List<String>> phi = new LinkedHashMap<>();
                    for (String keyword : keywordSet) {
                        phi.put(keyword, Collections.singletonList(documentId));
                    }

                    byte[] documentBytes = Files.readAllBytes(documentPath);
                    Encrypt.Result encrypted = Encrypt.encrypt(
                        mpk, phi, ownerSk, ownerPk, keys, documentId, documentBytes
                    );

                    Encrypt.saveOwnerDocumentKey(
                        ownerKeyDirectory, documentId, encrypted.ownerDocumentKeyBase64
                    );

                    StringBuilder out = new StringBuilder();
                    out.append("{\"success\":true");
                    out.append(",\"documentId\":").append(json(documentId));
                    out.append(",\"encryptedDocumentBase64\":")
                       .append(json(encrypted.encryptedDocumentBase64));
                    out.append(",\"documentNonceBase64\":")
                       .append(json(encrypted.documentNonceBase64));
                    out.append(",\"ownerDocumentKeySaved\":true");
                    out.append(",\"cspPayload\":").append(encrypted.toCspJson());
                    out.append(",\"indexKeyBase64\":")
                       .append(json(b64(keys.k)));
                    // K stays on the owner side. It is needed later
                    // by Authorize, Detect and Trace for this document.
                    out.append(",\"keys\":")
                       .append(Json.write(Codec.kToJson(keys)));
                    out.append("}");
                    System.out.println(out);
                    break;
                }

                default: {
                    // Algorithms 5-11 and document decryption.
                    // usage: Main <command> <setupFile> <inputJsonFile>
                    if (args.length < 3) {
                        throw new IllegalArgumentException(
                            "Unknown command: " + command
                        );
                    }

                    Setup.PublicParameters mpk =
                        Setup.loadSetup(file);

                    Map<String, Object> input = Codec.map(
                        Json.parse(
                            Files.readString(
                                Paths.get(args[2]),
                                StandardCharsets.UTF_8)));

                    System.out.println(
                        Json.write(
                            MinosCli.run(command, mpk, input)));

                    break;
                }
            }

        } catch (Exception e) {
            System.err.println(
                "Minos error: " + e.getMessage()
            );

            System.exit(1);
        }
    }
}