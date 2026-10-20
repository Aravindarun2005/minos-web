import it.unisa.dia.gas.jpbc.Element;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * JSON command layer for Algorithms 5-11.
 *
 * Main passes: command, loaded mpk, and the parsed JSON input file.
 * Every command returns a JSON object that Main prints.
 */
public class MinosCli {

    public static Map<String, Object> run(
            String command,
            Setup.PublicParameters mpk,
            Map<String, Object> in) throws Exception {

        Map<String, Object> out = new LinkedHashMap<>();

        out.put("success", true);

        switch (command) {

            // Algorithm 5, client side
            case "authorize-proof": {

                Element pkc = Codec.g1(mpk, Codec.str(in, "publicKey"));
                Element skc = Codec.zr(mpk, Codec.str(in, "privateKey"));

                out.put("proof",
                        Authorize.clientProof(mpk, pkc, skc).toJson());

                return out;
            }

            // Algorithm 5, data-owner side
            case "authorize": {

                Set<String> R = new LinkedHashSet<>();

                for (Object key : Codec.list(in.get("registeredKeys"))) {
                    R.add((String) key);
                }

                Set<String> Sc = new LinkedHashSet<>();

                for (Object a : Codec.list(in.get("attributes"))) {
                    Sc.add((String) a);
                }

                KeyGen.K K = Codec.kFromJson(mpk, Codec.map(in.get("keys")));

                Authorize.Token TK = Authorize.ownerAuthorize(
                        mpk,
                        R,
                        Codec.g1(mpk, Codec.str(in, "publicKey")),
                        Authorize.Proof.fromJson(mpk, Codec.map(in.get("proof"))),
                        Sc,
                        K,
                        Codec.zr(mpk, Codec.str(in, "ownerPrivateKey")));

                out.put("token", TK.toJson());
                out.put("indexKey", Codec.b64(K.k));

                return out;
            }

            // Algorithm 6
            case "trapgen": {

                Authorize.Token TK = Authorize.Token.fromJson(
                        mpk, Codec.map(in.get("token")));

                TrapGen.Trapdoor T = TrapGen.trapGen(
                        mpk,
                        Codec.str(in, "keyword"),
                        Codec.zr(mpk, Codec.str(in, "privateKey")),
                        TK);

                out.put("trapdoor", T.toJson());

                return out;
            }

            // Algorithm 7
            case "search": {

                List<Map<String, Object>> L = new ArrayList<>();

                for (Object e : Codec.list(in.get("entries"))) {
                    L.add(Codec.map(e));
                }

                TrapGen.Trapdoor T = TrapGen.Trapdoor.fromJson(
                        mpk, Codec.map(in.get("trapdoor")));

                out.put("matches", Search.search(mpk, L, T));

                return out;
            }

            // Algorithm 8
            case "decrypt": {

                byte[] k = Codec.unb64(Codec.str(in, "indexKey"));

                List<String> ids = new ArrayList<>();

                for (Object c : Codec.list(in.get("ciphertexts"))) {
                    ids.addAll(Decrypt.decrypt(k, (String) c));
                }

                out.put("ids", ids);

                return out;
            }

            // Algorithms 9 and 11
            case "detect": {

                Element sko = Codec.zr(mpk, Codec.str(in, "ownerPrivateKey"));

                TrapGen.Trapdoor T = TrapGen.Trapdoor.fromJson(
                        mpk, Codec.map(in.get("trapdoor")));

                // Algorithm 9
                out.put("publicKey",
                        Codec.enc(Detect.detect(T.tk3, sko)));

                // Algorithm 11
                KeyGen.K K = Codec.kFromJson(mpk, Codec.map(in.get("keys")));

                List<String> W = new ArrayList<>();

                for (Object w : Codec.list(in.get("keywords"))) {
                    W.add((String) w);
                }

                try {

                    Detect.Result r =
                            Detect.detectEnhanced(mpk, T, sko, K, W);

                    out.put("verified", true);
                    out.put("keyword", r.keyword);

                } catch (IllegalStateException e) {

                    out.put("verified", false);
                    out.put("error", e.getMessage());
                }

                return out;
            }

            // Algorithm 10, owner side
            case "trace-help": {

                Trace.HelpData hp = Trace.help(
                        mpk,
                        Codec.str(in, "keyword"),
                        Codec.zr(mpk, Codec.str(in, "ownerPrivateKey")),
                        Codec.g1(mpk, Codec.str(in, "ownerPublicKey")),
                        Codec.kFromJson(mpk, Codec.map(in.get("keys"))));

                out.put("helpData", hp.toJson());

                return out;
            }

            // Algorithm 10, CSP side
            case "trace": {

                List<Map<String, Object>> L = new ArrayList<>();

                for (Object e : Codec.list(in.get("entries"))) {
                    L.add(Codec.map(e));
                }

                out.put("valid", Trace.trace(
                        mpk,
                        L,
                        Trace.HelpData.fromJson(
                                mpk, Codec.map(in.get("helpData")))));

                return out;
            }

            // Application: decrypt the document itself
            case "decrypt-document": {

                byte[] encrypted = Files.readAllBytes(
                        Paths.get(Codec.str(in, "encryptedFile")));

                byte[] plain = Encrypt.decryptDocument(
                        Codec.str(in, "documentKeyBase64"),
                        Codec.str(in, "nonceBase64"),
                        Codec.b64(encrypted));

                Files.write(
                        Paths.get(Codec.str(in, "outputFile")),
                        plain);

                out.put("bytes", plain.length);

                return out;
            }

            default:
                throw new IllegalArgumentException(
                        "Unknown command: " + command);
        }
    }
}
