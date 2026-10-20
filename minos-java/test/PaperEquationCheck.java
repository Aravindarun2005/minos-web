import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import minos.core.*;
import minos.ext.*;

import java.util.*;

/**
 * Offline check of the Minos core (no servers needed).
 *
 * Part A shows numerically that two equations exactly as printed in the paper
 * do not hold, which is why the implementation uses corrected forms:
 *   - Algorithm 7 line 5:   e(tk3 * tk4, ct3) * Delta == 1   with tk4 = pkc^(sko * H2(w))
 *   - Algorithm 10 line 4:  t1 == t2  with t1 = e(ct3, pko^(H2(w)+sko))
 *
 * Part B runs all ten algorithms through the project's classes and checks
 * correctness, plus the one-time-envelope and AES-GCM extensions.
 *
 * Run: java -cp "build:lib/*:test-build" PaperEquationCheck
 */
public class PaperEquationCheck {

    static int failures = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + what);
        if (!ok) failures++;
    }

    public static void main(String[] args) throws Exception {
        Setup.PublicParameters mpk = Setup.setup(160,
                new LinkedHashSet<>(List.of("HR", "Manager", "Employee", "Finance", "Admin")));
        Pairing pr = mpk.getPairing();
        Register.RegistrationResult o = Register.register(mpk, new HashSet<>());
        Register.RegistrationResult c = Register.register(mpk, new HashSet<>());
        Register.RegistrationResult x = Register.register(mpk, new HashSet<>());

        KeyGen.K K = KeyGen.keyGen(mpk).withAccessStructure(AccessPolicy.parse(mpk, "HR OR Manager"));
        Map<String, List<String>> phi = new LinkedHashMap<>();
        phi.put("salary", List.of("D1"));
        phi.put("bonus", List.of("D1"));
        List<Encrypt.Entry> entries = Encrypt.encrypt(mpk, phi, o.sk, o.pk, K);
        List<Map<String, Object>> L = Encrypt.toJson(entries);
        Set<String> R = new HashSet<>(Set.of(Codec.enc(c.pk), Codec.enc(o.pk)));

        Authorize.Token TK = Authorize.ownerAuthorize(mpk, R, c.pk,
                Authorize.clientProof(mpk, c.pk, c.sk), Set.of("HR"), K, o.sk);
        TrapGen.Trapdoor T = TrapGen.trapGen(mpk, "salary", c.sk, TK);
        Element H = mpk.getHashFunctions().H2("salary");

        // ---------------- Part A: printed equations ----------------
        System.out.println("\n== A. Equations as printed in the paper");
        Element delta = pr.getGT().newOneElement();
        List<Element> ct3s = new ArrayList<>();
        for (Encrypt.Entry e : entries) {
            if ("attribute".equals(e.type) && T.tk1.containsKey(e.row)) {
                Element ct1 = Codec.g1(mpk, e.ct1), ct2 = Codec.g1(mpk, e.ct2);
                delta.mul(pr.pairing(T.tk1.get(e.row), ct1).div(pr.pairing(ct2, T.tk2.get(e.row))));
            }
            if ("keyword".equals(e.type)) ct3s.add(Codec.g1(mpk, e.ct3));
        }
        Element tk4Printed = c.pk.duplicate().powZn(o.sk).powZn(H);
        boolean printedSearch = false;
        for (Element ct3 : ct3s) printedSearch |= pr.pairing(T.tk3.duplicate().mul(tk4Printed), ct3).mul(delta.duplicate()).isOne();
        check("printed Alg. 7 check e(tk3*tk4, ct3)*Delta == 1 holds for NO keyword entry", !printedSearch);
        Element t2 = pr.getGT().newOneElement();
        for (Encrypt.Entry e : entries) {
            if ("attribute".equals(e.type) && "HR".equals(K.pi[e.row])) {
                t2.mul(pr.pairing(Codec.g1(mpk, e.ct2), K.sk2).div(pr.pairing(Codec.g1(mpk, e.ct1), K.sk1.get("HR"))));
            }
        }
        boolean printedTrace = false;
        for (Element ct3 : ct3s) printedTrace |= pr.pairing(ct3, o.pk.duplicate().powZn(H.duplicate().add(o.sk))).isEqual(t2);
        check("printed Alg. 10 check t1 == t2 fails even for the real owner", !printedTrace);

        // ---------------- Part B: implementation ----------------
        System.out.println("\n== B. Implemented algorithms (corrected forms)");
        check("Search finds 'salary'", Search.search(mpk, L, T).size() == 1);
        check("Search: other keyword no match",
                Search.search(mpk, L, TrapGen.trapGen(mpk, "nothere", c.sk, TK)).isEmpty());
        check("Search: long keywords with same prefix differ (hash fix)",
                Search.search(mpk, L, TrapGen.trapGen(mpk, "salary-and-a-very-long-suffix-xxxxxxxx", c.sk, TK)).isEmpty());
        check("tk5 consistency", Search.verifyTk5(mpk, T));
        check("Decrypt returns D1", Decrypt.decrypt(K.k, Search.search(mpk, L, T).get(0)).equals(List.of("D1")));
        check("Detect (Alg. 9) recovers pkc", Detect.detect(T.tk3, o.sk).isEqual(c.pk));
        check("Detect (Alg. 11) recovers pkc and verifies the trapdoor",
                Detect.detectEnhanced(mpk, T, o.sk, K, List.of("bonus", "salary")).pkc.isEqual(c.pk));
        check("Trace: real owner -> true", Trace.trace(mpk, L, Trace.help(mpk, "salary", o.sk, o.pk, K)));
        check("Trace: other user -> false", !Trace.trace(mpk, L, Trace.help(mpk, "salary", x.sk, x.pk, K)));

        boolean denied;
        try {
            Authorize.ownerAuthorize(mpk, R, c.pk, Authorize.clientProof(mpk, c.pk, c.sk), Set.of("Employee"), K, o.sk);
            denied = false;
        } catch (Exception e) { denied = true; }
        check("Authorize refuses attributes that do not satisfy (M, pi)", denied);
        try {
            Authorize.ownerAuthorize(mpk, R, x.pk, Authorize.clientProof(mpk, x.pk, x.sk), Set.of("HR"), K, o.sk);
            denied = false;
        } catch (Exception e) { denied = true; }
        check("Authorize refuses an identity not in R", denied);
        try {
            Authorize.ownerAuthorize(mpk, R, c.pk, Authorize.clientProof(mpk, c.pk, x.sk), Set.of("HR"), K, o.sk);
            denied = false;
        } catch (Exception e) { denied = true; }
        check("Authorize refuses a proof made with the wrong secret key", denied);

        KeyGen.K K2 = KeyGen.keyGen(mpk).withAccessStructure(AccessPolicy.parse(mpk, "(Finance AND Manager) OR Admin"));
        List<Map<String, Object>> L2 = Encrypt.toJson(Encrypt.encrypt(mpk, Map.of("board", List.of("D2")), o.sk, o.pk, K2));
        for (Set<String> S : List.of(Set.of("Finance", "Manager"), Set.of("Admin"))) {
            Authorize.Token tk = Authorize.ownerAuthorize(mpk, R, c.pk, Authorize.clientProof(mpk, c.pk, c.sk), S, K2, o.sk);
            check("AND/OR policy satisfied by " + S, Search.search(mpk, L2, TrapGen.trapGen(mpk, "board", c.sk, tk)).size() == 1);
        }
        try {
            Authorize.ownerAuthorize(mpk, R, c.pk, Authorize.clientProof(mpk, c.pk, c.sk), Set.of("Finance"), K2, o.sk);
            denied = false;
        } catch (Exception e) { denied = true; }
        check("AND/OR policy not satisfied by [Finance]", denied);

        System.out.println("\n== C. Project extensions");
        Map<String, Object> env = TrapdoorEnvelope.issue(mpk, "D1", T, o.sk, o.pk);
        check("envelope signature verifies", SchnorrSignature.verify(mpk, o.pk, TrapdoorEnvelope.signedMessage(env),
                (String) env.get("ownerSigR"), (String) env.get("ownerSigS")));
        Map<String, Object> env2 = TrapdoorEnvelope.issue(mpk, "D1", T, o.sk, o.pk);
        check("same trapdoor, new envelope -> different nonce", !env.get("nonce").equals(env2.get("nonce")));
        env.put("nonce", "AAAAAAAAAAAAAAAAAAAAAA==");
        check("tampered nonce breaks the signature", !SchnorrSignature.verify(mpk, o.pk, TrapdoorEnvelope.signedMessage(env),
                (String) env.get("ownerSigR"), (String) env.get("ownerSigS")));
        DocumentCrypto.Encrypted d = DocumentCrypto.encrypt("secret body".getBytes(), "D1", K.k);
        check("AES-GCM body decrypts with k", new String(DocumentCrypto.decrypt(
                DocumentCrypto.unwrapFileKey(K.k, "D1", d.wrappedFileKey), "D1", d.sealedDocument)).equals("secret body"));
        try {
            DocumentCrypto.unwrapFileKey(KeyGen.keyGen(mpk).k, "D1", d.wrappedFileKey);
            denied = false;
        } catch (Exception e) { denied = true; }
        check("file key cannot be unwrapped with a different k", denied);

        System.out.println(failures == 0 ? "\nALL CHECKS PASSED" : "\n" + failures + " CHECK(S) FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }
}
