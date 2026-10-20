import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

/**
 * Minos - Algorithm 8: Decrypt
 *
 * Input : secret key k (from KeyGen / Authorize), search result C (ct4)
 * Output: document identifiers ids
 *
 * ct4 = nonce(12 bytes) || AES-GCM(SHA-256(k), ids), Base64 encoded,
 * exactly as produced by Encrypt line 12.
 *
 * This is NOT the decryption of the document itself. The document has
 * its own key (see Encrypt.decryptDocument).
 */
public class Decrypt {

    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    public static List<String> decrypt(
            byte[] k,
            String ct4Base64) throws Exception {

        byte[] combined = Codec.unb64(ct4Base64);

        if (combined.length <= NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid ct4");
        }

        byte[] indexAesKey = MessageDigest
                .getInstance("SHA-256")
                .digest(k);

        byte[] nonce = Arrays.copyOfRange(
                combined, 0, NONCE_LENGTH);

        byte[] ciphertext = Arrays.copyOfRange(
                combined, NONCE_LENGTH, combined.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(indexAesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));

        // Line 1: ids <- Dec(k, C)
        String plaintext = new String(
                cipher.doFinal(ciphertext),
                StandardCharsets.UTF_8);

        List<String> ids = new ArrayList<>();

        for (String id : plaintext.split("\n")) {
            if (!id.isEmpty()) ids.add(id);
        }

        // Line 2: return ids
        return ids;
    }
}
