package minos.core;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Minos - Algorithm 8: Decrypt
 *
 * <pre>
 *   Input : secret key k (released by Authorize), search result C (ct4)
 *   Output: document identifiers ids
 *
 *   1: ids <- Dec(k, C)
 *   2: return ids
 * </pre>
 *
 * ct4 = nonce (12 bytes) || AES-GCM(SHA-256(k), ids), Base64 encoded,
 * exactly as produced by Encrypt line 12.
 *
 * This decrypts the search result, not the file itself. The file has its
 * own key (project extension, minos.ext.DocumentCrypto).
 */
public class Decrypt {

    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    public static List<String> decrypt(byte[] k, String ct4Base64) throws Exception {

        // ------------------------------------------------------------
        // Input checks
        // ------------------------------------------------------------
        if (k == null || k.length == 0) {
            throw new IllegalArgumentException("The secret key k is required");
        }
        if (ct4Base64 == null || ct4Base64.isEmpty()) {
            throw new IllegalArgumentException("The search result C is empty");
        }

        // ------------------------------------------------------------
        // Split C into nonce and ciphertext, byte by byte
        // ------------------------------------------------------------
        byte[] combined = Codec.unb64(ct4Base64);
        if (combined.length <= NONCE_LENGTH) {
            throw new IllegalArgumentException("Invalid ct4");
        }
        byte[] nonce = new byte[NONCE_LENGTH];
        for (int i = 0; i < NONCE_LENGTH; i++) {
            nonce[i] = combined[i];
        }
        byte[] ciphertext = new byte[combined.length - NONCE_LENGTH];
        for (int i = 0; i < ciphertext.length; i++) {
            ciphertext[i] = combined[NONCE_LENGTH + i];
        }

        // ------------------------------------------------------------
        // Line 1: ids <- Dec(k, C)      (AES-GCM with key SHA-256(k))
        // ------------------------------------------------------------
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] indexAesKey = sha256.digest(k);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(indexAesKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, nonce));
        byte[] plain = cipher.doFinal(ciphertext);
        String text = new String(plain, StandardCharsets.UTF_8);

        // The identifiers are stored one per line; read them character by character.
        List<String> ids = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch == '\n') {
                if (current.length() > 0) {
                    ids.add(current.toString());
                }
                current = new StringBuilder();
            } else {
                current.append(ch);
            }
        }
        if (current.length() > 0) {
            ids.add(current.toString());
        }

        // ------------------------------------------------------------
        // Line 2: return ids
        // ------------------------------------------------------------
        return ids;
    }
}
