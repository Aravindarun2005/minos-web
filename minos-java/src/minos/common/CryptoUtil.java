package minos.common;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/** Java built-in cryptography only (javax.crypto / java.security). */
public final class CryptoUtil {

    private CryptoUtil() {
    }

    public static final SecureRandom RANDOM = new SecureRandom();
    public static final int GCM_NONCE = 12;
    public static final int GCM_TAG_BITS = 128;

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /** AES-GCM; returns nonce(12) || ciphertext||tag. */
    public static byte[] aesGcmSeal(byte[] key, byte[] plaintext, byte[] aad) {
        try {
            byte[] nonce = random(GCM_NONCE);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, nonce));
            if (aad != null) c.updateAAD(aad);
            byte[] ct = c.doFinal(plaintext);
            byte[] out = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ct, 0, out, nonce.length, ct.length);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public static byte[] aesGcmOpen(byte[] key, byte[] sealed, byte[] aad) {
        try {
            if (sealed.length <= GCM_NONCE) throw new IllegalArgumentException("ciphertext too short");
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, Arrays.copyOfRange(sealed, 0, GCM_NONCE)));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(sealed, GCM_NONCE, sealed.length - GCM_NONCE);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM authentication failed (wrong key or tampered data)");
        }
    }

    /** HKDF-SHA256 (RFC 5869) built from javax.crypto.Mac. */
    public static byte[] hkdf(byte[] ikm, byte[] salt, String info, int length) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt == null || salt.length == 0 ? new byte[32] : salt, "HmacSHA256"));
            byte[] prk = mac.doFinal(ikm);
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] out = new byte[length];
            byte[] t = new byte[0];
            int pos = 0;
            for (int i = 1; pos < length; i++) {
                mac.update(t);
                mac.update(info.getBytes(StandardCharsets.UTF_8));
                mac.update((byte) i);
                t = mac.doFinal();
                int n = Math.min(t.length, length - pos);
                System.arraycopy(t, 0, out, pos, n);
                pos += n;
            }
            return out;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static final int PBKDF2_ITERATIONS = 210_000;

    public static byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
            byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) d.update(p);
            return d.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(byte[]... parts) {
        return hex(sha256(parts));
    }

    public static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    public static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static byte[] unb64(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new Http.ApiException(400, "Invalid Base64 data");
        }
    }

    public static String randomId(int bytes) {
        return hex(random(bytes));
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
