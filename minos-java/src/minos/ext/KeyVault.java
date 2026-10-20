package minos.ext;

import minos.common.CryptoUtil;
import minos.common.Json;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;

/**
 * PROJECT EXTENSION - protected storage of secret key material on the
 * Minos server (never on the CSP).
 *
 * Holds per account: sk (Register, Algorithm 2) and the KeyGen output
 * K = ({sk1,v}, sk2, k) (Algorithm 3); per document: the owner's keyword
 * dictionary W (needed by Detect/Algorithm 11 and Trace/Algorithm 10).
 *
 * Every entry is a JSON object encrypted with AES-256-GCM under a vault
 * master key (AAD = entry name, so entries cannot be swapped). The master
 * key is either
 *   - derived with PBKDF2-HMAC-SHA256 from the MINOS_VAULT_PASSPHRASE
 *     environment variable (recommended), or
 *   - a random 256-bit key in <data>/vault/master.key, created on first
 *     setup with owner-only file permissions where supported.
 *
 * Why not a per-user password-derived key: in Minos the data owner must be
 * online to run Authorize and Detect (paper Section VIII-A). The paper
 * suggests a trusted proxy for this; the Minos server plays that proxy role
 * here, so it must be able to use an owner's sk_o while the owner is
 * logged out.
 */
public final class KeyVault {

    private final Path dir;
    private final byte[] masterKey;
    private final String mode;

    public KeyVault(Path dataDir) throws Exception {
        this.dir = dataDir.resolve("vault");
        Files.createDirectories(dir.resolve("entries"));

        String pass = System.getenv("MINOS_VAULT_PASSPHRASE");
        if (pass != null && !pass.isEmpty()) {
            Path saltFile = dir.resolve("master.salt");
            if (!Files.exists(saltFile)) Files.write(saltFile, CryptoUtil.random(16));
            masterKey = CryptoUtil.pbkdf2(pass.toCharArray(), Files.readAllBytes(saltFile), CryptoUtil.PBKDF2_ITERATIONS);
            mode = "PBKDF2(MINOS_VAULT_PASSPHRASE)";
        } else {
            Path keyFile = dir.resolve("master.key");
            if (!Files.exists(keyFile)) {
                Files.write(keyFile, CryptoUtil.random(32));
                try {
                    Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-------"));
                } catch (UnsupportedOperationException ignored) {
                    // Windows: rely on the user profile ACLs
                }
            }
            masterKey = Files.readAllBytes(keyFile);
            mode = "random master key file";
        }
        // Detect a wrong passphrase early.
        Path check = dir.resolve("check.bin");
        if (Files.exists(check)) {
            try {
                CryptoUtil.aesGcmOpen(masterKey, Files.readAllBytes(check), "check".getBytes(StandardCharsets.UTF_8));
            } catch (IllegalStateException e) {
                throw new IllegalStateException("Key vault cannot be opened: wrong MINOS_VAULT_PASSPHRASE or master key");
            }
        } else {
            Files.write(check, CryptoUtil.aesGcmSeal(masterKey, "ok".getBytes(StandardCharsets.UTF_8),
                    "check".getBytes(StandardCharsets.UTF_8)));
        }
    }

    public String mode() {
        return mode;
    }

    public synchronized void put(String name, Map<String, Object> secret) {
        validate(name);
        byte[] plain = Json.write(secret).getBytes(StandardCharsets.UTF_8);
        byte[] sealed = CryptoUtil.aesGcmSeal(masterKey, plain, name.getBytes(StandardCharsets.UTF_8));
        java.util.Arrays.fill(plain, (byte) 0);
        try {
            Path target = dir.resolve("entries").resolve(name + ".vault");
            Path tmp = target.resolveSibling(name + ".vault.tmp");
            Files.write(tmp, sealed);
            Files.move(tmp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            throw new IllegalStateException("Vault write failed", e);
        }
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> get(String name) {
        validate(name);
        try {
            Path file = dir.resolve("entries").resolve(name + ".vault");
            if (!Files.exists(file)) throw new IllegalStateException("Vault entry not found: " + name);
            byte[] plain = CryptoUtil.aesGcmOpen(masterKey, Files.readAllBytes(file), name.getBytes(StandardCharsets.UTF_8));
            Map<String, Object> out = (Map<String, Object>) Json.parse(new String(plain, StandardCharsets.UTF_8));
            java.util.Arrays.fill(plain, (byte) 0);
            return out;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Vault read failed: " + name, e);
        }
    }

    public boolean has(String name) {
        validate(name);
        return Files.exists(dir.resolve("entries").resolve(name + ".vault"));
    }

    private static void validate(String name) {
        if (!name.matches("[A-Za-z0-9_.-]{1,120}")) throw new IllegalArgumentException("Bad vault entry name");
    }
}
