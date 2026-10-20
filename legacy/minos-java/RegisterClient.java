
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.Console;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

public class RegisterClient {

    private static final int ITERATIONS = 210000;
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int KEY_LENGTH = 256;

    public static void register(
            Path setupFile,
            Path privateKeyFile,
            String userId,
            String serverUrl) throws Exception {

        Setup.PublicParameters mpk =
                MinosStorage.load(setupFile);

        Pairing pairing = mpk.getPairing();

        Element beta =
                pairing.getZr()
                        .newRandomElement();

        while (beta.isZero()) {
            beta = pairing.getZr()
                    .newRandomElement();
        }

        beta = beta.getImmutable();

        Element publicKey =
                mpk.getG()
                        .duplicate()
                        .powZn(beta)
                        .getImmutable();

        byte[] privateKeyBytes =
                beta.toBytes();

        byte[] publicKeyBytes =
                publicKey.toBytes();

        String publicKeyBase64 =
                Base64.getEncoder()
                        .encodeToString(publicKeyBytes);

        Console console = System.console();

        if (console == null) {
            throw new IllegalStateException(
                    "Run this program from Windows CMD " +
                    "so the private key password can be entered securely.");
        }

        char[] password =
                console.readPassword(
                        "Create a password for your Minos private key: ");

        if (password == null || password.length < 8) {
            throw new IllegalArgumentException(
                    "Password must contain at least 8 characters");
        }

        Path parent =
                privateKeyFile.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        if (Files.exists(privateKeyFile)) {
            throw new IllegalStateException(
                    "A private key file already exists. " +
                    "Use another path or recover the existing key.");
        }

        saveEncryptedPrivateKey(
                privateKeyFile,
                privateKeyBytes,
                password);

        java.util.Arrays.fill(privateKeyBytes, (byte) 0);
        java.util.Arrays.fill(password, '\0');

        String requestJson =
                "{"
                + "\"userId\":\"" + escapeJson(userId) + "\","
                + "\"publicKey\":\"" + publicKeyBase64 + "\""
                + "}";

        try {
            String response =
                    sendRegistration(
                            serverUrl,
                            requestJson);

            System.out.println(response);
            System.out.println(
                    "Registration request completed.");

            System.out.println(
                    "Private key saved locally at: "
                    + privateKeyFile.toAbsolutePath());

        } catch (Exception e) {

            System.out.println(
                    "Registration with the server failed.");

            System.out.println(
                    "Your private key was saved locally. " +
                    "Do not generate a new key for this account.");

            throw e;
        }
    }

    private static void saveEncryptedPrivateKey(
            Path file,
            byte[] privateKeyBytes,
            char[] password) throws Exception {

        SecureRandom random = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];

        random.nextBytes(salt);
        random.nextBytes(iv);

        PBEKeySpec spec =
                new PBEKeySpec(
                        password,
                        salt,
                        ITERATIONS,
                        KEY_LENGTH);

        SecretKeyFactory factory =
                SecretKeyFactory.getInstance(
                        "PBKDF2WithHmacSHA256");

        byte[] derivedKey =
                factory.generateSecret(spec)
                        .getEncoded();

        spec.clearPassword();

        SecretKey secretKey =
                new SecretKeySpec(
                        derivedKey,
                        "AES");

        Cipher cipher =
                Cipher.getInstance(
                        "AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                new GCMParameterSpec(128, iv));

        byte[] encrypted =
                cipher.doFinal(privateKeyBytes);

        try (DataOutputStream out =
                     new DataOutputStream(
                             Files.newOutputStream(file))) {

            out.writeInt(1);
            out.writeInt(ITERATIONS);

            out.writeInt(salt.length);
            out.write(salt);

            out.writeInt(iv.length);
            out.write(iv);

            out.writeInt(encrypted.length);
            out.write(encrypted);
        }

        java.util.Arrays.fill(derivedKey, (byte) 0);
    }

    private static String sendRegistration(
            String serverUrl,
            String requestJson) throws Exception {

        URL url = new URL(serverUrl);

        HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("POST");
        connection.setRequestProperty(
                "Content-Type",
                "application/json");

        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setDoOutput(true);

        byte[] requestBytes =
                requestJson.getBytes(
                        StandardCharsets.UTF_8);

        try (DataOutputStream out =
                     new DataOutputStream(
                             connection.getOutputStream())) {

            out.write(requestBytes);
        }

        int status =
                connection.getResponseCode();

        java.io.InputStream stream =
                status >= 200 && status < 300
                        ? connection.getInputStream()
                        : connection.getErrorStream();

        String response;

        try (java.io.InputStream input = stream) {
            response = new String(
                    input.readAllBytes(),
                    StandardCharsets.UTF_8);
        }

        connection.disconnect();

        if (status < 200 || status >= 300) {
            throw new IOException(
                    "Server returned HTTP " + status
                    + ": " + response);
        }

        return response;
    }

    private static String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    public static void main(String[] args)
            throws Exception {

        if (args.length != 4) {
            System.out.println(
                    "Usage: java RegisterClient "
                    + "<setup-file> <private-key-file> "
                    + "<userId> <server-url>");
            return;
        }

        register(
                Paths.get(args[0]),
                Paths.get(args[1]),
                args[2],
                args[3]);
    }
}