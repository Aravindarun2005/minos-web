package minos.ext;

import minos.common.CryptoUtil;

import java.nio.charset.StandardCharsets;

/**
 * PROJECT EXTENSION - NOT PART OF THE MINOS PAPER.
 *
 * Minos Encrypt (Algorithm 4) only produces the searchable encrypted index
 * L: it hides keywords and document identifiers, not document contents.
 * This class protects the document body itself:
 *
 *   1. A fresh random 256-bit AES key is generated for every document.
 *   2. The document is encrypted with AES-256-GCM (AAD = document id).
 *   3. The file key is wrapped (AES-256-GCM) under a key-encryption key
 *        KEK = HKDF-SHA256(ikm = k, salt = documentId, info = "minos-file-key/v1")
 *      where k is the secret from Minos KeyGen (Algorithm 3, line 7).
 *
 * The CSP stores the encrypted document and the WRAPPED file key, never the
 * raw key. In Minos, k is released only by Authorize (Algorithm 5, lines
 * 20-21: "return TK and k") to users whose attributes satisfy the policy,
 * so only an authorized user can unwrap the file key. The raw file key is
 * never placed in a trapdoor, never logged, and never sent to the CSP.
 */
public final class DocumentCrypto {

    private DocumentCrypto() {
    }

    public static final class Encrypted {
        public final byte[] fileKey;          // raw AES key - caller must not persist it in clear
        public final byte[] sealedDocument;   // nonce || ciphertext || tag
        public final byte[] wrappedFileKey;   // nonce || ciphertext || tag

        Encrypted(byte[] fileKey, byte[] sealedDocument, byte[] wrappedFileKey) {
            this.fileKey = fileKey;
            this.sealedDocument = sealedDocument;
            this.wrappedFileKey = wrappedFileKey;
        }
    }

    public static Encrypted encrypt(byte[] document, String documentId, byte[] minosK) {
        byte[] fileKey = CryptoUtil.random(32);
        byte[] sealed = CryptoUtil.aesGcmSeal(fileKey, document, aad("doc", documentId));
        byte[] wrapped = CryptoUtil.aesGcmSeal(kek(minosK, documentId), fileKey, aad("key", documentId));
        return new Encrypted(fileKey, sealed, wrapped);
    }

    public static byte[] unwrapFileKey(byte[] minosK, String documentId, byte[] wrappedFileKey) {
        return CryptoUtil.aesGcmOpen(kek(minosK, documentId), wrappedFileKey, aad("key", documentId));
    }

    public static byte[] decrypt(byte[] fileKey, String documentId, byte[] sealedDocument) {
        return CryptoUtil.aesGcmOpen(fileKey, sealedDocument, aad("doc", documentId));
    }

    private static byte[] kek(byte[] minosK, String documentId) {
        return CryptoUtil.hkdf(minosK, documentId.getBytes(StandardCharsets.UTF_8), "minos-file-key/v1", 32);
    }

    private static byte[] aad(String purpose, String documentId) {
        return ("minos-" + purpose + "|" + documentId).getBytes(StandardCharsets.UTF_8);
    }
}
