package minos.common;

import java.util.List;

/**
 * Storage abstraction. All CSP persistence goes through this interface, so
 * the local implementation (LocalBlobStore) can later be replaced by a real
 * cloud object store (S3, Azure Blob, GCS...) without touching CSP logic.
 * Keys are '/'-separated paths such as "encrypted-documents/<id>.bin".
 */
public interface BlobStore {

    void put(String key, byte[] data);

    /** @return the stored bytes, or null if absent. */
    byte[] get(String key);

    boolean exists(String key);

    void delete(String key);

    /** Keys directly or indirectly below a prefix ("public-keys/"). */
    List<String> list(String prefix);

    /** Append to a log object (object stores would emulate this). */
    void append(String key, byte[] data);

    String describe();
}
