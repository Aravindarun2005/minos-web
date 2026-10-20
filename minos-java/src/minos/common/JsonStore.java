package minos.common;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Persistent JSON documents on top of a BlobStore. */
public final class JsonStore {

    private final BlobStore store;

    public JsonStore(BlobStore store) {
        this.store = store;
    }

    public BlobStore blobs() {
        return store;
    }

    @SuppressWarnings("unchecked")
    public synchronized Map<String, Object> readMap(String key) {
        byte[] b = store.get(key);
        if (b == null) return new LinkedHashMap<>();
        return (Map<String, Object>) Json.parse(new String(b, StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    public synchronized List<Object> readList(String key) {
        byte[] b = store.get(key);
        if (b == null) return new ArrayList<>();
        return (List<Object>) Json.parse(new String(b, StandardCharsets.UTF_8));
    }

    public synchronized void write(String key, Object value) {
        store.put(key, Json.write(value).getBytes(StandardCharsets.UTF_8));
    }

    /** Append one JSON object per line (security / audit logs). */
    public void log(String key, Map<String, Object> event) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("time", java.time.Instant.now().toString());
        e.putAll(event);
        store.append(key, (Json.write(e) + "\n").getBytes(StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> tailLog(String key, int max) {
        byte[] b = store.get(key);
        List<Map<String, Object>> out = new ArrayList<>();
        if (b == null) return out;
        String[] lines = new String(b, StandardCharsets.UTF_8).split("\n");
        for (int i = lines.length - 1; i >= 0 && out.size() < max; i--) {
            if (!lines[i].isBlank()) out.add((Map<String, Object>) Json.parse(lines[i]));
        }
        return out;
    }
}
