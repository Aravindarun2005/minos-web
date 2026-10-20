package minos.common;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** BlobStore on the local file system with atomic (temp + rename) writes. */
public final class LocalBlobStore implements BlobStore {

    private final Path root;

    public LocalBlobStore(Path root) {
        this.root = root.toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.root);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public Path root() {
        return root;
    }

    private Path resolve(String key) {
        if (key.contains("..") || key.startsWith("/") || key.contains("\\")) {
            throw new IllegalArgumentException("Illegal storage key: " + key);
        }
        Path p = root.resolve(key).normalize();
        if (!p.startsWith(root)) throw new IllegalArgumentException("Illegal storage key: " + key);
        return p;
    }

    @Override
    public synchronized void put(String key, byte[] data) {
        Path target = resolve(key);
        try {
            Files.createDirectories(target.getParent());
            Path tmp = target.resolveSibling(target.getFileName() + ".tmp");
            Files.write(tmp, data);
            try {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Storage write failed: " + key, e);
        }
    }

    @Override
    public synchronized byte[] get(String key) {
        Path p = resolve(key);
        try {
            return Files.isRegularFile(p) ? Files.readAllBytes(p) : null;
        } catch (IOException e) {
            throw new IllegalStateException("Storage read failed: " + key, e);
        }
    }

    @Override
    public boolean exists(String key) {
        return Files.isRegularFile(resolve(key));
    }

    @Override
    public synchronized void delete(String key) {
        try {
            Files.deleteIfExists(resolve(key));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public List<String> list(String prefix) {
        Path dir = resolve(prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix);
        List<String> out = new ArrayList<>();
        if (!Files.isDirectory(dir)) return out;
        try (Stream<Path> s = Files.walk(dir)) {
            s.filter(Files::isRegularFile)
                    .filter(p -> !p.getFileName().toString().endsWith(".tmp"))
                    .forEach(p -> out.add(root.relativize(p).toString().replace('\\', '/')));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        out.sort(null);
        return out;
    }

    @Override
    public synchronized void append(String key, byte[] data) {
        Path p = resolve(key);
        try {
            Files.createDirectories(p.getParent());
            Files.write(p, data, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String describe() {
        return "local:" + root;
    }
}
