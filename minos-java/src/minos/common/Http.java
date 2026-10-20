package minos.common;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * Minimal HTTP layer on the JDK's built-in com.sun.net.httpserver
 * (no external web framework). Used by both the Minos server and the CSP.
 *
 * Handlers return:
 *   - a Map            -> JSON {"success":true, ...map}
 *   - a Http.Response  -> sent as is (downloads, static files)
 * and throw Http.ApiException for client errors.
 */
public final class Http {

    private Http() {
    }

    public static final int MAX_BODY = 40 * 1024 * 1024;

    // ------------------------------------------------------------
    // Request / Response / errors
    // ------------------------------------------------------------

    public static final class Request {
        public final HttpExchange exchange;
        public final String method;
        public final String path;
        public final Map<String, String> query;
        public final Map<String, String> params = new LinkedHashMap<>();
        private final byte[] body;
        private Map<String, Object> json;
        public Object attachment;   // set by auth filters (session)

        Request(HttpExchange ex, byte[] body) {
            this.exchange = ex;
            this.method = ex.getRequestMethod().toUpperCase();
            this.path = ex.getRequestURI().getPath();
            this.query = parseQuery(ex.getRequestURI().getRawQuery());
            this.body = body;
        }

        public byte[] body() {
            return body;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> json() {
            if (json == null) {
                if (body.length == 0) {
                    json = new LinkedHashMap<>();
                } else {
                    Object parsed;
                    try {
                        parsed = Json.parse(new String(body, StandardCharsets.UTF_8));
                    } catch (RuntimeException e) {
                        throw new ApiException(400, "Malformed JSON body");
                    }
                    if (!(parsed instanceof Map)) throw new ApiException(400, "JSON object expected");
                    json = (Map<String, Object>) parsed;
                }
            }
            return json;
        }

        public String str(String key) {
            Object v = json().get(key);
            if (!(v instanceof String) || ((String) v).trim().isEmpty()) {
                throw new ApiException(400, "Missing field: " + key);
            }
            return (String) v;
        }

        public String optStr(String key, String def) {
            Object v = json().get(key);
            return v instanceof String ? (String) v : def;
        }

        @SuppressWarnings("unchecked")
        public List<Object> list(String key) {
            Object v = json().get(key);
            if (v == null) return new ArrayList<>();
            if (!(v instanceof List)) throw new ApiException(400, "Field must be an array: " + key);
            return (List<Object>) v;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> map(String key) {
            Object v = json().get(key);
            if (!(v instanceof Map)) throw new ApiException(400, "Field must be an object: " + key);
            return (Map<String, Object>) v;
        }

        public String header(String name) {
            return exchange.getRequestHeaders().getFirst(name);
        }

        public String cookie(String name) {
            List<String> headers = exchange.getRequestHeaders().get("Cookie");
            if (headers == null) return null;
            for (String h : headers) {
                for (String part : h.split(";")) {
                    String[] kv = part.trim().split("=", 2);
                    if (kv.length == 2 && kv[0].equals(name)) return kv[1];
                }
            }
            return null;
        }
    }

    public static final class Response {
        public int status = 200;
        public byte[] body = new byte[0];
        public String contentType = "application/octet-stream";
        public final Map<String, String> headers = new LinkedHashMap<>();

        public static Response bytes(byte[] body, String contentType) {
            Response r = new Response();
            r.body = body;
            r.contentType = contentType;
            return r;
        }

        public static Response json(int status, Map<String, Object> map) {
            Response r = bytes(Json.write(map).getBytes(StandardCharsets.UTF_8),
                    "application/json; charset=utf-8");
            r.status = status;
            return r;
        }

        public Response header(String name, String value) {
            headers.put(name, value);
            return this;
        }
    }

    public static class ApiException extends RuntimeException {
        public final int status;

        public ApiException(int status, String message) {
            super(message);
            this.status = status;
        }
    }

    public interface Handler {
        Object handle(Request request) throws Exception;
    }

    public interface Filter {
        void check(Request request) throws Exception;
    }

    // ------------------------------------------------------------
    // Router
    // ------------------------------------------------------------

    public static final class Router implements HttpHandler {

        private static final class Route {
            final String method;
            final String[] parts;
            final Handler handler;
            final Filter[] filters;

            Route(String method, String pattern, Handler handler, Filter[] filters) {
                this.method = method;
                this.parts = pattern.split("/");
                this.handler = handler;
                this.filters = filters;
            }

            boolean matches(Request r) {
                String[] p = r.path.split("/");
                if (!method.equals(r.method) || p.length != parts.length) return false;
                Map<String, String> found = new LinkedHashMap<>();
                for (int i = 0; i < parts.length; i++) {
                    if (parts[i].startsWith("{") && parts[i].endsWith("}")) {
                        found.put(parts[i].substring(1, parts[i].length() - 1),
                                URLDecoder.decode(p[i], StandardCharsets.UTF_8));
                    } else if (!parts[i].equals(p[i])) {
                        return false;
                    }
                }
                r.params.putAll(found);
                return true;
            }
        }

        private final List<Route> routes = new ArrayList<>();
        private Path staticRoot;
        private final String name;

        public Router(String name) {
            this.name = name;
        }

        public Router get(String pattern, Handler h, Filter... f) {
            routes.add(new Route("GET", pattern, h, f));
            return this;
        }

        public Router post(String pattern, Handler h, Filter... f) {
            routes.add(new Route("POST", pattern, h, f));
            return this;
        }

        public Router staticFiles(Path root) {
            this.staticRoot = root.toAbsolutePath().normalize();
            return this;
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            Response response;
            try {
                byte[] body = readBody(ex);
                Request request = new Request(ex, body);
                response = dispatch(request);
            } catch (ApiException e) {
                response = error(e.status, e.getMessage());
            } catch (Exception e) {
                System.err.println("[" + name + "] " + ex.getRequestMethod() + " "
                        + ex.getRequestURI().getPath() + " failed: " + e);
                response = error(500, e.getMessage() == null ? e.toString() : e.getMessage());
            }
            send(ex, response);
        }

        private Response dispatch(Request request) throws Exception {
            for (Route route : routes) {
                if (route.matches(request)) {
                    for (Filter f : route.filters) f.check(request);
                    Object result = route.handler.handle(request);
                    if (result instanceof Response) return (Response) result;
                    Map<String, Object> out = new LinkedHashMap<>();
                    out.put("success", true);
                    if (result instanceof Map) {
                        for (Map.Entry<?, ?> e : ((Map<?, ?>) result).entrySet()) {
                            out.put(String.valueOf(e.getKey()), e.getValue());
                        }
                    }
                    return Response.json(200, out);
                }
            }
            if (staticRoot != null && "GET".equals(request.method) && !request.path.startsWith("/api/")) {
                return serveStatic(request.path);
            }
            throw new ApiException(404, "Not found: " + request.method + " " + request.path);
        }

        private Response serveStatic(String path) throws IOException {
            String rel = path.equals("/") ? "index.html" : path.substring(1);
            Path file = staticRoot.resolve(rel).normalize();
            if (!file.startsWith(staticRoot) || !Files.isRegularFile(file)) {
                throw new ApiException(404, "Not found");
            }
            String type = "application/octet-stream";
            String f = file.getFileName().toString();
            if (f.endsWith(".html")) type = "text/html; charset=utf-8";
            else if (f.endsWith(".js")) type = "text/javascript; charset=utf-8";
            else if (f.endsWith(".css")) type = "text/css; charset=utf-8";
            else if (f.endsWith(".svg")) type = "image/svg+xml";
            Response r = Response.bytes(Files.readAllBytes(file), type);
            r.header("Cache-Control", "no-store");
            return r;
        }
    }

    // ------------------------------------------------------------
    // Server bootstrap / helpers
    // ------------------------------------------------------------

    public static HttpServer start(int port, Router router, int threads) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 64);
        server.createContext("/", router);
        server.setExecutor(Executors.newFixedThreadPool(threads));
        server.start();
        return server;
    }

    public static Response error(int status, String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("success", false);
        m.put("message", message);
        return Response.json(status, m);
    }

    private static byte[] readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] data = in.readNBytes(MAX_BODY + 1);
            if (data.length > MAX_BODY) throw new ApiException(413, "Request body too large");
            return data;
        }
    }

    private static void send(HttpExchange ex, Response r) throws IOException {
        ex.getResponseHeaders().set("Content-Type", r.contentType);
        ex.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        for (Map.Entry<String, String> h : r.headers.entrySet()) {
            ex.getResponseHeaders().add(h.getKey(), h.getValue());
        }
        ex.sendResponseHeaders(r.status, r.body.length == 0 ? -1 : r.body.length);
        if (r.body.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(r.body);
            }
        }
        ex.close();
    }

    public static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String part : raw.split("&")) {
            String[] kv = part.split("=", 2);
            out.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length > 1 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return out;
    }

    public static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(String.valueOf(kv[i]), kv[i + 1]);
        return m;
    }
}
