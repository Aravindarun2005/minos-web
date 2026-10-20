package minos.common;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/** Server-to-server JSON calls (Minos <-> CSP) using java.net.http. */
public final class JsonHttpClient {

    private final String baseUrl;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).build();
    private volatile String linkKey;

    public JsonHttpClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    public String baseUrl() {
        return baseUrl;
    }

    /** Shared secret sent as X-Minos-Link on privileged server-to-server calls. */
    public void setLinkKey(String linkKey) {
        this.linkKey = linkKey;
    }

    public Map<String, Object> get(String path) {
        return send(HttpRequest.newBuilder(URI.create(baseUrl + path)).GET());
    }

    public Map<String, Object> post(String path, Map<String, Object> body) {
        return send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> send(HttpRequest.Builder builder) {
        builder.timeout(Duration.ofSeconds(120));
        if (linkKey != null) builder.header("X-Minos-Link", linkKey);
        HttpResponse<String> response;
        try {
            response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new Http.ApiException(503, "Server unreachable at " + baseUrl + " (" + e.getClass().getSimpleName() + ")");
        }
        Map<String, Object> out;
        try {
            out = (Map<String, Object>) Json.parse(response.body());
        } catch (RuntimeException e) {
            out = new LinkedHashMap<>();
            out.put("success", false);
            out.put("message", "Invalid response from " + baseUrl);
        }
        if (response.statusCode() >= 300 || Boolean.FALSE.equals(out.get("success"))) {
            Object msg = out.get("message");
            throw new Http.ApiException(response.statusCode() >= 400 ? response.statusCode() : 502,
                    msg == null ? "Remote call failed" : msg.toString());
        }
        return out;
    }
}
