package dev.difme.exchange.svc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/** OAuth2 client-credentials token from Keycloak, cached until shortly before it expires; header() gives "Bearer …". */
final class ClientCredentials {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final URI tokenUrl;
    private final String form;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private String header;
    private long renewAtMs;

    ClientCredentials(String tokenUrl, String clientId, String clientSecret) {
        this.tokenUrl = URI.create(tokenUrl);
        this.form = "grant_type=client_credentials&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
    }

    synchronized String header() {
        if (header != null && System.currentTimeMillis() < renewAtMs) return header;
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(tokenUrl).timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new IllegalStateException("token endpoint HTTP " + r.statusCode());
            JsonNode n = JSON.readTree(r.body());
            header = "Bearer " + n.path("access_token").asText();
            renewAtMs = System.currentTimeMillis() + Math.max(10, n.path("expires_in").asLong(60) - 30) * 1000L;
            return header;
        } catch (java.io.IOException e) {
            throw new IllegalStateException("token endpoint unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }
}
