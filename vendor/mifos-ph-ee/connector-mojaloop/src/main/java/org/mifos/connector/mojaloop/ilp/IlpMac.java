package org.mifos.connector.mojaloop.ilp;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * DIFME (keys only in the emulated TEE): the HMAC-SHA256 behind every ILP fulfilment. With {@code connector.hsm-url}
 * set, the security module computes it with this FSP's own key {@code ilp-<connector.ilp-institution>}
 * (POST /v1/ilp/&lt;institution&gt;/hmac); the connector never holds the key. Without it (local runs, upstream tests)
 * the in-process {@code connector.ilp-secret} is used, as upstream did, with a warning.
 */
@Component
public class IlpMac {
    private static final Logger LOG = LoggerFactory.getLogger(IlpMac.class);
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    @Value("${connector.hsm-url:}")
    private String hsmUrl;

    @Value("${connector.ilp-institution:difme}")
    private String institution;

    @Value("${connector.ilp-secret:}")
    private String localSecret;

    private volatile boolean warned;

    /** HMAC-SHA256 over the ILP packet's bytes (as upstream's IlpConditionHandlerImpl computed it). */
    public byte[] mac(String ilpPacket) {
        byte[] data = ilpPacket.getBytes();
        if (hsmUrl == null || hsmUrl.isBlank()) return local(data);
        String url = hsmUrl.replaceAll("/+$", "") + "/v1/ilp/" + institution + "/hmac";
        String body = "{\"data\":\"" + HexFormat.of().withUpperCase().formatHex(data) + "\"}";
        try {
            HttpResponse<String> r = HTTP.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) throw new IllegalStateException("security module answered HTTP " + r.statusCode() + " for the ILP fulfilment");
            String hex = r.body().replaceAll(".*\"mac\"\\s*:\\s*\"([0-9A-Fa-f]{64})\".*", "$1");
            if (hex.length() != 64) throw new IllegalStateException("security module returned no MAC");
            return HexFormat.of().parseHex(hex);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("security module unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private byte[] local(byte[] data) {
        if (localSecret == null || localSecret.isBlank()) throw new IllegalStateException("no connector.hsm-url and no connector.ilp-secret");
        if (!warned) {
            warned = true;
            LOG.warn("ILP secret held in this process (connector.hsm-url not set): local runs only, never in a cluster");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(localSecret.getBytes(), "HmacSHA256"));
            return mac.doFinal(data);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
