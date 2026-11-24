package dev.difme.hsworker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Fluxnova (Camunda 7 compatible) external-task API: fetch-and-lock with long polling, complete, failure. */
final class Fluxnova {
    record Task(String id, String topic, int retries, JsonNode variables) {
        String str(String name) { JsonNode v = variables.path(name).path("value"); return v.isMissingNode() || v.isNull() ? null : v.asText(); }
        long num(String name) { return variables.path(name).path("value").asLong(); }
    }

    private static final ObjectMapper JSON = new ObjectMapper();
    private final URI base;
    private final String auth, workerId;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    Fluxnova(String engineUrl, String basic, String workerId) {
        this.base = URI.create(engineUrl.endsWith("/") ? engineUrl : engineUrl + "/");
        this.auth = basic == null || basic.isBlank() ? null : "Basic " + Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8));
        this.workerId = workerId;
    }

    List<Task> fetchAndLock(List<String> topics, int max, long pollMs, long lockMs) {
        ObjectNode b = JSON.createObjectNode().put("workerId", workerId).put("maxTasks", max).put("asyncResponseTimeout", pollMs);
        var ts = b.putArray("topics");
        for (String t : topics) ts.addObject().put("topicName", t).put("lockDuration", lockMs);
        JsonNode r = post("external-task/fetchAndLock", b, Duration.ofMillis(pollMs + 10_000));
        List<Task> out = new ArrayList<>();
        for (JsonNode n : r) out.add(new Task(n.path("id").asText(), n.path("topicName").asText(), n.path("retries").asInt(-1), n.path("variables")));
        return out;
    }

    void complete(Task t, Map<String, Object> vars) {
        ObjectNode b = JSON.createObjectNode().put("workerId", workerId);
        ObjectNode v = b.putObject("variables");
        vars.forEach((k, val) -> {
            ObjectNode e = v.putObject(k);
            if (val instanceof Long l) e.put("value", l).put("type", "Long");
            else e.put("value", val == null ? null : String.valueOf(val)).put("type", "String");
        });
        post("external-task/" + t.id() + "/complete", b, Duration.ofSeconds(15));
    }

    /** A transient failure: Fluxnova retries after retryTimeout until retries reach 0, then raises an incident. */
    void failure(Task t, String message, int retriesLeft, long retryMs) {
        ObjectNode b = JSON.createObjectNode().put("workerId", workerId).put("errorMessage", message.length() > 600 ? message.substring(0, 600) : message)
                .put("retries", Math.max(0, retriesLeft)).put("retryTimeout", retryMs);
        post("external-task/" + t.id() + "/failure", b, Duration.ofSeconds(15));
    }

    private JsonNode post(String path, ObjectNode body, Duration timeout) {
        HttpRequest.Builder r = HttpRequest.newBuilder(base.resolve(path)).timeout(timeout).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
        if (auth != null) r.header("Authorization", auth);
        try {
            HttpResponse<String> resp = http.send(r.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) throw new IllegalStateException("Fluxnova " + path + ": HTTP " + resp.statusCode() + " " + head(resp.body()));
            return resp.body() == null || resp.body().isBlank() ? JSON.createArrayNode() : JSON.readTree(resp.body());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Fluxnova unreachable: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static String head(String s) { return s == null ? "" : s.length() > 300 ? s.substring(0, 300) : s; }
}
