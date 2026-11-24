package dev.difme.railsworker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigDecimal;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Core banking (Apache Fineract) as DIFME's CBS. Every party holds one INR savings account, addressed by a DIFME name
 * (e.g. {@code merchant-M1}, {@code escrow}) stored as the account's external id, so the hub keeps no mapping of its
 * own. Money moves as account transfers carrying an {@code Idempotency-Key}: a retried posting is answered from
 * Fineract's record of the first one, never booked twice.
 */
public final class Fineract {
    /** The payer's account can't cover the amount (Fineract domain rule); retrying won't help. */
    public static final class Insufficient extends RuntimeException {
        public Insufficient(String m) { super(m); }
    }

    /** Fineract refused the request for a reason other than funds; retrying won't help. */
    public static final class Rejected extends RuntimeException {
        public Rejected(String m) { super(m); }
    }

    public record Account(long id, long clientId, long officeId, String name, long balanceMinor) {}

    static final String WALLET = "DIFME Wallet", SETTLEMENT = "DIFME Settlement";
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd MMMM yyyy", Locale.ENGLISH);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final URI base;
    private final java.util.function.Supplier<String> auth;
    private final String tenant;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, Long> products = new ConcurrentHashMap<>();
    private final Map<String, Account> accounts = new ConcurrentHashMap<>();   // ids never change once opened

    /** Password login (a Fineract without OIDC federation, e.g. a local one). */
    public Fineract(String baseUrl, String user, String password, String tenant) {
        this(baseUrl, basic(user, password), tenant);
    }

    /** {@code auth} gives the Authorization header for each request. */
    public Fineract(String baseUrl, java.util.function.Supplier<String> auth, String tenant) {
        this.base = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
        this.auth = auth;
        this.tenant = tenant;
    }

    static java.util.function.Supplier<String> basic(String user, String password) {
        String h = "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        return () -> h;
    }

    /**
     * Keycloak login (OAuth2 client credentials): Fineract accepts the token through its OIDC federation and maps the
     * token's {@code fineract_user} claim to one of its users. The token is reused until a minute before it expires.
     */
    public static java.util.function.Supplier<String> clientCredentials(String tokenUrl, String clientId, String clientSecret) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        String form = "grant_type=client_credentials&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
        Object lock = new Object();
        String[] header = {null};
        long[] renewAt = {0};
        return () -> {
            synchronized (lock) {
                if (header[0] == null || System.currentTimeMillis() >= renewAt[0]) {
                    try {
                        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(tokenUrl)).timeout(Duration.ofSeconds(10))
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString());
                        if (r.statusCode() != 200) throw new IllegalStateException("identity provider refused the login: HTTP " + r.statusCode());
                        JsonNode t = JSON.readTree(r.body());
                        header[0] = "Bearer " + t.path("access_token").asText();
                        renewAt[0] = System.currentTimeMillis() + Math.max(10, t.path("expires_in").asLong(300) - 60) * 1000;
                    } catch (java.io.IOException e) {
                        throw new IllegalStateException("identity provider unreachable: " + e.getMessage(), e);   // retryable
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("interrupted", e);
                    }
                }
                return header[0];
            }
        };
    }

    /**
     * Settlement accounts (the card scheme's, the exchange's) may run negative: they stand for money owed between
     * institutions. Every other party's account can't go below zero.
     */
    static boolean settlement(String name) { return name.endsWith("-settlement"); }

    /** The named account, opened (client + product + account, approved and active) on first use. */
    public Account account(String name) {
        Account known = accounts.get(name);
        if (known != null) return known;
        JsonNode a = get("api/v1/savingsaccounts/external-id/" + enc(name));
        if (a == null) a = open(name);
        interopIdentifier(name);
        Account acc = new Account(a.path("id").asLong(), a.path("clientId").asLong(), officeOf(a), name, 0);
        accounts.put(name, acc);
        return acc;
    }

    /**
     * Registers the account's interop identifier ACCOUNT_ID = its DIFME name (the external id) if missing, so Mifos PH-EE,
     * which resolves every party through Fineract's interoperation API, can address the same account (ADR-022, D3).
     * Also backfills accounts opened before. Fineract refuses a second registration (403): fine if it now exists.
     */
    private void interopIdentifier(String name) {
        String path = "api/v1/interoperation/parties/ACCOUNT_ID/" + enc(name);
        if (get(path) != null) return;
        try {
            post(path, JSON.createObjectNode().put("accountId", name), null);
        } catch (Rejected e) {
            if (get(path) == null) throw e;
        }
    }

    /** The account a PH-EE party identifier ACCOUNT_ID resolves to (its external id), or null. */
    public String interopAccount(String name) {
        JsonNode n = get("api/v1/interoperation/parties/ACCOUNT_ID/" + enc(name));
        return n == null ? null : n.path("accountId").asText(null);
    }

    /** Current balance in minor units. */
    public long balanceMinor(String name) {
        JsonNode a = get("api/v1/savingsaccounts/" + account(name).id());
        return toMinor(a.path("summary").path("accountBalance").decimalValue());
    }

    /** Moves money between two named accounts; idempotencyKey makes retries safe. Returns Fineract's transfer id. */
    public long transfer(String idempotencyKey, String from, String to, long amountMinor, String note) {
        if (amountMinor <= 0) throw new Rejected("amount must be positive");
        Account f = account(from), t = account(to);
        ObjectNode b = dated();
        b.put("fromOfficeId", f.officeId()).put("fromClientId", f.clientId()).put("fromAccountType", 2).put("fromAccountId", f.id())
                .put("toOfficeId", t.officeId()).put("toClientId", t.clientId()).put("toAccountType", 2).put("toAccountId", t.id())
                .put("transferAmount", toMajor(amountMinor)).put("transferDate", today()).put("transferDescription", note);
        return post("api/v1/accounttransfers", b, idempotencyKey).path("resourceId").asLong();
    }

    /** Money arriving from outside DIFME's books (a bank transfer in): a deposit, idempotent by key. */
    public long deposit(String idempotencyKey, String to, long amountMinor, String note) {
        if (amountMinor <= 0) throw new Rejected("amount must be positive");
        ObjectNode b = dated();
        b.put("transactionDate", today()).put("transactionAmount", toMajor(amountMinor)).put("paymentTypeId", paymentType()).put("note", note);
        return post("api/v1/savingsaccounts/" + account(to).id() + "/transactions?command=deposit", b, idempotencyKey)
                .path("resourceId").asLong();
    }

    // ── opening accounts ────────────────────────────────────────────────────────────────────────────────────────────

    private JsonNode open(String name) {
        long product = product(settlement(name) ? SETTLEMENT : WALLET);
        ObjectNode c = dated();
        c.put("officeId", 1).put("legalFormId", settlement(name) ? 2 : 1).put("externalId", name).put("active", true)
                .put("activationDate", today()).put("submittedOnDate", today());
        if (settlement(name)) c.put("fullname", name); else c.put("firstname", "DIFME").put("lastname", name);
        long clientId;
        JsonNode existing = get("api/v1/clients/external-id/" + enc(name));
        clientId = existing != null ? existing.path("id").asLong() : post("api/v1/clients", c, null).path("clientId").asLong();
        ObjectNode s = dated();
        s.put("clientId", clientId).put("productId", product).put("externalId", name).put("submittedOnDate", today());
        long id;
        try {
            id = post("api/v1/savingsaccounts", s, null).path("savingsId").asLong();
        } catch (Rejected e) {                     // opened concurrently by another request: use that one
            JsonNode again = get("api/v1/savingsaccounts/external-id/" + enc(name));
            if (again == null) throw e;
            return again;
        }
        post("api/v1/savingsaccounts/" + id + "?command=approve", dated().put("approvedOnDate", today()), null);
        post("api/v1/savingsaccounts/" + id + "?command=activate", dated().put("activatedOnDate", today()), null);
        return get("api/v1/savingsaccounts/" + id);
    }

    private long product(String name) {
        return products.computeIfAbsent(name, n -> {
            JsonNode all = get("api/v1/savingsproducts");
            if (all != null) for (JsonNode p : all) if (n.equals(p.path("name").asText())) return p.path("id").asLong();
            ObjectNode p = JSON.createObjectNode();
            p.put("name", n).put("shortName", n.equals(SETTLEMENT) ? "DST" : "DWL").put("currencyCode", "INR")
                    .put("digitsAfterDecimal", 2).put("inMultiplesOf", 0).put("nominalAnnualInterestRate", 0)
                    .put("interestCompoundingPeriodType", 1).put("interestPostingPeriodType", 4).put("interestCalculationType", 1)
                    .put("interestCalculationDaysInYearType", 365).put("accountingRule", 1).put("locale", "en");
            if (n.equals(SETTLEMENT)) p.put("allowOverdraft", true).put("overdraftLimit", 1_000_000_000_000L);
            try {
                return post("api/v1/savingsproducts", p, null).path("resourceId").asLong();
            } catch (Rejected e) {                 // created concurrently
                for (JsonNode q : get("api/v1/savingsproducts")) if (n.equals(q.path("name").asText())) return q.path("id").asLong();
                throw e;
            }
        });
    }

    private long paymentType() {
        JsonNode types = get("api/v1/paymenttypes");
        return types != null && types.size() > 0 ? types.get(0).path("id").asLong() : 1;
    }

    private static long officeOf(JsonNode account) {
        long office = account.path("officeId").asLong(0);   // not always in the account view: Head Office otherwise
        return office == 0 ? 1 : office;
    }

    // ── HTTP ────────────────────────────────────────────────────────────────────────────────────────────────────────

    private JsonNode get(String path) {
        HttpResponse<String> r = send(req(path).GET().build());
        if (r.statusCode() == 404) return null;
        return parse(r);
    }

    private JsonNode post(String path, ObjectNode body, String idempotencyKey) {
        HttpRequest.Builder b = req(path).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body.toString()));
        if (idempotencyKey != null) b.header("Idempotency-Key", idempotencyKey);
        return parse(send(b.build()));
    }

    private HttpRequest.Builder req(String path) {
        return HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(30))
                .header("Authorization", auth.get()).header("Fineract-Platform-TenantId", tenant).header("Accept", "application/json");
    }

    private HttpResponse<String> send(HttpRequest r) {
        try {
            return http.send(r, HttpResponse.BodyHandlers.ofString());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("core banking unreachable: " + e.getMessage(), e);   // retryable
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted", e);
        }
    }

    private static JsonNode parse(HttpResponse<String> r) {
        JsonNode n;
        try {
            n = r.body() == null || r.body().isBlank() ? JSON.createObjectNode() : JSON.readTree(r.body());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("core banking answered HTTP " + r.statusCode() + " with a body that is not JSON");
        }
        int s = r.statusCode();
        if (s >= 200 && s < 300) return n;
        String why = n.path("errors").path(0).path("defaultUserMessage").asText(n.path("defaultUserMessage").asText("HTTP " + s));
        String code = n.path("errors").path(0).path("userMessageGlobalisationCode").asText("");
        if (s >= 500 || s == 401 || s == 429) throw new IllegalStateException("core banking HTTP " + s + ": " + why);  // retryable
        if (code.contains("insufficient") || why.toLowerCase(Locale.ROOT).contains("insufficient")) throw new Insufficient(why);
        throw new Rejected(why);
    }

    private static ObjectNode dated() {
        ObjectNode n = JSON.createObjectNode();
        n.put("dateFormat", "dd MMMM yyyy").put("locale", "en");
        return n;
    }

    /** Business date in the tenant's time zone (Asia/Kolkata). */
    private static String today() { return LocalDate.now(ZoneId.of("Asia/Kolkata")).format(DATE); }

    static String toMajor(long minor) { return BigDecimal.valueOf(minor).movePointLeft(2).toPlainString(); }

    static long toMinor(BigDecimal major) { return major.movePointRight(2).longValueExact(); }

    private static String enc(String s) { return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}
