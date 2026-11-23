package org.mifos.connector.ams.tenant;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.mifos.connector.ams.camel.config.CamelProperties.LOGIN_PASSWORD;
import static org.mifos.connector.ams.camel.config.CamelProperties.LOGIN_USERNAME;
import static org.mifos.connector.ams.zeebe.ZeebeVariables.TENANT_ID;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.ws.rs.core.HttpHeaders;
import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.ProducerTemplate;
import org.apache.camel.support.DefaultExchange;
import org.mifos.connector.ams.properties.Tenant;
import org.mifos.connector.ams.properties.TenantProperties;
import org.mifos.connector.common.ams.dto.LoginFineractCnResponseDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
// @ConditionalOnExpression("${ams.local.enabled}")
public class TenantService {

    public static final String X_TENANT_IDENTIFIER_HEADER = "X-Tenant-Identifier";
    public static final String USER_HEADER = "User";
    public static final String FINERACT_PLATFORM_TENANT_ID_HEADER = "Fineract-Platform-TenantId";

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private ProducerTemplate producerTemplate;

    @Autowired
    private TenantProperties tenantProperties;

    @Autowired
    private CamelContext camelContext;

    @Value("${ams.local.version}")
    private String amsLocalVersion;

    private final Map<String, CachedTenantAuth> cachedTenantAuths = new ConcurrentHashMap<>();

    public Map<String, Object> getHeaders(String tenantName) {
        logger.info("Getting headers for tenant: {}", tenantName);
        Tenant tenant = tenantProperties.getTenant(tenantName);
        Map<String, Object> headers = new HashMap<>();

        if ("1.2".equals(amsLocalVersion)) {
            headers.put(FINERACT_PLATFORM_TENANT_ID_HEADER, tenantName);
        } else if ("cn".equals(amsLocalVersion)) {
            headers.put(X_TENANT_IDENTIFIER_HEADER, tenantName);
            headers.put(USER_HEADER, tenant.getUser());
        } else {
            throw new RuntimeException("Unsupported Fineract version: " + amsLocalVersion);
        }

        headers.put(HttpHeaders.AUTHORIZATION, getTenantAuthData(tenant).getToken());

        return headers;
    }

    private CachedTenantAuth getTenantAuthData(Tenant tenant) {
        CachedTenantAuth cachedTenantAuth = cachedTenantAuths.get(tenant.getName());
        if (cachedTenantAuth == null || isAccessTokenExpired(cachedTenantAuth.getAccessTokenExpiration())) {
            cachedTenantAuth = login(tenant);
            cachedTenantAuths.put(tenant.getName(), cachedTenantAuth);
        }
        return cachedTenantAuth;
    }

    private CachedTenantAuth login(Tenant tenant) {
        String tenantAuthtype = tenant.getAuthtype();
        if ("1.2".equals(amsLocalVersion) && "basic".equals(tenantAuthtype)) {
            return new CachedTenantAuth(
                    "Basic " + Base64.getEncoder().encodeToString((tenant.getUser() + ":" + tenant.getPassword()).getBytes(UTF_8)), null);
        } else if ("1.2".equals(amsLocalVersion) && "oauth".equals(tenantAuthtype)) {
            // DIFME patch (upstream: "TODO implement"): OAuth2 client credentials against the identity provider
            // (Keycloak) at ams.local.oauth.token-url; tenant user/password are the client id/secret. Fineract accepts
            // the token through its OIDC federation and maps the service account to a Fineract user.
            return clientCredentials(tenant);
        } else if ("cn".equals(amsLocalVersion) && "oauth".equals(tenantAuthtype)) {
            Exchange ex = new DefaultExchange(camelContext);
            ex.setProperty(TENANT_ID, tenant.getName());
            ex.setProperty(LOGIN_USERNAME, tenant.getUser());
            ex.setProperty(LOGIN_PASSWORD, tenant.getPassword());
            producerTemplate.send("direct:fincn-oauth", ex);
            LoginFineractCnResponseDTO response = ex.getOut().getBody(LoginFineractCnResponseDTO.class);
            return new CachedTenantAuth(response.getAccessToken(), response.getAccessTokenExpiration());
        } else {
            throw new RuntimeException("Unsupported authType: " + tenantAuthtype + ", for local fsp version: " + amsLocalVersion
                    + ", for tenant: " + tenant.getName());
        }
    }

    @Value("${ams.local.oauth.token-url:}")
    private String oauthTokenUrl;

    private final java.net.http.HttpClient oauthHttp = java.net.http.HttpClient.newHttpClient();

    /** DIFME patch: OAuth2 client-credentials grant; the cached header is "Bearer token" with the token's expiry. */
    private CachedTenantAuth clientCredentials(Tenant tenant) {
        if (oauthTokenUrl == null || oauthTokenUrl.isBlank()) {
            throw new RuntimeException("ams.local.oauth.token-url is not set (tenant " + tenant.getName() + " uses oauth)");
        }
        String form = "grant_type=client_credentials&client_id=" + java.net.URLEncoder.encode(tenant.getUser(), UTF_8)
                + "&client_secret=" + java.net.URLEncoder.encode(tenant.getPassword(), UTF_8);
        try {
            java.net.http.HttpResponse<String> r = oauthHttp.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(oauthTokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(form)).build(), java.net.http.HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() != 200) {
                throw new RuntimeException("token request for tenant " + tenant.getName() + " failed: HTTP " + r.statusCode());
            }
            org.json.JSONObject body = new org.json.JSONObject(r.body());
            long expiresIn = body.optLong("expires_in", 300);
            return new CachedTenantAuth("Bearer " + body.getString("access_token"), new Date(System.currentTimeMillis() + expiresIn * 1000));
        } catch (java.io.IOException e) {
            throw new RuntimeException("token request for tenant " + tenant.getName() + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("interrupted", e);
        }
    }

    private boolean isAccessTokenExpired(Date accessTokenExpiration) {
        if (accessTokenExpiration == null) { // basic is stateless and has no expiration
            return false;
        }

        Date fiveMinsFromNow = new Date(System.currentTimeMillis() + 300 * 1000);
        return accessTokenExpiration.before(fiveMinsFromNow);
    }
}
