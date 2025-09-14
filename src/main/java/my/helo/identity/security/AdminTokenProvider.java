package my.helo.identity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AdminTokenProvider {

    private final WebClient webClient;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;

    private final ConcurrentHashMap<String, CachedToken> cache = new ConcurrentHashMap<>();

    public AdminTokenProvider(WebClient.Builder builder,
                              @Value("${keycloak.server-url}") String serverUrl,
                              @Value("${keycloak.realm}") String realm,
                              @Value("${keycloak.admin-client-id}") String clientId,
                              @Value("${keycloak.admin-client-secret}") String clientSecret) {
        this.webClient = builder.build();
        this.tokenUrl = serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String getToken() {
        CachedToken cached = cache.get("admin");
        if (cached != null && Instant.now().isBefore(cached.expiry)) {
            return cached.token;
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("grant_type", "client_credentials");

        Map<String, Object> response = webClient.post()
                .uri(tokenUrl)
                .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        String token = (String) response.get("access_token");
        int expiresIn = (int) response.get("expires_in");

        cache.put("admin", new CachedToken(token, Instant.now().plusSeconds(expiresIn - 30)));
        return token;
    }

    private record CachedToken(String token, Instant expiry) {}
}
