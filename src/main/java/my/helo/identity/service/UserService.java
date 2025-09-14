package my.helo.identity.service;

import my.helo.identity.dto.TokenResponse;
import my.helo.identity.security.AdminTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.*;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final WebClient webClient;
    private final AdminTokenProvider tokenProvider;
    private final String realm;
    private final String clientId;
    private final String serverUrl;

    public UserService(WebClient.Builder builder,
                       AdminTokenProvider tokenProvider,
                       @Value("${keycloak.realm}") String realm,
                       @Value("${keycloak.client-id}") String clientId,
                       @Value("${keycloak.server-url}") String serverUrl) {
        this.webClient = builder.build();
        this.tokenProvider = tokenProvider;
        this.realm = realm;
        this.clientId = clientId;
        this.serverUrl = serverUrl;
    }

    public void createUser(String email) {
        String token;
        try {
            token = tokenProvider.getToken();
        } catch (Exception e) {
            log.error("Failed to retrieve admin token", e);
            throw new RuntimeException("Unable to create user: admin token unavailable");
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", email);
        payload.put("email", email);
        payload.put("enabled", true);
        payload.put("credentials", List.of(Map.of(
                "type", "password",
                "value", "temporary123",
                "temporary", false
        )));

        try {
            webClient.post()
                    .uri(serverUrl + "/admin/realms/" + realm + "/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(payload)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log.info("User {} created successfully", email);
        } catch (WebClientResponseException e) {
            log.error("Keycloak user creation failed: {}", e.getResponseBodyAsString(), e);
            throw new RuntimeException("User creation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during user creation", e);
            throw new RuntimeException("Unexpected error during user creation", e);
        }
    }

    public String issueJwt(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);

        try {
            Map<String, Object> response = webClient.post()
                    .uri(serverUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(form))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return (String) response.get("access_token");
        } catch (WebClientResponseException e) {
            log.error("JWT issuance failed: {}", e.getResponseBodyAsString(), e);
            throw new RuntimeException("JWT issuance failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during JWT issuance", e);
            throw new RuntimeException("Unexpected error during JWT issuance", e);
        }
    }

    public TokenResponse issueJwtWithRefresh(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);
        form.add("scope", "openid offline_access");

        try {
            Map<String, Object> response = webClient.post()
                    .uri(serverUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(form))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return new TokenResponse(
                    (String) response.get("access_token"),
                    (String) response.get("refresh_token")
            );
        } catch (WebClientResponseException e) {
            log.error("Refresh token issuance failed: {}", e.getResponseBodyAsString(), e);
            throw new RuntimeException("Refresh token issuance failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during refresh token issuance", e);
            throw new RuntimeException("Unexpected error during refresh token issuance", e);
        }
    }
}
