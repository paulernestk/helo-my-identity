package my.helo.identity.service;

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

import java.util.*;

@Service
public class KeycloakUserService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUserService.class);

    private final WebClient webClient;

    @Value("${keycloak.server-url}")
    private String keycloakServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.admin-client-id}")
    private String adminClientId;

    @Value("${keycloak.admin-client-secret}")
    private String adminClientSecret;

    public KeycloakUserService(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    public String issueJwtForUser(String username, String password) {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", clientId);
        formData.add("grant_type", "password");
        formData.add("username", username);
        formData.add("password", password);

        try {
            Map<String, Object> response = webClient.post()
                    .uri(keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return (String) response.get("access_token");
        } catch (Exception e) {
            log.error("Failed to issue JWT for user {}: {}", username, e.getMessage());
            throw new RuntimeException("Token issuance failed");
        }
    }

    private String getAdminToken() {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", adminClientId);
        formData.add("client_secret", adminClientSecret);
        formData.add("grant_type", "client_credentials");

        try {
            Map<String, Object> response = webClient.post()
                    .uri(keycloakServerUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return (String) response.get("access_token");
        } catch (Exception e) {
            log.error("Failed to retrieve admin token: {}", e.getMessage());
            throw new RuntimeException("Admin token retrieval failed");
        }
    }

    public void createUser(String email) {
        String token = getAdminToken();

        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("username", email);
        userPayload.put("email", email);
        userPayload.put("enabled", true);
        userPayload.put("credentials", List.of(Map.of(
                "type", "password",
                "value", "temporary123",
                "temporary", false
        )));

        try {
            webClient.post()
                    .uri(keycloakServerUrl + "/admin/realms/" + realm + "/users")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(userPayload)
                    .retrieve()
                    .toBodilessEntity()
                    .block();

            log.info("User {} created successfully", email);
        } catch (Exception e) {
            log.warn("User creation failed for {}: {}", email, e.getMessage());
        }
    }

    public void promoteToMember(String email) {
        String token = getAdminToken();

        List<Map<String, Object>> users = webClient.get()
                .uri(keycloakServerUrl + "/admin/realms/" + realm + "/users?username=" + email)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(List.class)
                .block();

        if (users == null || users.isEmpty()) {
            log.warn("User {} not found for role promotion", email);
            return;
        }

        String userId = (String) users.get(0).get("id");

        List<Map<String, Object>> roles = webClient.get()
                .uri(keycloakServerUrl + "/admin/realms/" + realm + "/roles")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(List.class)
                .block();

        Map<String, Object> memberRole = roles.stream()
                .filter(role -> "member".equals(role.get("name")))
                .findFirst()
                .orElse(null);

        if (memberRole == null) {
            log.warn("Role 'member' not found in realm {}", realm);
            return;
        }

        webClient.post()
                .uri(keycloakServerUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(List.of(memberRole))
                .retrieve()
                .toBodilessEntity()
                .block();

        log.info("User {} promoted to 'member' role", email);
    }

    public void initializeRoles() {
        String token = getAdminToken();
        List<String> roles = List.of("guest", "member", "admin");

        for (String role : roles) {
            Map<String, Object> payload = Map.of("name", role);

            try {
                webClient.post()
                        .uri(keycloakServerUrl + "/admin/realms/" + realm + "/roles")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue(payload)
                        .retrieve()
                        .toBodilessEntity()
                        .block();

                log.info("Role '{}' initialized", role);
            } catch (Exception e) {
                log.warn("Failed to initialize role '{}': {}", role, e.getMessage());
            }
        }
    }
}
