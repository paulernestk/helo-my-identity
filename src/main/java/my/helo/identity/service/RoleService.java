package my.helo.identity.service;

import my.helo.identity.security.AdminTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.*;

@Service
public class RoleService {

    private final WebClient webClient;
    private final AdminTokenProvider tokenProvider;
    private final String realm;
    private final String serverUrl;

    public RoleService(WebClient.Builder builder,
                       AdminTokenProvider tokenProvider,
                       @Value("${keycloak.realm}") String realm,
                       @Value("${keycloak.server-url}") String serverUrl) {
        this.webClient = builder.build();
        this.tokenProvider = tokenProvider;
        this.realm = realm;
        this.serverUrl = serverUrl;
    }

    public void initializeRoles() {
        String token = tokenProvider.getToken();
        List<String> roles = List.of("guest", "member", "admin");

        for (String role : roles) {
            Map<String, Object> payload = Map.of("name", role);

            webClient.post()
                    .uri(serverUrl + "/admin/realms/" + realm + "/roles")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(payload)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
        }
    }

    public void assignRole(String email, String roleName) {
        String token = tokenProvider.getToken();

        List<Map<String, Object>> users = webClient.get()
                .uri(serverUrl + "/admin/realms/" + realm + "/users?username=" + email)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(List.class)
                .block();

        if (users == null || users.isEmpty()) return;
        String userId = (String) users.get(0).get("id");

        List<Map<String, Object>> roles = webClient.get()
                .uri(serverUrl + "/admin/realms/" + realm + "/roles")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .retrieve()
                .bodyToMono(List.class)
                .block();

        Map<String, Object> role = roles.stream()
                .filter(r -> roleName.equals(r.get("name")))
                .findFirst()
                .orElse(null);

        if (role == null) return;

        webClient.post()
                .uri(serverUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(List.of(role))
                .retrieve()
                .toBodilessEntity()
                .block();
    }
}
