package my.helo.identity.service;

import my.helo.identity.security.AdminTokenProvider;
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
public class UserService {

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
        String token = tokenProvider.getToken();

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", email);
        payload.put("email", email);
        payload.put("enabled", true);
        payload.put("credentials", List.of(Map.of(
                "type", "password",
                "value", "temporary123",
                "temporary", false
        )));

        webClient.post()
                .uri(serverUrl + "/admin/realms/" + realm + "/users")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                .toBodilessEntity()
                .block();
    }

    public String issueJwt(String username, String password) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "password");
        form.add("username", username);
        form.add("password", password);

        Map<String, Object> response = webClient.post()
                .uri(serverUrl + "/realms/" + realm + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(Map.class)
                .block();

        return (String) response.get("access_token");
    }
}
