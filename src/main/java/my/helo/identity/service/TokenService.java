package my.helo.identity.service;

import my.helo.identity.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Map;

@Service
public class TokenService {

    private final WebClient webClient;
    private final String serverUrl;
    private final String realm;
    private final String clientId;

    public TokenService(WebClient.Builder builder,
                        @Value("${keycloak.server-url}") String serverUrl,
                        @Value("${keycloak.realm}") String realm,
                        @Value("${keycloak.client-id}") String clientId) {
        this.webClient = builder.build();
        this.serverUrl = serverUrl;
        this.realm = realm;
        this.clientId = clientId;
    }

    public TokenResponse refreshAccessToken(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);

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
    }
}
