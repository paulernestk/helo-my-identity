package my.helo.identity.service;

import my.helo.identity.security.AdminTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;
import java.util.Map;

@Service
public class FederatedIdentityService {

    private static final Logger log = LoggerFactory.getLogger(FederatedIdentityService.class);

    private final WebClient webClient;
    private final AdminTokenProvider adminTokenProvider;
    private final UserService userService;
    private final String realm;
    private final String serverUrl;

    public FederatedIdentityService(WebClient.Builder builder,
                                    AdminTokenProvider adminTokenProvider,
                                    UserService userService,
                                    @org.springframework.beans.factory.annotation.Value("${keycloak.realm}") String realm,
                                    @org.springframework.beans.factory.annotation.Value("${keycloak.server-url}") String serverUrl) {
        this.webClient = builder.build();
        this.adminTokenProvider = adminTokenProvider;
        this.userService = userService;
        this.realm = realm;
        this.serverUrl = serverUrl;
    }

    public void linkProvider(String provider, String bearerToken) {
        String userId = userService.extractUserIdFromJwt(bearerToken);
        String adminToken = adminTokenProvider.getToken();

        // This assumes the provider has already been authenticated via frontend
        log.info("Linking provider {} to user {}", provider, userId);
        // Linking typically requires redirect flow; this is a placeholder
    }

    public List<Map<String, Object>> getLinkedProviders(String bearerToken) {
        String userId = userService.extractUserIdFromJwt(bearerToken);
        String adminToken = adminTokenProvider.getToken();

        return webClient.get()
                .uri(serverUrl + "/admin/realms/" + realm + "/users/" + userId + "/federated-identity")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .bodyToMono(List.class)
                .block();
    }

    public void unlinkProvider(String provider, String bearerToken) {
        String userId = userService.extractUserIdFromJwt(bearerToken);
        String adminToken = adminTokenProvider.getToken();

        webClient.delete()
                .uri(serverUrl + "/admin/realms/" + realm + "/users/" + userId + "/federated-identity/" + provider)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .toBodilessEntity()
                .block();

        log.info("Unlinked provider {} from user {}", provider, userId);
    }
}
