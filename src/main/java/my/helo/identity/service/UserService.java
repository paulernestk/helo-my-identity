package my.helo.identity.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import my.helo.identity.dto.ProfileDto;
import my.helo.identity.dto.TokenResponse;
import my.helo.identity.security.AdminTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;
import java.util.*;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);
    private static final Duration USER_CACHE_TTL = Duration.ofMinutes(30);

    private final WebClient webClient;
    private final AdminTokenProvider tokenProvider;
    private final StringRedisTemplate redis;
    private final String realm;
    private final String clientId;
    private final String serverUrl;

    public UserService(WebClient.Builder builder,
                       AdminTokenProvider tokenProvider,
                       StringRedisTemplate redis,
                       @Value("${keycloak.realm}") String realm,
                       @Value("${keycloak.client-id}") String clientId,
                       @Value("${keycloak.server-url}") String serverUrl) {
        this.webClient = builder.build();
        this.tokenProvider = tokenProvider;
        this.redis = redis;
        this.realm = realm;
        this.clientId = clientId;
        this.serverUrl = serverUrl;
    }

    public TokenResponse issueJwtWithProfile(String username, String password) {
        TokenResponse token = issueJwtWithRefresh(username, password);
        ProfileDto profile = getProfile("Bearer " + token.accessToken());
        return new TokenResponse(token.accessToken(), token.refreshToken(), profile);
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

    public String issueJwt(String username, String password) {
        return issueJwtWithRefresh(username, password).accessToken();
    }

    public ProfileDto getProfile(String bearerToken) {
        String userId = extractUserIdFromJwt(bearerToken);
        String token = tokenProvider.getToken();

        try {
            Map<String, Object> user = webClient.get()
                    .uri(serverUrl + "/admin/realms/" + realm + "/users/" + userId)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            return new ProfileDto(
                    (String) user.get("id"),
                    (String) user.get("email"),
                    (String) user.get("username"),
                    List.of()
            );
        } catch (Exception e) {
            log.error("Failed to fetch profile for user {}", userId, e);
            throw new RuntimeException("Profile fetch failed");
        }
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

    public void updatePassword(String email, String newPassword) {
        String token = tokenProvider.getToken();
        String userId = findUserIdByEmail(email);

        Map<String, Object> payload = Map.of(
                "type", "password",
                "value", newPassword,
                "temporary", false
        );

        try {
            webClient.put()
                    .uri(serverUrl + "/admin/realms/" + realm + "/users/" + userId + "/reset-password")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(payload)
                    .retrieve()
                    .toBodilessEntity()
                    .block();
            log.info("Password updated for user {}", email);
        } catch (WebClientResponseException e) {
            log.error("Password update failed: {}", e.getResponseBodyAsString(), e);
            throw new RuntimeException("Password update failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during password update", e);
            throw new RuntimeException("Unexpected error during password update", e);
        }
    }

    public String findUserIdByEmail(String email) {
        String cacheKey = "user-id:" + email;
        String cachedId = redis.opsForValue().get(cacheKey);
        if (cachedId != null) {
            return cachedId;
        }

        String token = tokenProvider.getToken();

        try {
            List<Map<String, Object>> users = webClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path(serverUrl + "/admin/realms/" + realm + "/users")
                            .queryParam("email", email)
                            .build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                    .retrieve()
                    .bodyToMono(List.class)
                    .block();

            if (users == null || users.isEmpty()) {
                throw new IllegalArgumentException("User not found for email: " + email);
            }

            if (users.size() > 1) {
                log.warn("Multiple users found for email: {}. Enforcing uniqueness.", email);
                throw new IllegalStateException("Multiple users found for email: " + email);
            }

            String userId = (String) users.get(0).get("id");
            redis.opsForValue().set(cacheKey, userId, USER_CACHE_TTL);
            return userId;

        } catch (WebClientResponseException e) {
            log.error("Failed to fetch user by email: {}", e.getResponseBodyAsString(), e);
            throw new RuntimeException("User lookup failed: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Unexpected error during user lookup", e);
            throw new RuntimeException("Unexpected error during user lookup", e);
        }
    }

    public String extractUserIdFromJwt(String bearerToken) {
        try {
            String token = bearerToken.replace("Bearer ", "").trim();
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getSubject();
        } catch (Exception e) {
            log.error("Failed to decode JWT for user ID extraction", e);
            throw new RuntimeException("Invalid JWT token");
        }
    }
}
