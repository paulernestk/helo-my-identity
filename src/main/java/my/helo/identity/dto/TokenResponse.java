package my.helo.identity.dto;

public record TokenResponse(String accessToken, String refreshToken, ProfileDto profile) {
    public TokenResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, null);
    }
}
