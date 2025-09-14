package my.helo.identity.dto;

public class AuthResponse {
    private String message;
    private TokenResponse token;

    public AuthResponse(String message, TokenResponse token) {
        this.message = message;
        this.token = token;
    }

    public String getMessage() { return message; }
    public TokenResponse getToken() { return token; }
}
