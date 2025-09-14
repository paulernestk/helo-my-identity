package my.helo.identity.dto;
public record PasswordResetUpdate(String token, String newPassword) {}